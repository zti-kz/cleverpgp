from __future__ import annotations

import hmac
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QAction, QCloseEvent, QDesktopServices
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractSpinBox,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QMenu,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSlider,
    QSizePolicy,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from cleverpgp.core.block_volume import (
    BlockVolumeError,
    EncryptedBlockVolume,
)
from cleverpgp.core.disk_crypto import DEFAULT_DISK_ALGORITHM
from cleverpgp.core.errors import BioPGPError, InvalidContainerError
from cleverpgp.core.block_container import BlockVaultContainer as EncryptedContainer
from cleverpgp.core.file_crypto import DecryptedFileResult, FileCryptoService
from cleverpgp.core.identity import formatted_fingerprint
from cleverpgp.core.mount import (
    VaultMountManager,
    mount_backend_available,
    normalized_drive_name,
)
from cleverpgp.core.mount_router import AutomaticMountManager
from cleverpgp.core.models import UnlockMode
from cleverpgp.core.profile_service import ProfileService, UnlockedSession
from cleverpgp.core.storage import ProfileRepository
from cleverpgp.core.windows_storage import (
    WindowsSystemDiskManager,
    winspd_driver_available,
)
from cleverpgp.core.windows_shell import application_command_prefix
from cleverpgp.core.winspd import MIN_WINDOWS_DISK_CAPACITY
from cleverpgp.localization import (
    current_language,
    install_language_pack,
    localize_widget_tree,
    set_language,
    tr,
)
from cleverpgp.biometrics.key_protection import default_key_protector
from cleverpgp.biometrics.service import BiometricService
from cleverpgp.ui.about_dialog import AboutDialog
from cleverpgp.ui.adaptive import ResponsiveBox
from cleverpgp.ui.container_dialog import ContainerCreationDialog
from cleverpgp.ui.disk_algorithm_dialog import DiskAlgorithmChangeDialog
from cleverpgp.ui.face_dialog import FaceEnrollmentDialog, FaceVerificationDialog
from cleverpgp.ui.hidden_volume_dialog import (
    HiddenVolumeCreationDialog,
    HiddenVolumeCreationRequest,
    OpaqueVolumeUnlockDialog,
)
from cleverpgp.ui.icons import line_icon
from cleverpgp.ui.key_dialogs import ContactsDialog, RecipientSelectionDialog
from cleverpgp.ui.password_generator import add_password_generator_action
from cleverpgp.ui.resize_dialog import ContainerResizeDialog
from cleverpgp.ui.settings_dialog import AccessSettingsDialog


class BackgroundTaskThread(QThread):
    succeeded = Signal(object)
    failed = Signal(str)
    progress = Signal(int, str)

    def __init__(
        self,
        operation: Callable[[Callable[[int, str], None]], object],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.operation = operation

    def run(self) -> None:
        try:
            # This is emitted by the worker itself. The packaged UI can now
            # distinguish a started operation from its pre-start paint value.
            self._report_progress(2, "Операция запущена")
            self.succeeded.emit(self.operation(self._report_progress))
        except Exception as error:
            self.failed.emit(str(error))

    def _report_progress(self, value: int, message: str) -> None:
        self.progress.emit(max(0, min(100, int(value))), message)


@dataclass(frozen=True, slots=True)
class _OpaquePasswordRequired:
    source: Path


class MainWindow(QMainWindow):
    def __init__(
        self,
        repository: ProfileRepository,
        profile_service: ProfileService,
        file_crypto: FileCryptoService,
        mount_manager: (
            VaultMountManager
            | WindowsSystemDiskManager
            | AutomaticMountManager
            | None
        ) = None,
        startup_container: Path | None = None,
        startup_action: str | None = None,
        startup_drive: str | None = None,
    ) -> None:
        super().__init__()
        self.repository = repository
        stored_language = self.repository.get_setting("language")
        if stored_language:
            set_language(stored_language)
        self.profile_service = profile_service
        self.file_crypto = file_crypto
        self.file_crypto.bind_repository(repository)
        self.mount_manager = mount_manager or VaultMountManager()
        self._direct_container_launch = startup_container is not None
        self._direct_mount_pending = False
        self._startup_action = startup_action
        self._startup_drive = startup_drive
        self._compact_settings_launch = startup_action == "settings"
        self._compact_result_message: str | None = None
        self._compact_result_error = False
        self.startup_container = (
            startup_container.expanduser().resolve()
            if startup_container is not None
            else None
        )
        self.session: UnlockedSession | None = None
        self._busy = False
        self._task_thread: BackgroundTaskThread | None = None
        self._task_result: object = None
        self._task_error: str | None = None
        self._task_success_handler: Callable[[object], None] | None = None
        self._task_failure_handler: Callable[[str], None] | None = None
        self._task_determinate = False
        self._busy_widget_states: dict[QWidget, bool] = {}
        self._disk_creation_operation: object | None = None
        self._disk_creation_target: Path | None = None
        self._disk_creation_success_handler: Callable[[object], None] | None = None
        self._disk_creation_adopter: Callable[[Path, str], str] | None = None
        self._disk_creation_timer = QTimer(self)
        self._disk_creation_timer.setInterval(75)
        self._disk_creation_timer.timeout.connect(self._poll_disk_creation)

        title_suffix = (
            f" — {self.startup_container.name}" if self.startup_container else ""
        )
        self.setWindowTitle(f"Clever PGP{title_suffix}")
        self.setMinimumSize(420, 320)
        self.resize(840, 600)
        self.setStyleSheet(STYLESHEET)
        self._setup_tray()

        self._mount_monitor = QTimer(self)
        self._mount_monitor.setInterval(1000)
        self._mount_monitor.timeout.connect(self._sync_tray_state)
        self._mount_monitor.start()

        if self.repository.has_profile():
            self._show_unlock()
        elif self.startup_container is not None:
            # A portable disk must remain usable after a clean reinstall. It
            # therefore asks for its own password before any local profile is
            # created on this computer.
            source = self.startup_container
            self.startup_container = None
            self._direct_mount_pending = True
            page, _content = self._base_page(
                "Открытие переносимого диска",
                tr("Контейнер: {name}", name=source.name),
                compact=True,
                page_icon="lock",
            )
            self.setCentralWidget(page)
            QTimer.singleShot(0, lambda: self._prompt_opaque_volume_password(source))
        else:
            self._show_profile_creation()

    def _show_profile_creation(self) -> None:
        page, content = self._base_page(
            "Создание профиля",
            "Мастер-ключ будет создан случайно и сохранён только в зашифрованном виде.",
            compact=True,
            page_icon="shield",
        )

        form = QFormLayout()
        form.setSpacing(14)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        form.setFieldGrowthPolicy(
            QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
        )
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Например, Алмас")
        self.name_input.addAction(line_icon("face"), QLineEdit.ActionPosition.LeadingPosition)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Не менее 12 символов")
        self.password_input.addAction(
            line_icon("lock"), QLineEdit.ActionPosition.LeadingPosition
        )
        self.password_repeat_input = QLineEdit()
        self.password_repeat_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_repeat_input.addAction(
            line_icon("lock"), QLineEdit.ActionPosition.LeadingPosition
        )
        self.mode_input = QComboBox()
        for mode in UnlockMode:
            self.mode_input.addItem(mode.display_name, mode.value)

        form.addRow("Имя профиля", self.name_input)
        form.addRow("Мастер-пароль", self.password_input)
        form.addRow("Повторите пароль", self.password_repeat_input)
        form.addRow("Режим разблокировки", self.mode_input)
        content.addLayout(form)
        add_password_generator_action(
            self.password_input,
            self.password_repeat_input,
        )

        note = QLabel(
            "Биометрия управляет доступом: лицо не "
            "используется как криптографический ключ. Отдельный файл "
            "восстановления не создаётся."
        )
        note.setWordWrap(True)
        note.setObjectName("muted")
        content.addWidget(note)

        create_button = QPushButton("Создать защищённый профиль")
        create_button.setObjectName("primary")
        create_button.setIcon(line_icon("shield"))
        create_button.clicked.connect(self._create_profile)
        content.addWidget(create_button)

        self.password_repeat_input.returnPressed.connect(self._create_profile)
        localize_widget_tree(page)
        self.setCentralWidget(page)
        self.name_input.setFocus()

    def _create_profile(self) -> None:
        if self.password_input.text() != self.password_repeat_input.text():
            self._show_error("Мастер-пароли не совпадают.")
            return
        try:
            mode = UnlockMode(self.mode_input.currentData())
            self.profile_service.create_profile(
                self.name_input.text(), self.password_input.text(), mode
            )
        except BioPGPError as error:
            self._show_error(str(error))
            return

        self.password_input.clear()
        self.password_repeat_input.clear()
        self._show_unlock()

    def _show_unlock(self) -> None:
        profile = self.repository.get_profile()
        if profile is None:
            self._show_profile_creation()
            return

        unlock_subtitle = tr(
            "Режим: {mode}", mode=tr(profile.unlock_mode.display_name)
        )
        if self.startup_container is not None:
            unlock_subtitle += tr(
                ". Разблокируйте профиль, чтобы подключить {name}",
                name=self.startup_container.name,
            )
        page, content = self._base_page(
            tr("Здравствуйте, {name}", name=profile.display_name),
            unlock_subtitle,
            compact=True,
            page_icon="lock",
        )

        biometric_enrolled = self.repository.has_biometric_profile()
        password_allowed = profile.unlock_mode in (
            UnlockMode.PASSWORD_OR_FACE,
            UnlockMode.PASSWORD_ONLY,
            UnlockMode.PASSWORD_AND_FACE,
        ) or not biometric_enrolled
        password_recovery = (
            profile.unlock_mode is UnlockMode.FACE_ONLY and biometric_enrolled
        )
        face_allowed = profile.unlock_mode in (
            UnlockMode.PASSWORD_OR_FACE,
            UnlockMode.FACE_ONLY,
            UnlockMode.PASSWORD_AND_FACE,
        )

        if password_allowed or password_recovery:
            self.unlock_password_input = QLineEdit()
            self.unlock_password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.unlock_password_input.setPlaceholderText("Мастер-пароль")
            self.unlock_password_input.addAction(
                line_icon("lock"), QLineEdit.ActionPosition.LeadingPosition
            )
            self.unlock_password_input.returnPressed.connect(self._unlock)
            content.addWidget(self.unlock_password_input)

            unlock_button = QPushButton("Разблокировать паролем")
            unlock_button.setObjectName("primary")
            unlock_button.setIcon(line_icon("unlock"))
            unlock_button.clicked.connect(self._unlock)
            content.addWidget(unlock_button)
            self.unlock_password_button = unlock_button
            if password_recovery:
                self.unlock_password_input.hide()
                unlock_button.hide()

        if face_allowed and profile.unlock_mode is not UnlockMode.PASSWORD_AND_FACE:
            face_button = QPushButton(
                "Открыть по лицу"
                if biometric_enrolled
                else "Лицо ещё не зарегистрировано"
            )
            face_button.setEnabled(biometric_enrolled)
            face_button.setIcon(line_icon("face"))
            face_button.clicked.connect(lambda: self._unlock_with_face())
            content.addWidget(face_button)
        elif profile.unlock_mode is UnlockMode.PASSWORD_AND_FACE and biometric_enrolled:
            mfa_note = QLabel(
                "После проверки мастер-пароля автоматически откроется камера для второго фактора."
            )
            mfa_note.setWordWrap(True)
            mfa_note.setObjectName("muted")
            content.addWidget(mfa_note)

        if password_recovery:
            show_recovery_button = QPushButton("Использовать мастер-пароль")
            show_recovery_button.setIcon(line_icon("unlock"))
            show_recovery_button.clicked.connect(
                lambda: self._show_recovery_password(show_recovery_button)
            )
            content.addWidget(show_recovery_button)

        recovery_note = QLabel(
            "Мастер-пароль остаётся локальной альтернативой, если камера недоступна. "
            "У разработчика нет универсального ключа восстановления."
        )
        recovery_note.setWordWrap(True)
        recovery_note.setObjectName("muted")
        content.addWidget(recovery_note)

        self.auth_progress = QProgressBar()
        self.auth_progress.setRange(0, 100)
        self.auth_progress.setValue(0)
        self.auth_progress.hide()
        content.addWidget(self.auth_progress)

        localize_widget_tree(page)
        self.setCentralWidget(page)
        if password_allowed:
            self.unlock_password_input.setFocus()

    def _show_recovery_password(self, trigger: QPushButton) -> None:
        if not hasattr(self, "unlock_password_input"):
            return
        self.unlock_password_input.show()
        self.unlock_password_button.show()
        trigger.hide()
        self.unlock_password_input.setFocus()

    def _unlock(self) -> None:
        try:
            password_session = self.profile_service.unlock_with_password(
                self.unlock_password_input.text()
            )
        except BioPGPError as error:
            self._show_error(str(error))
            return
        finally:
            if hasattr(self, "unlock_password_input"):
                self.unlock_password_input.clear()

        profile = self.repository.get_profile()
        if (
            profile is not None
            and profile.unlock_mode is UnlockMode.PASSWORD_AND_FACE
            and self.repository.has_biometric_profile()
        ):
            self._unlock_with_face(password_session)
            return
        self._complete_unlock(password_session)

    def _new_biometric_service(self) -> BiometricService:
        return BiometricService(self.repository, default_key_protector())

    def _unlock_with_face(
        self, password_session: UnlockedSession | None = None
    ) -> None:
        try:
            dialog = FaceVerificationDialog(self._new_biometric_service(), self)
            accepted = dialog.exec() == QDialog.DialogCode.Accepted
            face_session = dialog.session
            if not accepted or face_session is None:
                if password_session is not None:
                    password_session.lock()
                return
            if password_session is not None:
                password_key = password_session.master_key_copy()
                face_key = face_session.master_key_copy()
                password_session.lock()
                if not hmac.compare_digest(password_key, face_key):
                    face_session.lock()
                    self._show_error("Факторы MFA относятся к разным ключам.")
                    return
            self._complete_unlock(face_session)
        except BioPGPError as error:
            if password_session is not None:
                password_session.lock()
            self._show_error(str(error))

    def _complete_unlock(self, session: UnlockedSession) -> None:
        self.session = session
        if self.startup_container is not None:
            self._mount_startup_container()
            return
        if self._startup_action == "settings":
            self._startup_action = None
            if not self._validate_compact_settings_drive():
                return
            QTimer.singleShot(0, self._show_access_settings)
            return

        self._show_dashboard()
        if self._startup_action == "resize":
            self._startup_action = None
            QTimer.singleShot(0, self._show_resize_dialog)
        elif self._startup_action == "algorithm":
            self._startup_action = None
            QTimer.singleShot(0, self._show_algorithm_dialog)

    def _show_dashboard(self) -> None:
        profile = self.repository.get_profile()
        if profile is None or self.session is None or not self.session.is_unlocked:
            self._show_unlock()
            return

        page, content = self._base_page(
            "Clever PGP разблокирован",
            tr(
                "Профиль: {name}. Ключ доступен только текущему сеансу.",
                name=profile.display_name,
            ),
        )

        status = QLabel("● Защищённый сеанс активен")
        status.setObjectName("success")
        status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content.addWidget(status)

        file_panel = QFrame()
        file_panel.setObjectName("dashboardPanel")
        file_layout = QVBoxLayout(file_panel)
        file_layout.setContentsMargins(22, 20, 22, 20)
        file_layout.setSpacing(12)

        file_layout.addLayout(self._section_heading("Защита файлов", "file_lock"))

        encrypt_button = QPushButton("Зашифровать файл")
        encrypt_button.setObjectName("primary")
        encrypt_button.setIcon(line_icon("file_lock"))
        encrypt_button.clicked.connect(self._encrypt_file)
        decrypt_button = QPushButton("Расшифровать файл .cpgp")
        decrypt_button.setIcon(line_icon("file_open"))
        decrypt_button.clicked.connect(self._decrypt_file)
        contacts_button = QPushButton("Открытые ключи и контакты")
        contacts_button.setIcon(line_icon("key"))
        contacts_button.clicked.connect(self._show_contacts)
        file_layout.addWidget(encrypt_button)
        file_layout.addWidget(decrypt_button)
        file_layout.addWidget(contacts_button)

        info = QLabel(
            "Файл обрабатывается локально. Для каждого файла создаётся новый случайный "
            "ключ; изменение хотя бы одного блока будет обнаружено при расшифровании."
        )
        info.setWordWrap(True)
        info.setObjectName("muted")
        file_layout.addWidget(info)

        file_layout.addLayout(self._section_heading("Биометрия лица", "face"))
        biometric_button = QPushButton(
            "Обновить данные лица"
            if self.repository.has_biometric_profile()
            else "Зарегистрировать лицо"
        )
        biometric_button.setIcon(line_icon("face"))
        biometric_button.clicked.connect(self._enroll_face)
        file_layout.addWidget(biometric_button)
        file_layout.addStretch()

        container_panel = QFrame()
        container_panel.setObjectName("dashboardPanel")
        container_layout = QVBoxLayout(container_panel)
        container_layout.setContentsMargins(22, 20, 22, 20)
        container_layout.setSpacing(12)

        container_layout.addLayout(
            self._section_heading("Зашифрованный диск", "vault")
        )

        container_info = QLabel(
            "Контейнер открывается как отдельный диск. Файлы, скопированные на него, "
            "шифруются автоматически и остаются внутри одного файла .cpgv."
        )
        container_info.setWordWrap(True)
        container_info.setObjectName("muted")
        container_layout.addWidget(container_info)

        create_container_button = QPushButton("Создать контейнер-диск")
        create_container_button.setObjectName("primary")
        create_container_button.setIcon(line_icon("vault_add"))
        create_container_button.clicked.connect(self._create_container)
        open_container_button = QPushButton("Подключить контейнер .cpgv")
        open_container_button.setIcon(line_icon("vault"))
        open_container_button.clicked.connect(self._open_container)
        container_layout.addWidget(create_container_button)
        container_layout.addWidget(open_container_button)

        disk_backend_available = self._disk_backend_available()
        if self._uses_windows_system_disk and not disk_backend_available:
            create_container_button.setEnabled(False)
            open_container_button.setEnabled(False)
        if not disk_backend_available:
            if self._uses_windows_system_disk:
                unavailable = QLabel(
                    "Быстрый виртуальный диск недоступен: компонент WinSpd "
                    "не установлен."
                )
                unavailable.setObjectName("muted")
                unavailable.setWordWrap(True)
                container_layout.addWidget(unavailable)
            else:
                install_button = QPushButton(
                    "Установить компонент виртуального диска"
                )
                install_button.setIcon(line_icon("shield"))
                install_button.clicked.connect(self._install_mount_backend)
                container_layout.addWidget(install_button)
        container_layout.addStretch()

        action_panels = ResponsiveBox(
            (file_panel, container_panel),
            breakpoint=820,
            spacing=18,
        )
        content.addWidget(action_panels, 1)

        self.dashboard_status = QLabel()
        self.dashboard_status.setWordWrap(True)
        self.dashboard_status.hide()
        content.addWidget(self.dashboard_status)

        self.dashboard_progress = QProgressBar()
        self.dashboard_progress.setRange(0, 100)
        self.dashboard_progress.setValue(0)
        self.dashboard_progress.hide()
        content.addWidget(self.dashboard_progress)
        footer = QHBoxLayout()
        footer.addStretch()
        lock_button = QPushButton("Заблокировать")
        lock_button.setIcon(line_icon("lock"))
        lock_button.clicked.connect(self._lock)
        footer.addWidget(lock_button)
        content.addLayout(footer)

        localize_widget_tree(page)
        self.setCentralWidget(page)

    def _show_access_settings(self) -> None:
        if self._busy:
            return
        profile = self.repository.get_profile()
        if profile is None or self.session is None or not self.session.is_unlocked:
            self._show_unlock()
            return
        dialog = AccessSettingsDialog(
            profile.unlock_mode,
            biometric_enrolled=self.repository.has_biometric_profile(),
            drive=(
                normalized_drive_name(self._startup_drive)
                if self._compact_settings_launch
                and self._startup_drive is not None
                else None
            ),
            selected_language=current_language(),
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted or dialog.request is None:
            if self._compact_settings_launch:
                self.close()
            return
        request = dialog.request
        if request.operation == "install_language" and request.language_pack_path:
            try:
                language = install_language_pack(request.language_pack_path)
                self.repository.set_setting("language", language.code)
            except (OSError, TypeError, ValueError) as error:
                self._show_error(str(error))
                return
            if not self._compact_settings_launch:
                self._set_dashboard_status(
                    tr(
                        "Язык {name} установлен. Clever PGP перезапускается.",
                        name=language.native_name,
                    )
                )
            QTimer.singleShot(0, self._restart_application)
            return
        if request.operation == "language" and request.language_code:
            self.repository.set_setting("language", request.language_code)
            if request.language_code == current_language():
                if self._compact_settings_launch:
                    self._show_compact_settings_result("Язык интерфейса не изменён.")
                else:
                    self._set_dashboard_status("Язык интерфейса не изменён.")
                return
            if not self._compact_settings_launch:
                self._set_dashboard_status(
                    "Язык интерфейса сохранён. Clever PGP перезапускается."
                )
            QTimer.singleShot(0, self._restart_application)
            return
        if request.operation == "face":
            if self._compact_settings_launch:
                self._enroll_face(
                    on_success=lambda: self._show_compact_settings_result(
                        "Лицо зарегистрировано. Биометрический ключ "
                        "защищён Windows."
                    ),
                    on_cancel=lambda: QTimer.singleShot(
                        0,
                        self._show_access_settings,
                    ),
                    on_failure=self._show_compact_settings_error,
                )
            else:
                self._enroll_face()
            return
        if request.operation == "unlock_mode" and request.unlock_mode is not None:
            selected_mode = request.unlock_mode

            def change_mode(progress: Callable[[int, str], None]) -> object:
                progress(20, "Проверка режима разблокировки")
                changed = self.profile_service.change_unlock_mode(selected_mode)
                progress(100, "Режим разблокировки изменён")
                return changed

            def mode_changed(_result: object) -> None:
                if self._compact_settings_launch:
                    self._show_compact_settings_result(
                        "Режим разблокировки изменён."
                    )
                else:
                    self._show_dashboard()
                    self._set_dashboard_status(
                        tr("Режим разблокировки изменён.")
                    )

            self._start_progress_task(
                change_mode,
                mode_changed,
                on_failure=(
                    self._show_compact_settings_error
                    if self._compact_settings_launch
                    else None
                ),
            )
            return
        if request.operation == "password":
            current_password = request.current_password
            new_password = request.new_password

            def change_password(progress: Callable[[int, str], None]) -> object:
                return self.profile_service.change_master_password(
                    current_password,
                    new_password,
                    progress=progress,
                )

            def password_changed(_result: object) -> None:
                if self._compact_settings_launch:
                    self._show_compact_settings_result(
                        "Мастер-пароль успешно изменён."
                    )
                else:
                    self._show_dashboard()
                    self._set_dashboard_status(
                        tr("Мастер-пароль успешно изменён.")
                    )

            self._start_progress_task(
                change_password,
                password_changed,
                on_failure=(
                    self._show_compact_settings_error
                    if self._compact_settings_launch
                    else None
                ),
            )

    def _validate_compact_settings_drive(self) -> bool:
        if self._startup_drive is None:
            return True
        try:
            expected = normalized_drive_name(self._startup_drive)
        except BioPGPError as error:
            self._show_compact_settings_error(str(error))
            return False
        try:
            active = self.mount_manager.mounted_drive
        except (BioPGPError, OSError, TypeError, ValueError) as error:
            self._show_compact_settings_error(str(error))
            return False
        if active != expected:
            self._show_compact_settings_error(
                "Выбранный виртуальный диск Clever PGP не подключён."
            )
            return False
        return True

    def _show_compact_settings_result(
        self,
        message: str,
        *,
        error: bool = False,
    ) -> None:
        self._compact_result_message = message
        self._compact_result_error = error
        page, content = self._base_page(
            "Настройки доступа",
            "Подключённый диск продолжает работать.",
            compact=True,
            page_icon="settings",
        )
        status = QLabel(tr(message))
        status.setObjectName("error" if error else "success")
        status.setWordWrap(True)
        status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content.addWidget(status)
        localize_widget_tree(page)
        self.setCentralWidget(page)

    def _show_compact_settings_error(self, message: str) -> None:
        self._show_compact_settings_result(message, error=True)

    def _show_resize_dialog(self) -> None:
        if not self._uses_windows_system_disk:
            self._show_error(
                "Изменение размера доступно только для виртуального диска Windows."
            )
            return
        drive = self.mount_manager.mounted_drive
        expected_drive = (
            str(self._startup_drive).strip().upper().rstrip("\\/")
            if self._startup_drive
            else None
        )
        if expected_drive and len(expected_drive) == 1:
            expected_drive += ":"
        if drive is None or (expected_drive is not None and drive != expected_drive):
            self._show_error("Выбранный виртуальный диск Clever PGP не подключён.")
            return
        container_path = self.mount_manager.mounted_container
        if container_path is None:
            self._show_error(
                "Путь контейнера недоступен. Отключите и снова откройте диск."
            )
            return
        try:
            info = self.mount_manager.inspect_mounted_disk()
            pending = (
                info.disk_size - info.partition_offset - info.partition_size > 0
            )
            dialog = ContainerResizeDialog(
                container_path,
                current_capacity=info.disk_size,
                file_system=info.file_system,
                partition_growth_pending=pending,
                parent=self,
            )
        except (BioPGPError, OSError, TypeError, ValueError) as error:
            self._show_error(str(error))
            return
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        selected_capacity = dialog.logical_capacity

        def resize_disk(
            master_key: bytes,
            progress: Callable[[int, str], None],
        ) -> str:
            return self.mount_manager.resize_mounted_disk(
                master_key,
                logical_capacity=selected_capacity,
                context_menu_labels=self._ordinary_disk_context_labels(),
                progress=progress,
            )

        def resized(result: object) -> None:
            resized_drive = str(result)
            self._sync_tray_state()
            self._set_dashboard_status(
                tr(
                    "Диск {drive} увеличен и снова подключён.",
                    drive=resized_drive,
                )
            )
            if self._startup_drive is not None:
                self._hide_to_tray()

        self._start_key_progress_task(resize_disk, resized)

    def _show_algorithm_dialog(self) -> None:
        if not self._uses_windows_system_disk:
            self._show_error(
                "Изменение метода доступно только для виртуального диска Windows."
            )
            return
        drive = self.mount_manager.mounted_drive
        expected_drive = (
            str(self._startup_drive).strip().upper().rstrip("\\/")
            if self._startup_drive
            else None
        )
        if expected_drive and len(expected_drive) == 1:
            expected_drive += ":"
        if drive is None or (expected_drive is not None and drive != expected_drive):
            self._show_error("Выбранный виртуальный диск Clever PGP не подключён.")
            return
        container_path = self.mount_manager.mounted_container
        current_algorithm = getattr(
            self.mount_manager,
            "mounted_algorithm",
            None,
        )
        if container_path is None or current_algorithm is None:
            self._show_error(
                "Сведения о методе шифрования недоступны. "
                "Отключите и снова откройте диск."
            )
            return
        try:
            dialog = DiskAlgorithmChangeDialog(
                container_path,
                str(current_algorithm),
                self,
            )
        except (BioPGPError, OSError, TypeError, ValueError) as error:
            self._show_error(str(error))
            return
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        selected_algorithm = dialog.new_algorithm

        def change_algorithm(
            master_key: bytes,
            progress: Callable[[int, str], None],
        ) -> str:
            return self.mount_manager.change_mounted_disk_algorithm(
                master_key,
                algorithm=selected_algorithm,
                context_menu_labels=self._ordinary_disk_context_labels(),
                progress=progress,
            )

        def changed(result: object) -> None:
            remounted_drive = str(result)
            self._sync_tray_state()
            self._set_dashboard_status(
                tr(
                    "Метод шифрования диска {drive} изменён, диск снова подключён.",
                    drive=remounted_drive,
                )
            )
            if self._startup_drive is not None:
                self._hide_to_tray()

        self._start_key_progress_task(change_algorithm, changed)

    def _encrypt_file(self) -> None:
        source_name, _ = QFileDialog.getOpenFileName(self, tr("Выберите файл"))
        if not source_name:
            return
        source = Path(source_name)
        selected_contacts = ()
        contacts = self.repository.list_contacts()
        if contacts:
            recipient_dialog = RecipientSelectionDialog(contacts, self)
            if recipient_dialog.exec() != QDialog.DialogCode.Accepted:
                return
            selected_contacts = recipient_dialog.selected_contacts
        suggested = self.file_crypto.default_encrypted_path(source)
        target_name, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить зашифрованный файл"),
            str(suggested),
            "Clever PGP (*.cpgp)",
        )
        if not target_name:
            return
        self._run_file_operation(
            tr("Зашифровано"),
            lambda key, progress: self.file_crypto.encrypt_file(
                source,
                Path(target_name),
                key,
                recipients=selected_contacts,
                overwrite=True,
                progress=progress,
            ),
        )

    def _decrypt_file(self) -> None:
        source_name, _ = QFileDialog.getOpenFileName(
            self,
            tr("Выберите файл Clever PGP"),
            filter=tr("Clever PGP (*.cpgp);;Все файлы (*)"),
        )
        if not source_name:
            return
        source = Path(source_name)
        suggested = self.file_crypto.default_decrypted_path(source)
        target_name, _ = QFileDialog.getSaveFileName(
            self, tr("Сохранить расшифрованный файл"), str(suggested)
        )
        if not target_name:
            return
        def decrypted(result: object) -> None:
            if not isinstance(result, DecryptedFileResult):
                self._show_error("Не удалось получить сведения о подписи файла.")
                return
            if result.sender_is_self:
                verification = tr("Подпись текущего профиля подтверждена.")
            elif result.sender_is_known:
                verification = tr(
                    "Подпись контакта {name} подтверждена.",
                    name=result.sender.display_name,
                )
            else:
                verification = tr(
                    "Подпись математически верна, но отправитель {name} ещё не "
                    "сохранён в контактах. Сверьте полный отпечаток по "
                    "независимому каналу:\n{fingerprint}",
                    name=result.sender.display_name,
                    fingerprint=formatted_fingerprint(result.sender.fingerprint),
                )
            self._set_dashboard_status(
                tr("Расшифровано: {path}", path=result.path) + "\n" + verification
            )

        self._start_key_progress_task(
            lambda key, progress: self.file_crypto.decrypt_file_detailed(
                source,
                Path(target_name),
                key,
                overwrite=True,
                progress=progress,
            ),
            decrypted,
        )

    def _show_contacts(self) -> None:
        if self.session is None or not self.session.is_unlocked:
            self._show_unlock()
            return
        key_buffer = bytearray(self.session.master_key_copy())
        try:
            dialog = ContactsDialog(
                self.repository,
                bytes(key_buffer),
                self,
            )
            dialog.exec()
        except BioPGPError as error:
            self._show_error(str(error))
        finally:
            for index in range(len(key_buffer)):
                key_buffer[index] = 0

    def _run_file_operation(
        self,
        message: str,
        operation: Callable[[bytes, Callable[[int, str], None]], object],
    ) -> None:
        self._start_key_progress_task(
            operation,
            lambda result: self._set_dashboard_status(f"{message}: {result}"),
        )

    def _create_container(self) -> None:
        if self._uses_windows_system_disk:
            dialog = ContainerCreationDialog(
                self,
                minimum_capacity=MIN_WINDOWS_DISK_CAPACITY,
                system_disk=True,
                hidden_volume_available=True,
            )
        elif self._automatically_selects_disk_backend:
            if sys.platform == "win32" and not winspd_driver_available():
                self._show_error(
                    "Компонент быстрого виртуального диска Windows не установлен. "
                    "Переустановите Clever PGP и повторите создание."
                )
                return
            dialog = ContainerCreationDialog(
                self,
                minimum_capacity=MIN_WINDOWS_DISK_CAPACITY,
                system_disk=sys.platform == "win32",
                hidden_volume_available=winspd_driver_available(),
            )
        else:
            dialog = ContainerCreationDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        target = dialog.container_path
        data_capacity = dialog.data_capacity
        volume_label = dialog.volume_label
        file_system = dialog.file_system
        disk_algorithm = getattr(
            dialog,
            "disk_algorithm",
            DEFAULT_DISK_ALGORITHM,
        )
        disk_password = getattr(dialog, "disk_password", None)
        # New Windows containers always use the fast block-disk backend.  The
        # older WinFsp format remains readable, but must never silently become
        # the creation path and reintroduce a blocking Qt worker.
        create_as_system_disk = self._uses_windows_system_disk or (
            self._automatically_selects_disk_backend
            and sys.platform == "win32"
            and winspd_driver_available()
        )
        isolated_creator = getattr(
            self.mount_manager,
            "create_and_mount_isolated",
            None,
        )
        if create_as_system_disk and not callable(isolated_creator):
            prepare = getattr(
                self.mount_manager,
                (
                    "prepare_system_backend"
                    if self._automatically_selects_disk_backend
                    else "prepare_backend"
                ),
                None,
            )
            if callable(prepare):
                try:
                    prepare()
                except (BioPGPError, OSError) as error:
                    self._show_error(str(error))
                    return
        hidden_request: HiddenVolumeCreationRequest | None = None
        if getattr(dialog, "hidden_volume", False):
            try:
                hidden_dialog = HiddenVolumeCreationDialog(
                    data_capacity,
                    volume_label,
                    self,
                )
            except ValueError as error:
                self._show_error(str(error))
                return
            if (
                hidden_dialog.exec() != QDialog.DialogCode.Accepted
                or hidden_dialog.request is None
            ):
                return
            hidden_request = hidden_dialog.request

        def create_hidden_container(
            progress: Callable[[int, str], None],
        ) -> tuple[Path, str | None, str | None]:
            assert hidden_request is not None
            creator = getattr(
                self.mount_manager,
                "create_hidden_and_mount_isolated",
                None,
            )
            if not callable(creator):
                creator = getattr(
                    self.mount_manager,
                    "create_hidden_and_mount",
                    None,
                )
            if not callable(creator):
                raise BioPGPError(
                    "Скрытый виртуальный диск доступен только в Windows с WinSpd."
                )
            passwords: list[str | None] = [
                hidden_request.outer_password,
                hidden_request.hidden_password,
            ]
            try:
                drive = creator(
                    target,
                    passwords[0],
                    passwords[1],
                    outer_capacity=data_capacity,
                    hidden_capacity=hidden_request.hidden_capacity,
                    outer_label=volume_label,
                    hidden_label=hidden_request.hidden_label,
                    file_system=file_system,
                    context_menu_labels=(
                        tr("Открыть зашифрованный диск"),
                        tr("Сведения о диске"),
                        tr("Настройки доступа"),
                        tr("Изменить пароль диска"),
                        "",
                        tr("Отключить зашифрованный диск"),
                    ),
                    progress=progress,
                )
            finally:
                passwords[0] = None
                passwords[1] = None
            return target, drive, None

        def create_container(
            master_key: bytes, progress: Callable[[int, str], None]
        ) -> tuple[Path, str | None, str | None]:
            if create_as_system_disk:
                try:
                    creator = getattr(
                        self.mount_manager,
                        "create_and_mount_isolated",
                        None,
                    )
                    if not callable(creator):
                        creator = self.mount_manager.create_and_mount
                    drive = creator(
                        target,
                        master_key,
                        logical_capacity=data_capacity,
                        label=volume_label,
                        file_system=file_system,
                        algorithm=disk_algorithm,
                        password=disk_password,
                        context_menu_labels=self._ordinary_disk_context_labels(),
                        progress=progress,
                    )
                except Exception as error:
                    if target.is_file():
                        progress(100, "Контейнер создан без подключения")
                        return target, None, str(error)
                    raise
                return target, drive, None

            def creation_progress(value: int, message: str) -> None:
                progress(max(1, round(value * 0.6)), message)

            container = EncryptedContainer.create(
                target,
                master_key,
                data_capacity=data_capacity,
                label=volume_label,
                algorithm=disk_algorithm,
                password=disk_password,
                progress=creation_progress,
            )
            container.close(save=False)
            if not mount_backend_available():
                progress(100, "Контейнер создан")
                return target, None, None
            try:
                drive = self.mount_manager.mount(
                    target,
                    master_key,
                    progress=lambda value, message: progress(
                        60 + round(value * 0.4), message
                    ),
                )
            except Exception as error:
                progress(100, "Контейнер создан без подключения")
                return target, None, str(error)
            return target, drive, None

        def created(result: object) -> None:
            created_path, drive, mount_error = result
            created_path = Path(created_path)
            if drive is not None:
                self._container_mounted(drive)
                return
            self._set_dashboard_status(
                tr("Контейнер создан: {path}", path=created_path)
            )
            if mount_error:
                self._show_error(
                    tr(
                        "Контейнер создан, но не подключён: {error}",
                        error=mount_error,
                    )
                )

        if create_as_system_disk:
            adopter = getattr(
                self.mount_manager,
                "adopt_isolated_creation",
                None,
            )
            if hidden_request is not None:
                starter = getattr(
                    self.mount_manager,
                    "begin_create_hidden_and_mount_isolated",
                    None,
                )
                if callable(starter) and callable(adopter):
                    passwords: list[str | None] = [
                        hidden_request.outer_password,
                        hidden_request.hidden_password,
                    ]

                    def begin_hidden_creation() -> object:
                        try:
                            return starter(
                                target,
                                passwords[0],
                                passwords[1],
                                outer_capacity=data_capacity,
                                hidden_capacity=hidden_request.hidden_capacity,
                                outer_label=volume_label,
                                hidden_label=hidden_request.hidden_label,
                                file_system=file_system,
                                context_menu_labels=(
                                    tr("Открыть зашифрованный диск"),
                                    tr("Сведения о диске"),
                                    tr("Настройки доступа"),
                                    tr("Изменить пароль диска"),
                                    "",
                                    tr("Отключить зашифрованный диск"),
                                ),
                            )
                        finally:
                            passwords[0] = None
                            passwords[1] = None

                    self._start_isolated_disk_creation(
                        begin_hidden_creation,
                        target,
                        adopter,
                        created,
                    )
                    return
                self._show_error(
                    "Неблокирующий компонент создания скрытого диска недоступен."
                )
                return
            else:
                starter = getattr(
                    self.mount_manager,
                    "begin_create_and_mount_isolated",
                    None,
                )
                if callable(starter) and callable(adopter):
                    if self.session is None:
                        self._show_unlock()
                        return
                    key_buffer = bytearray(self.session.master_key_copy())

                    def begin_ordinary_creation() -> object:
                        try:
                            return starter(
                                target,
                                bytes(key_buffer),
                                logical_capacity=data_capacity,
                                label=volume_label,
                                file_system=file_system,
                                algorithm=disk_algorithm,
                                password=disk_password,
                                context_menu_labels=(
                                    self._ordinary_disk_context_labels()
                                ),
                            )
                        finally:
                            key_buffer[:] = b"\x00" * len(key_buffer)

                    self._start_isolated_disk_creation(
                        begin_ordinary_creation,
                        target,
                        adopter,
                        created,
                    )
                    return
                self._show_error(
                    "Неблокирующий компонент создания диска недоступен."
                )
                return

        if hidden_request is not None:
            self._start_progress_task(create_hidden_container, created)
        else:
            self._start_key_progress_task(create_container, created)

    @property
    def _uses_windows_system_disk(self) -> bool:
        selected = getattr(
            self.mount_manager,
            "uses_windows_system_disk",
            None,
        )
        if isinstance(selected, bool):
            return selected
        return isinstance(self.mount_manager, WindowsSystemDiskManager)

    @property
    def _automatically_selects_disk_backend(self) -> bool:
        return bool(
            getattr(
                self.mount_manager,
                "automatically_selects_backend",
                False,
            )
        )

    @staticmethod
    def _ordinary_disk_context_labels() -> tuple[str, ...]:
        return (
            tr("Открыть зашифрованный диск"),
            tr("Сведения о диске"),
            tr("Настройки доступа"),
            tr("Изменить пароль диска"),
            tr("Изменить метод шифрования"),
            tr("Увеличить диск"),
            tr("Отключить зашифрованный диск"),
        )

    def _disk_backend_available(self) -> bool:
        if self._uses_windows_system_disk:
            return winspd_driver_available()
        if self._automatically_selects_disk_backend:
            return winspd_driver_available() or mount_backend_available()
        return mount_backend_available()

    def _enroll_face(
        self,
        *,
        on_success: Callable[[], None] | None = None,
        on_cancel: Callable[[], None] | None = None,
        on_failure: Callable[[str], None] | None = None,
    ) -> None:
        try:
            dialog = FaceEnrollmentDialog(self)
            if dialog.exec() != QDialog.DialogCode.Accepted or dialog.template is None:
                if on_cancel is not None:
                    on_cancel()
                return
            template = dialog.template.copy()
            service = self._new_biometric_service()
        except BioPGPError as error:
            if on_failure is not None:
                on_failure(str(error))
            else:
                self._show_error(str(error))
            return

        def enroll(master_key: bytes) -> None:
            try:
                service.enroll(template, master_key)
            finally:
                template.fill(0)

        def enrolled(_result: object) -> None:
            if on_success is not None:
                on_success()
            else:
                self._set_dashboard_status(
                    tr(
                        "Лицо зарегистрировано. Биометрический ключ "
                        "защищён Windows."
                    )
                )

        self._start_key_task(
            enroll,
            enrolled,
            on_failure=on_failure,
        )

    def _open_container(self) -> None:
        source_name, _ = QFileDialog.getOpenFileName(
            self,
            tr("Выберите контейнер Clever PGP"),
            filter=tr("Контейнер Clever PGP (*.cpgv);;Все файлы (*)"),
        )
        if not source_name:
            return
        self._mount_container(Path(source_name))

    def _mount_container(self, source: Path) -> None:
        def mount_container(
            master_key: bytes,
            progress: Callable[[int, str], None],
        ) -> str | _OpaquePasswordRequired:
            try:
                if self._uses_windows_system_disk or getattr(
                    self.mount_manager,
                    "automatically_selects_backend",
                    False,
                ):
                    return self.mount_manager.mount(
                        source,
                        master_key,
                        context_menu_labels=self._ordinary_disk_context_labels(),
                        progress=progress,
                    )
                return self.mount_manager.mount(
                    source,
                    master_key,
                    progress=progress,
                )
            except (BlockVolumeError, InvalidContainerError):
                if callable(getattr(self.mount_manager, "mount_opaque", None)):
                    return _OpaquePasswordRequired(source)
                raise

        def mounted(result: object) -> None:
            if isinstance(result, _OpaquePasswordRequired):
                self._prompt_opaque_volume_password(result.source)
                return
            self._container_mounted(result)

        self._start_key_progress_task(
            mount_container,
            mounted,
        )

    def _prompt_opaque_volume_password(self, source: Path) -> None:
        dialog = OpaqueVolumeUnlockDialog(source, self)
        if (
            dialog.exec() != QDialog.DialogCode.Accepted
            or dialog.request is None
        ):
            if self._direct_mount_pending:
                self._direct_mount_pending = False
                if self.repository.has_profile():
                    self._show_dashboard()
                else:
                    self._close_background_window()
            return
        request = dialog.request
        passwords: list[str | None] = [
            request.password,
            request.hidden_protection_password,
        ]
        profile_key = (
            bytearray(self.session.master_key_copy())
            if self.session is not None and self.session.is_unlocked
            else None
        )

        def mount_opaque(progress: Callable[[int, str], None]) -> str:
            opener = getattr(self.mount_manager, "mount_opaque", None)
            if not callable(opener):
                raise BioPGPError(
                    "Этот зашифрованный диск нельзя открыть выбранным способом."
                )
            try:
                if profile_key is not None:
                    try:
                        progress(3, "Привязка локального профиля к диску")
                        EncryptedBlockVolume.add_profile_access(
                            source,
                            passwords[0],
                            bytes(profile_key),
                        )
                    except BioPGPError:
                        # Linking is an optional convenience. The manager still
                        # performs the authoritative password authentication,
                        # including for opaque hidden v4 disks.
                        pass
                return opener(
                    source,
                    passwords[0],
                    hidden_protection_password=passwords[1],
                    context_menu_labels=(
                        tr("Открыть зашифрованный диск"),
                        tr("Сведения о диске"),
                        tr("Настройки доступа"),
                        tr("Изменить пароль диска"),
                        "",
                        tr("Отключить зашифрованный диск"),
                    ),
                    progress=progress,
                )
            finally:
                passwords[0] = None
                passwords[1] = None
                if profile_key is not None:
                    profile_key[:] = b"\x00" * len(profile_key)

        self._start_progress_task(mount_opaque, self._container_mounted)

    def _container_mounted(self, result: object) -> None:
        drive = str(result)
        self._direct_mount_pending = False
        self._sync_tray_state()
        self._set_dashboard_status(
            tr(
                "Контейнер подключён как {drive}\\. Копируйте файлы на этот диск.",
                drive=drive,
            )
        )
        QDesktopServices.openUrl(QUrl.fromLocalFile(f"{drive}\\"))
        # The mounted disk is served independently from the unlocked GUI.
        # Always leave Explorer in front and remove the profile key from this
        # process as soon as the mount operation has completed.
        QTimer.singleShot(0, self._hide_to_tray)

    def _mount_startup_container(self) -> None:
        source = self.startup_container
        if source is None:
            return
        self.startup_container = None
        if not source.is_file():
            self._show_dashboard()
            self._show_error("Выбранный контейнер Clever PGP не найден.")
            return
        self._direct_mount_pending = True
        QTimer.singleShot(0, lambda: self._mount_container(source))

    def _unmount_container(self) -> None:
        drive = self.mount_manager.mounted_drive
        if drive is None:
            return

        def unmounted(result: object) -> None:
            self._sync_tray_state()
            self._set_dashboard_status(
                tr("Диск {drive} безопасно отключён.", drive=drive)
            )
            if not self.isVisible() and self._direct_container_launch:
                self._close_background_window()

        self._start_task(self.mount_manager.unmount, unmounted)

    def _install_mount_backend(self) -> None:
        script = Path(__file__).resolve().parents[3] / "install_virtual_disk.ps1"
        if not script.is_file():
            self._show_error("Установщик виртуального диска не найден.")
            return
        try:
            subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script),
                ],
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
            )
        except OSError as error:
            self._show_error(str(error))
            return
        self._set_dashboard_status(
            "Запущена установка виртуального диска. После завершения перезапустите Clever PGP."
        )

    def _set_dashboard_status(self, message: str) -> None:
        if not hasattr(self, "dashboard_status"):
            return
        self.dashboard_status.setObjectName("success")
        self.dashboard_status.setText(tr(message))
        self.dashboard_status.style().unpolish(self.dashboard_status)
        self.dashboard_status.style().polish(self.dashboard_status)
        self.dashboard_status.show()

    def _restart_application(self) -> None:
        if self._busy:
            return
        command = list(application_command_prefix())
        if not command:
            self._show_error("Не удалось найти команду запуска Clever PGP.")
            return
        command.extend(("--restart-after-process", str(os.getpid())))
        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
                subprocess,
                "CREATE_NEW_PROCESS_GROUP",
                0,
            )
        try:
            subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=creation_flags,
            )
        except OSError as error:
            self._show_error(
                tr("Не удалось перезапустить Clever PGP: {error}", error=error)
            )
            return
        self._clear_session()
        self._tray_icon.hide()
        application = QApplication.instance()
        if application is not None:
            application.quit()

    def _start_isolated_disk_creation(
        self,
        starter: Callable[[], object],
        target: Path,
        adopter: Callable[[Path, str], str],
        on_success: Callable[[object], None],
    ) -> None:
        """Launch a disk helper directly and poll it from the Qt event loop."""

        if self._busy:
            return
        self._set_busy(True, determinate=True)
        self._task_progress(2, "Защита одноразового запроса создания диска")
        try:
            operation = starter()
        except Exception as error:
            self._set_busy(False)
            self._show_error(str(error))
            return
        required = ("read_progress", "result", "cleanup")
        if any(not callable(getattr(operation, name, None)) for name in required):
            self._set_busy(False)
            self._show_error("Процесс создания диска не поддерживает контроль состояния.")
            return
        self._disk_creation_operation = operation
        self._disk_creation_target = Path(target).expanduser().resolve()
        self._disk_creation_success_handler = on_success
        self._disk_creation_adopter = adopter
        self._task_progress(3, "Запуск изолированного процесса")
        self._disk_creation_timer.start()

    @Slot()
    def _poll_disk_creation(self) -> None:
        operation = self._disk_creation_operation
        if operation is None:
            self._disk_creation_timer.stop()
            return
        try:
            current = operation.read_progress()
            if current is not None:
                self._task_progress(*current)
            if not bool(getattr(operation, "finished", False)):
                return
            drive = str(operation.result())
            target = self._disk_creation_target
            adopter = self._disk_creation_adopter
            if target is None or adopter is None:
                raise BioPGPError("Не удалось восстановить состояние созданного диска.")
            mounted = str(adopter(target, drive))
            result: object = (target, mounted, None)
            error: str | None = None
        except Exception as caught:
            target = self._disk_creation_target
            if target is not None and target.is_file():
                result = (target, None, str(caught))
                error = None
            else:
                result = None
                error = str(caught) or caught.__class__.__name__
        self._finish_isolated_disk_creation(result, error)

    def _finish_isolated_disk_creation(
        self,
        result: object,
        error: str | None,
    ) -> None:
        self._disk_creation_timer.stop()
        operation = self._disk_creation_operation
        handler = self._disk_creation_success_handler
        self._disk_creation_operation = None
        self._disk_creation_target = None
        self._disk_creation_success_handler = None
        self._disk_creation_adopter = None
        try:
            if operation is not None:
                operation.cleanup()
        finally:
            self._set_busy(False)
        if error is not None:
            self._show_error(error)
            return
        if handler is not None:
            try:
                handler(result)
            except (BioPGPError, OSError, TypeError, ValueError) as caught:
                self._show_error(str(caught))

    def _start_key_task(
        self,
        operation: Callable[[bytes], object],
        on_success: Callable[[object], None],
        *,
        on_failure: Callable[[str], None] | None = None,
    ) -> None:
        if self.session is None:
            self._show_unlock()
            return
        key_buffer = bytearray(self.session.master_key_copy())

        def protected_operation() -> object:
            try:
                return operation(bytes(key_buffer))
            finally:
                for index in range(len(key_buffer)):
                    key_buffer[index] = 0

        self._start_task(
            protected_operation,
            on_success,
            on_failure=on_failure,
        )

    def _start_key_progress_task(
        self,
        operation: Callable[[bytes, Callable[[int, str], None]], object],
        on_success: Callable[[object], None],
    ) -> None:
        if self.session is None:
            self._show_unlock()
            return
        key_buffer = bytearray(self.session.master_key_copy())

        def protected_operation(progress: Callable[[int, str], None]) -> object:
            try:
                return operation(bytes(key_buffer), progress)
            finally:
                for index in range(len(key_buffer)):
                    key_buffer[index] = 0

        self._start_progress_task(protected_operation, on_success)

    def _start_task(
        self,
        operation: Callable[[], object],
        on_success: Callable[[object], None],
        *,
        on_failure: Callable[[str], None] | None = None,
    ) -> None:
        if on_failure is None:
            self._start_worker(
                lambda _progress: operation(),
                on_success,
                determinate=False,
            )
        else:
            self._start_worker(
                lambda _progress: operation(),
                on_success,
                determinate=False,
                on_failure=on_failure,
            )

    def _start_progress_task(
        self,
        operation: Callable[[Callable[[int, str], None]], object],
        on_success: Callable[[object], None],
        *,
        on_failure: Callable[[str], None] | None = None,
    ) -> None:
        if on_failure is None:
            self._start_worker(
                operation,
                on_success,
                determinate=True,
            )
        else:
            self._start_worker(
                operation,
                on_success,
                determinate=True,
                on_failure=on_failure,
            )

    def _start_worker(
        self,
        operation: Callable[[Callable[[int, str], None]], object],
        on_success: Callable[[object], None],
        *,
        determinate: bool,
        on_failure: Callable[[str], None] | None = None,
    ) -> None:
        if self._busy:
            return
        self._task_result = None
        self._task_error = None
        self._task_success_handler = on_success
        self._task_failure_handler = on_failure
        self._task_determinate = determinate
        self._set_busy(True, determinate=determinate)

        self._task_thread = BackgroundTaskThread(operation, self)
        self._task_thread.succeeded.connect(self._task_succeeded)
        self._task_thread.failed.connect(self._task_failed)
        self._task_thread.progress.connect(self._task_progress)
        self._task_thread.finished.connect(self._task_finished)
        self._task_thread.finished.connect(self._task_thread.deleteLater)
        self._task_thread.start()
        # Paint a started state immediately. The worker repeats this signal
        # from its own thread, while the operation itself reports 3% and above.
        self._task_progress(2, "Операция запущена")

    @Slot(object)
    def _task_succeeded(self, result: object) -> None:
        self._task_result = result

    @Slot(str)
    def _task_failed(self, message: str) -> None:
        self._task_error = message or "Операция завершилась ошибкой."

    @Slot(int, str)
    def _task_progress(self, value: int, message: str) -> None:
        formatted = f"{value}%"
        if message:
            formatted += f" — {tr(message)}"
        for name in ("dashboard_progress", "auth_progress"):
            progress = getattr(self, name, None)
            if progress is not None:
                try:
                    progress.setRange(0, 100)
                    progress.setValue(value)
                    progress.setFormat(formatted)
                except RuntimeError:
                    # A central-page replacement destroys its Qt widgets while
                    # the Python attribute can still reference the wrapper.
                    # Ignore only that deleted page and keep updating the live
                    # progress bar for the current page.
                    setattr(self, name, None)

    @Slot()
    def _task_finished(self) -> None:
        result = self._task_result
        error = self._task_error
        handler = self._task_success_handler
        failure_handler = self._task_failure_handler
        self._task_thread = None
        self._task_result = None
        self._task_error = None
        self._task_success_handler = None
        self._task_failure_handler = None
        self._task_determinate = False
        self._set_busy(False)
        if error is not None:
            if failure_handler is not None:
                failure_handler(error)
                return
            if self._direct_mount_pending:
                self._direct_mount_pending = False
                self._show_dashboard()
            self._show_error(error)
            return
        if handler is not None:
            try:
                handler(result)
            except (BioPGPError, OSError, TypeError, ValueError) as caught:
                self._show_error(str(caught))

    def _set_busy(self, busy: bool, *, determinate: bool = False) -> None:
        self._busy = busy
        for name in ("dashboard_progress", "auth_progress"):
            progress = getattr(self, name, None)
            if progress is None:
                continue
            try:
                if busy:
                    if determinate:
                        progress.setRange(0, 100)
                        progress.setValue(1)
                        progress.setFormat(tr("1% — Запуск операции"))
                    else:
                        progress.setRange(0, 0)
                        progress.setFormat("")
                progress.setVisible(busy)
            except RuntimeError:
                setattr(self, name, None)
        dashboard_status = getattr(self, "dashboard_status", None)
        if dashboard_status is not None and busy:
            try:
                dashboard_status.hide()
            except RuntimeError:
                self.dashboard_status = None
        central = self.centralWidget()
        if busy:
            self._busy_widget_states.clear()
            if central is not None:
                interactive: set[QWidget] = set()
                for widget_type in (
                    QAbstractButton,
                    QAbstractSpinBox,
                    QComboBox,
                    QLineEdit,
                    QSlider,
                ):
                    interactive.update(central.findChildren(widget_type))
                for widget in interactive:
                    self._busy_widget_states[widget] = widget.isEnabled()
                    widget.setEnabled(False)
        else:
            for widget, was_enabled in self._busy_widget_states.items():
                try:
                    widget.setEnabled(was_enabled)
                except RuntimeError:
                    pass
            self._busy_widget_states.clear()
        if busy:
            for action in (
                self._tray_show_action,
                self._tray_open_drive_action,
                self._tray_unmount_action,
                self._tray_exit_action,
            ):
                action.setEnabled(False)
        else:
            self._tray_show_action.setEnabled(True)
            self._sync_tray_state()
        # Do not change native window flags while a visible maximized window
        # is returning from a modal dialog. On Windows, Qt may synchronously
        # recreate the native window here and never return to the code that
        # starts the isolated disk helper. ``closeEvent`` already rejects
        # closing while ``_busy`` is true, so no title-bar mutation is needed.

    def _lock(self) -> None:
        if self._busy:
            return
        self._clear_session()
        self._show_unlock()
        if self.mount_manager.mounted_drive is not None:
            self._hide_to_tray()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self._busy:
            event.ignore()
            return
        if self._compact_settings_launch:
            self._clear_session()
            self._tray_icon.hide()
            event.accept()
            return
        if self.mount_manager.mounted_drive is not None:
            event.ignore()
            self._hide_to_tray()
            return
        self._clear_session()
        self._tray_icon.hide()
        event.accept()

    def _setup_tray(self) -> None:
        self._last_mounted_drive: str | None = None
        self._tray_icon = QSystemTrayIcon(line_icon("shield", "#38bdf8"), self)
        self._tray_menu = QMenu(self)

        self._tray_show_action = QAction(self)
        self._tray_show_action.setIcon(line_icon("shield"))
        self._tray_show_action.triggered.connect(self._show_from_tray)
        self._tray_menu.addAction(self._tray_show_action)

        self._tray_open_drive_action = QAction(self)
        self._tray_open_drive_action.setIcon(line_icon("vault"))
        self._tray_open_drive_action.triggered.connect(self._open_mounted_drive)
        self._tray_menu.addAction(self._tray_open_drive_action)

        self._tray_unmount_action = QAction(self)
        self._tray_unmount_action.setIcon(line_icon("eject"))
        self._tray_unmount_action.triggered.connect(self._unmount_container)
        self._tray_menu.addAction(self._tray_unmount_action)

        self._tray_menu.addSeparator()
        self._tray_exit_action = QAction(self)
        self._tray_exit_action.setIcon(line_icon("close"))
        self._tray_exit_action.triggered.connect(self._exit_from_tray)
        self._tray_menu.addAction(self._tray_exit_action)

        self._tray_icon.setContextMenu(self._tray_menu)
        self._tray_icon.activated.connect(self._tray_activated)
        self._retranslate_tray()
        self._sync_tray_state()

    def _retranslate_tray(self) -> None:
        self._tray_show_action.setText(tr("Открыть Clever PGP"))
        self._tray_open_drive_action.setText(tr("Открыть зашифрованный диск"))
        self._tray_unmount_action.setText(tr("Отключить зашифрованный диск"))
        self._tray_exit_action.setText(tr("Завершить Clever PGP"))

    def _sync_tray_state(self) -> None:
        drive = self.mount_manager.mounted_drive
        previous_drive = self._last_mounted_drive
        self._last_mounted_drive = drive
        mounted = drive is not None
        self._tray_open_drive_action.setEnabled(mounted and not self._busy)
        self._tray_unmount_action.setEnabled(mounted and not self._busy)
        detached_disk = mounted and self._uses_windows_system_disk
        self._tray_exit_action.setText(
            tr("Закрыть Clever PGP — диск останется подключённым")
            if detached_disk
            else tr("Завершить Clever PGP")
        )
        self._tray_exit_action.setEnabled(
            not self._busy and (not mounted or detached_disk)
        )
        self._tray_icon.setToolTip(
            tr("Clever PGP — диск {drive} подключён", drive=drive)
            if mounted
            else "Clever PGP"
        )
        if mounted:
            self._tray_icon.show()
        elif (
            previous_drive is not None
            and not self.isVisible()
            and self._direct_container_launch
            and not self._busy
        ):
            QTimer.singleShot(0, self._close_background_window)

    def _hide_to_tray(self) -> None:
        self._clear_session()
        if self.repository.get_profile() is not None:
            self._show_unlock()
        self._sync_tray_state()
        self._tray_icon.show()
        self.hide()

    def _show_from_tray(self) -> None:
        if self.session is None or not self.session.is_unlocked:
            if self.repository.get_profile() is None:
                self._show_profile_creation()
            else:
                self._show_unlock()
        self.showMaximized()
        self.raise_()
        self.activateWindow()

    def _open_mounted_drive(self) -> None:
        drive = self.mount_manager.mounted_drive
        if drive is not None:
            QDesktopServices.openUrl(QUrl.fromLocalFile(f"{drive}\\"))

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason not in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            return
        if self.mount_manager.mounted_drive is not None:
            self._open_mounted_drive()
        else:
            self._show_from_tray()

    def _exit_from_tray(self) -> None:
        if self._busy:
            return
        if (
            self.mount_manager.mounted_drive is not None
            and not self._uses_windows_system_disk
        ):
            return
        self._close_background_window()

    def _close_background_window(self) -> None:
        self._clear_session()
        self._tray_icon.hide()
        application = QApplication.instance()
        if application is not None:
            application.quit()

    @Slot()
    def _shutdown_for_uninstall(self) -> None:
        """Release profile files before the elevated uninstaller removes them."""

        if self._busy:
            return
        self._close_background_window()

    def _clear_session(self) -> None:
        if self.session is not None:
            self.session.lock()
            self.session = None

    def _show_about(self) -> None:
        if self._busy:
            return
        AboutDialog(self).exec()

    def _base_page(
        self,
        title: str,
        subtitle: str,
        *,
        compact: bool = False,
        page_icon: str | None = None,
    ) -> tuple[QWidget, QVBoxLayout]:
        viewport = QScrollArea()
        viewport.setObjectName("pageScroll")
        viewport.setFrameShape(QFrame.Shape.NoFrame)
        viewport.setWidgetResizable(True)
        viewport.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        page = QWidget()
        page.setObjectName("pageContent")
        page.setMinimumSize(0, 0)
        outer = QVBoxLayout(page)
        outer.setContentsMargins(24, 22, 24, 22)

        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        header_controls = QWidget()
        header_controls.setObjectName("headerControls")
        controls = QHBoxLayout(header_controls)
        controls.setContentsMargins(0, 0, 0, 0)
        controls.setSpacing(8)
        if self.session is not None and self.session.is_unlocked:
            settings_button = QPushButton()
            settings_button.setObjectName("headerIconButton")
            settings_button.setIcon(line_icon("settings", "#bae6fd"))
            settings_button.setFixedSize(46, 46)
            settings_button.setToolTip("Настройки доступа")
            settings_button.setAccessibleName("Настройки доступа")
            settings_button.clicked.connect(self._show_access_settings)
            controls.addWidget(settings_button, 0, Qt.AlignmentFlag.AlignTop)
        about_button = QPushButton()
        about_button.setObjectName("headerIconButton")
        about_button.setIcon(line_icon("info", "#bae6fd"))
        about_button.setFixedSize(46, 46)
        about_button.setToolTip("О программе")
        about_button.setAccessibleName("О программе")
        about_button.clicked.connect(self._show_about)
        controls.addWidget(about_button, 0, Qt.AlignmentFlag.AlignTop)
        header = ResponsiveBox(
            (brand, header_controls),
            breakpoint=560,
            spacing=8,
            align_last_right=True,
        )
        outer.addWidget(header)

        card = QFrame()
        card.setObjectName("authCard" if compact else "card")
        card.setSizePolicy(
            QSizePolicy.Policy.Preferred if compact else QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Maximum if compact else QSizePolicy.Policy.Expanding,
        )
        if compact:
            card.setMinimumWidth(0)
            card.setMaximumWidth(620)
        content = QVBoxLayout(card)
        content.setContentsMargins(34, 30, 34, 30)
        content.setSpacing(16)

        if page_icon is not None:
            hero_icon = QLabel()
            hero_icon.setObjectName("heroIcon")
            hero_icon.setPixmap(line_icon(page_icon, "#7dd3fc").pixmap(52, 52))
            hero_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            content.addWidget(hero_icon)

        title_label = QLabel(title)
        title_label.setObjectName("title")
        if compact:
            title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("muted")
        subtitle_label.setWordWrap(True)
        if compact:
            subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content.addWidget(title_label)
        content.addWidget(subtitle_label)

        if compact:
            centered = QHBoxLayout()
            centered.addStretch()
            centered.addWidget(card)
            centered.addStretch()
            outer.addStretch(1)
            outer.addLayout(centered)
            outer.addStretch(2)
        else:
            outer.addWidget(card, 1)
        viewport.setWidget(page)
        return viewport, content

    @staticmethod
    def _section_heading(title: str, icon_name: str) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(9)
        icon = QLabel()
        icon.setPixmap(line_icon(icon_name, "#7dd3fc").pixmap(22, 22))
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        row.addWidget(icon)
        row.addWidget(heading)
        row.addStretch()
        return row

    def _show_error(self, message: str) -> None:
        QMessageBox.critical(self, "Clever PGP", tr(message))

STYLESHEET = """
QMainWindow, QWidget {
    background: #111827;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
}
QScrollArea#pageScroll, QWidget#pageContent,
QScrollArea#pageScroll > QWidget > QWidget {
    background: #111827;
    border: 0;
}
QLabel {
    background: transparent;
}
QLabel#brand {
    color: #7dd3fc;
    font-size: 25px;
    font-weight: 700;
    padding-bottom: 12px;
}
QLabel#title {
    color: #f9fafb;
    font-size: 24px;
    font-weight: 650;
}
QLabel#sectionTitle {
    color: #f9fafb;
    font-size: 17px;
    font-weight: 650;
    padding-top: 8px;
}
QLabel#muted {
    color: #9ca3af;
}
QPushButton#headerIconButton {
    background: transparent;
    color: #bae6fd;
    border: 1px solid #334155;
    border-radius: 23px;
    padding: 0;
}
QPushButton#headerIconButton:hover {
    background: #172033;
    border-color: #38bdf8;
}
QLabel#status {
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 10px;
    padding: 18px;
    font-size: 16px;
}
QLabel#success {
    background: #052e2b;
    border: 1px solid #0f766e;
    border-radius: 10px;
    color: #99f6e4;
    padding: 18px;
    font-size: 16px;
}
QLabel#error {
    background: #3f151b;
    border: 1px solid #991b1b;
    border-radius: 10px;
    color: #fecaca;
    padding: 18px;
    font-size: 16px;
}
QFrame#card, QFrame#authCard {
    background: #182235;
    border: 1px solid #2d3b52;
    border-radius: 16px;
}
QFrame#authCard {
    border: 1px solid #36506f;
}
QLabel#heroIcon {
    padding: 4px 0 2px 0;
}
QFrame#dashboardPanel {
    background: #111b2c;
    border: 1px solid #334155;
    border-radius: 12px;
}
QLineEdit, QComboBox {
    background: #0f172a;
    border: 1px solid #475569;
    border-radius: 8px;
    color: #f9fafb;
    min-height: 40px;
    padding: 0 12px;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #38bdf8;
}
QPushButton {
    background: #263449;
    border: 1px solid #475569;
    border-radius: 8px;
    color: #f9fafb;
    min-height: 42px;
    padding: 0 18px;
    font-weight: 600;
    qproperty-iconSize: 20px 20px;
}
QPushButton::icon { padding-right: 5px; }
QPushButton:hover {
    background: #334155;
}
QPushButton#primary {
    background: #0284c7;
    border-color: #0ea5e9;
}
QPushButton#primary:hover {
    background: #0369a1;
}
QPushButton:disabled {
    color: #64748b;
    background: #1e293b;
    border-color: #334155;
}
QProgressBar {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    color: #f8fafc;
    min-height: 28px;
    max-height: 28px;
    text-align: center;
    font-weight: 650;
}
QProgressBar::chunk {
    background: #0284c7;
    border-radius: 7px;
}
"""
