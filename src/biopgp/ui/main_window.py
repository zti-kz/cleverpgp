from __future__ import annotations

import subprocess
import hmac
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QAction, QCloseEvent, QDesktopServices
from PySide6.QtWidgets import (
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
    QSizePolicy,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from biopgp.core.errors import BioPGPError
from biopgp.core.block_container import BlockVaultContainer as EncryptedContainer
from biopgp.core.file_crypto import FileCryptoService
from biopgp.core.mount import VaultMountManager, mount_backend_available
from biopgp.core.mount_router import AutomaticMountManager
from biopgp.core.models import UnlockMode
from biopgp.core.profile_service import ProfileService, UnlockedSession
from biopgp.core.storage import ProfileRepository
from biopgp.core.windows_storage import (
    WindowsSystemDiskManager,
    winspd_driver_available,
)
from biopgp.core.winspd import MIN_WINDOWS_DISK_CAPACITY
from biopgp.localization import (
    available_languages,
    current_language,
    localize_widget_tree,
    set_language,
    tr,
)
from biopgp.biometrics.key_protection import default_key_protector
from biopgp.biometrics.service import BiometricService
from biopgp.ui.about_dialog import AboutDialog
from biopgp.ui.container_dialog import ContainerCreationDialog
from biopgp.ui.face_dialog import FaceEnrollmentDialog, FaceVerificationDialog
from biopgp.ui.icons import line_icon
from biopgp.ui.resize_dialog import ContainerResizeDialog
from biopgp.ui.settings_dialog import AccessSettingsDialog


class BackgroundWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()
    progress = Signal(int, str)

    def __init__(
        self, operation: Callable[[Callable[[int, str], None]], object]
    ) -> None:
        super().__init__()
        self.operation = operation

    @Slot()
    def run(self) -> None:
        try:
            self.succeeded.emit(self.operation(self._report_progress))
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            self.finished.emit()

    def _report_progress(self, value: int, message: str) -> None:
        self.progress.emit(max(0, min(100, int(value))), message)


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
        self.mount_manager = mount_manager or VaultMountManager()
        self._direct_container_launch = startup_container is not None
        self._direct_mount_pending = False
        self._startup_action = startup_action
        self._startup_drive = startup_drive
        self.startup_container = (
            startup_container.expanduser().resolve()
            if startup_container is not None
            else None
        )
        self.session: UnlockedSession | None = None
        self._busy = False
        self._task_thread: QThread | None = None
        self._task_worker: BackgroundWorker | None = None
        self._task_result: object = None
        self._task_error: str | None = None
        self._task_success_handler: Callable[[object], None] | None = None
        self._task_determinate = False

        title_suffix = (
            f" — {self.startup_container.name}" if self.startup_container else ""
        )
        self.setWindowTitle(f"Clever PGP{title_suffix}")
        self.setMinimumSize(720, 520)
        self.resize(840, 600)
        self.setStyleSheet(STYLESHEET)
        self._setup_tray()

        self._mount_monitor = QTimer(self)
        self._mount_monitor.setInterval(1000)
        self._mount_monitor.timeout.connect(self._sync_tray_state)
        self._mount_monitor.start()

        if self.repository.has_profile():
            self._show_unlock()
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
        else:
            self._show_dashboard()
            if self._startup_action == "settings":
                self._startup_action = None
                QTimer.singleShot(0, self._show_access_settings)
            elif self._startup_action == "resize":
                self._startup_action = None
                QTimer.singleShot(0, self._show_resize_dialog)

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

        action_columns = QHBoxLayout()
        action_columns.setSpacing(18)

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
        file_layout.addWidget(encrypt_button)
        file_layout.addWidget(decrypt_button)

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

        action_columns.addWidget(file_panel, 1)
        action_columns.addWidget(container_panel, 1)
        content.addLayout(action_columns, 1)

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
        profile = self.repository.get_profile()
        if profile is None or self.session is None or not self.session.is_unlocked:
            self._show_unlock()
            return
        dialog = AccessSettingsDialog(
            profile.unlock_mode,
            biometric_enrolled=self.repository.has_biometric_profile(),
            parent=self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted or dialog.request is None:
            return
        request = dialog.request
        if request.operation == "face":
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
                self._show_dashboard()
                self._set_dashboard_status(tr("Режим разблокировки изменён."))

            self._start_progress_task(change_mode, mode_changed)
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
                self._show_dashboard()
                self._set_dashboard_status(tr("Мастер-пароль успешно изменён."))

            self._start_progress_task(change_password, password_changed)

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
                context_menu_labels=(
                    tr("Открыть зашифрованный диск"),
                    tr("Сведения о диске"),
                    tr("Настройки доступа"),
                    tr("Увеличить диск"),
                    tr("Отключить зашифрованный диск"),
                ),
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

    def _encrypt_file(self) -> None:
        source_name, _ = QFileDialog.getOpenFileName(self, tr("Выберите файл"))
        if not source_name:
            return
        source = Path(source_name)
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
        self._run_file_operation(
            tr("Расшифровано"),
            lambda key, progress: self.file_crypto.decrypt_file(
                source,
                Path(target_name),
                key,
                overwrite=True,
                progress=progress,
            ),
        )

    def _run_file_operation(
        self,
        message: str,
        operation: Callable[[bytes, Callable[[int, str], None]], Path],
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
            )
        elif self._automatically_selects_disk_backend:
            dialog = ContainerCreationDialog(
                self,
                minimum_capacity=MIN_WINDOWS_DISK_CAPACITY,
                allow_backend_choice=True,
                system_backend_available=winspd_driver_available(),
                winfsp_backend_available=mount_backend_available(),
            )
        else:
            dialog = ContainerCreationDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        target = dialog.container_path
        data_capacity = dialog.data_capacity
        volume_label = dialog.volume_label
        file_system = dialog.file_system
        create_as_system_disk = self._uses_windows_system_disk or (
            self._automatically_selects_disk_backend and dialog.system_disk
        )

        def create_container(
            master_key: bytes, progress: Callable[[int, str], None]
        ) -> tuple[Path, str | None, str | None]:
            if create_as_system_disk:
                try:
                    drive = self.mount_manager.create_and_mount(
                        target,
                        master_key,
                        logical_capacity=data_capacity,
                        label=volume_label,
                        file_system=file_system,
                        context_menu_labels=(
                            tr("Открыть зашифрованный диск"),
                            tr("Сведения о диске"),
                            tr("Настройки доступа"),
                            tr("Увеличить диск"),
                            tr("Отключить зашифрованный диск"),
                        ),
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

    def _disk_backend_available(self) -> bool:
        if self._uses_windows_system_disk:
            return winspd_driver_available()
        if self._automatically_selects_disk_backend:
            return winspd_driver_available() or mount_backend_available()
        return mount_backend_available()

    def _enroll_face(self) -> None:
        try:
            dialog = FaceEnrollmentDialog(self)
            if dialog.exec() != QDialog.DialogCode.Accepted or dialog.template is None:
                return
            template = dialog.template.copy()
            service = self._new_biometric_service()
        except BioPGPError as error:
            self._show_error(str(error))
            return

        def enroll(master_key: bytes) -> None:
            try:
                service.enroll(template, master_key)
            finally:
                template.fill(0)

        self._start_key_task(
            enroll,
            lambda result: self._set_dashboard_status(
                tr("Лицо зарегистрировано. Биометрический ключ защищён Windows.")
            ),
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
        ) -> str:
            if self._uses_windows_system_disk or getattr(
                self.mount_manager,
                "automatically_selects_backend",
                False,
            ):
                return self.mount_manager.mount(
                    source,
                    master_key,
                    context_menu_labels=(
                        tr("Открыть зашифрованный диск"),
                        tr("Сведения о диске"),
                        tr("Настройки доступа"),
                        tr("Увеличить диск"),
                        tr("Отключить зашифрованный диск"),
                    ),
                    progress=progress,
                )
            return self.mount_manager.mount(
                source,
                master_key,
                progress=progress,
            )

        self._start_key_progress_task(
            mount_container,
            self._container_mounted,
        )

    def _container_mounted(self, result: object) -> None:
        drive = str(result)
        direct_launch = self._direct_mount_pending
        self._direct_mount_pending = False
        self._sync_tray_state()
        self._set_dashboard_status(
            tr(
                "Контейнер подключён как {drive}\\. Копируйте файлы на этот диск.",
                drive=drive,
            )
        )
        QDesktopServices.openUrl(QUrl.fromLocalFile(f"{drive}\\"))
        if direct_launch:
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

    def _start_key_task(
        self,
        operation: Callable[[bytes], object],
        on_success: Callable[[object], None],
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

        self._start_task(protected_operation, on_success)

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
    ) -> None:
        self._start_worker(lambda _progress: operation(), on_success, determinate=False)

    def _start_progress_task(
        self,
        operation: Callable[[Callable[[int, str], None]], object],
        on_success: Callable[[object], None],
    ) -> None:
        self._start_worker(operation, on_success, determinate=True)

    def _start_worker(
        self,
        operation: Callable[[Callable[[int, str], None]], object],
        on_success: Callable[[object], None],
        *,
        determinate: bool,
    ) -> None:
        if self._busy:
            return
        self._task_result = None
        self._task_error = None
        self._task_success_handler = on_success
        self._task_determinate = determinate
        self._set_busy(True, determinate=determinate)

        self._task_thread = QThread(self)
        self._task_worker = BackgroundWorker(operation)
        self._task_worker.moveToThread(self._task_thread)
        self._task_thread.started.connect(self._task_worker.run)
        self._task_worker.succeeded.connect(self._task_succeeded)
        self._task_worker.failed.connect(self._task_failed)
        self._task_worker.progress.connect(self._task_progress)
        self._task_worker.finished.connect(self._task_thread.quit)
        self._task_worker.finished.connect(self._task_worker.deleteLater)
        self._task_thread.finished.connect(self._task_finished)
        self._task_thread.finished.connect(self._task_thread.deleteLater)
        self._task_thread.start()

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
                progress.setRange(0, 100)
                progress.setValue(value)
                progress.setFormat(formatted)

    @Slot()
    def _task_finished(self) -> None:
        result = self._task_result
        error = self._task_error
        handler = self._task_success_handler
        self._task_thread = None
        self._task_worker = None
        self._task_result = None
        self._task_error = None
        self._task_success_handler = None
        self._task_determinate = False
        self._set_busy(False)
        if error is not None:
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
        restore_window = self.isVisible()
        for name in ("dashboard_progress", "auth_progress"):
            progress = getattr(self, name, None)
            if progress is None:
                continue
            if busy:
                if determinate:
                    progress.setRange(0, 100)
                    progress.setValue(1)
                    progress.setFormat(tr("1% — Запуск операции"))
                else:
                    progress.setRange(0, 0)
                    progress.setFormat("")
            progress.setVisible(busy)
        if hasattr(self, "dashboard_status") and busy:
            self.dashboard_status.hide()
        central = self.centralWidget()
        if central is not None:
            for button in central.findChildren(QPushButton):
                button.setEnabled(not busy)
        self._tray_unmount_action.setEnabled(
            not busy and self.mount_manager.mounted_drive is not None
        )
        self._tray_open_drive_action.setEnabled(
            not busy and self.mount_manager.mounted_drive is not None
        )
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, not busy)
        if restore_window:
            self.show()

    def _lock(self) -> None:
        if self.session is not None:
            self.session.lock()
            self.session = None
        self._show_unlock()
        if self.mount_manager.mounted_drive is not None:
            self._hide_to_tray()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self._busy:
            event.ignore()
            return
        if self.mount_manager.mounted_drive is not None:
            event.ignore()
            self._hide_to_tray()
            return
        if self.session is not None:
            self.session.lock()
            self.session = None
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
        self._sync_tray_state()
        self._tray_icon.show()
        self.hide()

    def _show_from_tray(self) -> None:
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
        if self.session is not None:
            self.session.lock()
            self.session = None
        self._tray_icon.hide()
        application = QApplication.instance()
        if application is not None:
            application.quit()

    def _show_about(self) -> None:
        AboutDialog(self).exec()

    def _base_page(
        self,
        title: str,
        subtitle: str,
        *,
        compact: bool = False,
        page_icon: str | None = None,
    ) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(42, 34, 42, 34)

        header = QHBoxLayout()
        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        header.addWidget(brand)
        header.addStretch()
        language_selector = QComboBox()
        language_selector.setObjectName("languageSelector")
        language_selector.setFixedWidth(132)
        language_selector.setToolTip(tr("Язык интерфейса"))
        language_selector.setAccessibleName(tr("Язык интерфейса"))
        for language in available_languages():
            language_selector.addItem(language.native_name, language.code)
        selected_index = language_selector.findData(current_language())
        language_selector.setCurrentIndex(max(0, selected_index))
        language_selector.currentIndexChanged.connect(
            lambda _index: self._change_language(language_selector.currentData())
        )
        header.addWidget(language_selector, 0, Qt.AlignmentFlag.AlignTop)
        if self.session is not None and self.session.is_unlocked:
            settings_button = QPushButton()
            settings_button.setObjectName("headerIconButton")
            settings_button.setIcon(line_icon("settings", "#bae6fd"))
            settings_button.setFixedSize(46, 46)
            settings_button.setToolTip("Настройки доступа")
            settings_button.setAccessibleName("Настройки доступа")
            settings_button.clicked.connect(self._show_access_settings)
            header.addWidget(settings_button, 0, Qt.AlignmentFlag.AlignTop)
        about_button = QPushButton()
        about_button.setObjectName("headerIconButton")
        about_button.setIcon(line_icon("info", "#bae6fd"))
        about_button.setFixedSize(46, 46)
        about_button.setToolTip("О программе")
        about_button.setAccessibleName("О программе")
        about_button.clicked.connect(self._show_about)
        header.addWidget(about_button, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(header)

        card = QFrame()
        card.setObjectName("authCard" if compact else "card")
        card.setSizePolicy(
            QSizePolicy.Policy.Preferred if compact else QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Maximum if compact else QSizePolicy.Policy.Expanding,
        )
        if compact:
            card.setMinimumWidth(520)
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
        return page, content

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

    def _change_language(self, code: str) -> None:
        if not code or code == current_language():
            return
        set_language(code)
        self.repository.set_setting("language", code)
        self._retranslate_tray()
        if self.session is not None and self.session.is_unlocked:
            self._show_dashboard()
        elif self.repository.has_profile():
            self._show_unlock()
        else:
            self._show_profile_creation()


STYLESHEET = """
QMainWindow, QWidget {
    background: #111827;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
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
