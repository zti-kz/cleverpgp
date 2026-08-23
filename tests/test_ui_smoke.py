import os
import time
from collections.abc import Callable
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nacl import pwhash  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import QCloseEvent  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QDialog,
    QLabel,
    QPushButton,
    QScrollArea,
)

from biopgp.core.container import MIN_DATA_CAPACITY  # noqa: E402
from biopgp.core.block_volume import InvalidBlockVolumeError  # noqa: E402
from biopgp.core.file_crypto import FileCryptoService  # noqa: E402
from biopgp.core.models import BiometricProfile, UnlockMode  # noqa: E402
from biopgp.core.profile_service import KdfParameters, ProfileService  # noqa: E402
from biopgp.core.storage import ProfileRepository  # noqa: E402
from biopgp.ui.main_window import MainWindow  # noqa: E402
from biopgp.ui import main_window as main_window_module  # noqa: E402
from biopgp.ui.settings_dialog import AccessSettingsRequest  # noqa: E402
from biopgp.ui.hidden_volume_dialog import (  # noqa: E402
    HiddenVolumeCreationRequest,
    OpaqueVolumeUnlockRequest,
)


def test_first_window_can_be_created(tmp_path: Path) -> None:
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )

    window = MainWindow(repository, profile_service, FileCryptoService())

    assert window.windowTitle() == "Clever PGP"
    assert window.centralWidget() is not None
    about_buttons = [
        button
        for button in window.centralWidget().findChildren(QPushButton)
        if button.toolTip() == "О программе"
    ]
    assert len(about_buttons) == 1
    assert about_buttons[0].text() == ""
    assert not about_buttons[0].icon().isNull()
    window.close()
    application.processEvents()


def test_background_task_shows_progress_and_blocks_closing(tmp_path: Path) -> None:
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profile_service.create_profile("Test", password)
    window = MainWindow(repository, profile_service, FileCryptoService())
    window.session = profile_service.unlock_with_password(password)
    window._show_dashboard()
    window.show()
    application.processEvents()
    results: list[object] = []

    window._start_task(lambda: (time.sleep(0.1), "done")[1], results.append)
    assert window._busy
    assert window.dashboard_progress.isVisible()
    assert not window.windowFlags() & Qt.WindowType.WindowCloseButtonHint
    assert all(
        not button.isEnabled()
        for button in window.centralWidget().findChildren(QPushButton)
    )

    deadline = time.monotonic() + 5
    while window._busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert not window._busy
    assert not window.dashboard_progress.isVisible()
    assert window.windowFlags() & Qt.WindowType.WindowCloseButtonHint
    assert results == ["done"]
    window.close()
    application.processEvents()


def test_face_only_mode_keeps_hidden_master_password_recovery(tmp_path: Path) -> None:
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profile = profile_service.create_profile(
        "Test",
        password,
        UnlockMode.FACE_ONLY,
    )
    repository.save_biometric_profile(
        BiometricProfile(
            profile_id=profile.profile_id,
            protected_biometric_key=b"protected-key",
            encrypted_template=b"encrypted-template",
            encrypted_master_key=b"biometric-master-key-slot",
            model_id="test-model",
            model_sha256="0" * 64,
            match_threshold=0.7,
            enrolled_at="2026-08-23T00:00:00+00:00",
        )
    )

    window = MainWindow(repository, profile_service, FileCryptoService())
    recovery = next(
        button
        for button in window.centralWidget().findChildren(QPushButton)
        if button.text() == "Использовать мастер-пароль"
    )

    assert window.unlock_password_input.isHidden()
    assert window.unlock_password_button.isHidden()
    recovery.click()
    assert not window.unlock_password_input.isHidden()
    assert not window.unlock_password_button.isHidden()

    window.close()
    application.processEvents()


def test_access_settings_changes_password_without_replacing_session_key(
    monkeypatch, tmp_path: Path
) -> None:
    old_password = "correct horse battery staple"
    new_password = "new correct horse battery staple"

    class PasswordDialog:
        request = AccessSettingsRequest(
            "password",
            current_password=old_password,
            new_password=new_password,
        )

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

    monkeypatch.setattr(
        main_window_module,
        "AccessSettingsDialog",
        PasswordDialog,
    )
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    profile_service.create_profile("Test", old_password)
    window = MainWindow(repository, profile_service, FileCryptoService())
    window.session = profile_service.unlock_with_password(old_password)
    original_key = window.session.master_key_copy()
    window._show_dashboard()
    window.show()
    application.processEvents()

    window._show_access_settings()
    deadline = time.monotonic() + 5
    while window._busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert not window._busy
    assert window.session is not None
    assert window.session.master_key_copy() == original_key
    changed_session = profile_service.unlock_with_password(new_password)
    assert changed_session.master_key_copy() == original_key
    changed_session.lock()
    assert "Мастер-пароль успешно изменён" in window.dashboard_status.text()

    window.close()
    application.processEvents()


def test_explorer_settings_open_without_showing_dashboard(
    tmp_path: Path,
) -> None:
    class MountedDisk:
        mounted_drive = "Z:"

        def unmount(self) -> None:
            raise AssertionError("Settings must not disconnect the disk")

    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profile_service.create_profile("Test", password)
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(),
        mount_manager=MountedDisk(),  # type: ignore[arg-type]
        startup_action="settings",
        startup_drive="z:\\",
    )
    settings_calls: list[bool] = []
    window._show_access_settings = lambda: settings_calls.append(True)  # type: ignore[method-assign]

    window._complete_unlock(profile_service.unlock_with_password(password))
    application.processEvents()

    assert settings_calls == [True]
    assert not hasattr(window, "dashboard_status")
    window.close()
    application.processEvents()


def test_explorer_settings_reject_wrong_drive_without_disconnect(
    tmp_path: Path,
) -> None:
    class MountedDisk:
        mounted_drive = "Y:"

        def __init__(self) -> None:
            self.unmount_calls = 0

        def unmount(self) -> None:
            self.unmount_calls += 1

    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profile_service.create_profile("Test", password)
    mounted = MountedDisk()
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(),
        mount_manager=mounted,  # type: ignore[arg-type]
        startup_action="settings",
        startup_drive="Z:\\",
    )

    window._complete_unlock(profile_service.unlock_with_password(password))
    application.processEvents()
    visible_text = " ".join(
        label.text() for label in window.centralWidget().findChildren(QLabel)
    )

    assert "Выбранный виртуальный диск Clever PGP не подключён" in visible_text
    assert mounted.unmount_calls == 0
    event = QCloseEvent()
    window.closeEvent(event)
    assert event.isAccepted()
    assert mounted.unmount_calls == 0
    window.close()
    application.processEvents()


def test_explorer_settings_change_password_without_opening_dashboard(
    monkeypatch,
    tmp_path: Path,
) -> None:
    old_password = "correct horse battery staple"
    new_password = "new correct horse battery staple"

    class PasswordDialog:
        request = AccessSettingsRequest(
            "password",
            current_password=old_password,
            new_password=new_password,
        )

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            assert _kwargs["drive"] == "Z:"

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

    class MountedDisk:
        mounted_drive = "Z:"

        def __init__(self) -> None:
            self.unmount_calls = 0

        def unmount(self) -> None:
            self.unmount_calls += 1

    monkeypatch.setattr(
        main_window_module,
        "AccessSettingsDialog",
        PasswordDialog,
    )
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    profile_service.create_profile("Test", old_password)
    mounted = MountedDisk()
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(),
        mount_manager=mounted,  # type: ignore[arg-type]
        startup_action="settings",
        startup_drive="Z:\\",
    )
    session = profile_service.unlock_with_password(old_password)
    original_key = session.master_key_copy()

    window._complete_unlock(session)
    application.processEvents()
    deadline = time.monotonic() + 5
    while window._busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)
    visible_text = " ".join(
        label.text() for label in window.centralWidget().findChildren(QLabel)
    )

    assert not window._busy
    assert "Мастер-пароль успешно изменён" in visible_text
    assert not hasattr(window, "dashboard_status")
    assert mounted.unmount_calls == 0
    changed_session = profile_service.unlock_with_password(new_password)
    assert changed_session.master_key_copy() == original_key
    changed_session.lock()
    window.close()
    application.processEvents()


def test_progress_task_displays_percentage_and_stage(tmp_path: Path) -> None:
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profile_service.create_profile("Test", password)
    window = MainWindow(repository, profile_service, FileCryptoService())
    window.session = profile_service.unlock_with_password(password)
    window._show_dashboard()
    window.show()
    application.processEvents()

    def operation(progress: Callable[[int, str], None]) -> str:
        progress(42, "Проверка прогресса")
        time.sleep(0.1)
        progress(100, "Готово")
        return "done"

    window._start_progress_task(operation, lambda _result: None)
    deadline = time.monotonic() + 5
    saw_percentage = False
    while window._busy and time.monotonic() < deadline:
        application.processEvents()
        if "42%" in window.dashboard_progress.format():
            saw_percentage = True
        time.sleep(0.01)

    assert saw_percentage
    window.close()
    application.processEvents()


def test_container_creation_and_mount_use_one_continuous_progress_task(
    monkeypatch, tmp_path: Path
) -> None:
    class CreationDialog:
        container_path = tmp_path / "continuous.cpgv"
        data_capacity = MIN_DATA_CAPACITY
        volume_label = "Continuous"
        file_system = "NTFS"

        def __init__(self, parent: object = None) -> None:
            pass

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

    class MountedDisk:
        def __init__(self) -> None:
            self.mounted_drive: str | None = None

        def mount(
            self,
            source: Path,
            key: bytes,
            *,
            progress: Callable[[int, str], None],
        ) -> str:
            progress(5, "Проверка")
            progress(25, "Запуск")
            self.mounted_drive = "Z:"
            progress(100, "Готово")
            return self.mounted_drive

        def unmount(self) -> None:
            self.mounted_drive = None

    monkeypatch.setattr(
        main_window_module, "ContainerCreationDialog", CreationDialog
    )
    monkeypatch.setattr(main_window_module, "mount_backend_available", lambda: True)
    monkeypatch.setattr(
        main_window_module.QDesktopServices, "openUrl", lambda _url: True
    )
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profile_service.create_profile("Test", password)
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(),
        mount_manager=MountedDisk(),
    )
    window.session = profile_service.unlock_with_password(password)
    window._show_dashboard()
    window.show()
    application.processEvents()
    worker_starts: list[bool] = []
    original_start_worker = window._start_worker

    def record_worker_start(
        operation: Callable[[Callable[[int, str], None]], object],
        on_success: Callable[[object], None],
        *,
        determinate: bool,
    ) -> None:
        worker_starts.append(determinate)
        original_start_worker(
            operation, on_success, determinate=determinate
        )

    window._start_worker = record_worker_start
    window._create_container()
    deadline = time.monotonic() + 5
    while window._busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert (tmp_path / "continuous.cpgv").is_file()
    assert worker_starts == [True]
    assert window.mount_manager.mounted_drive == "Z:"
    window.mount_manager.mounted_drive = None
    window.close()
    application.processEvents()


def test_system_disk_creation_uses_winspd_lifecycle_manager(
    monkeypatch, tmp_path: Path
) -> None:
    class CreationDialog:
        container_path = tmp_path / "system.cpgv"
        data_capacity = 64 * 1024 * 1024
        volume_label = "System disk"
        file_system = "EXFAT"
        requested_minimum: int | None = None
        requested_system_mode = False

        def __init__(
            self,
            parent: object = None,
            *,
            minimum_capacity: int,
            system_disk: bool,
            hidden_volume_available: bool,
        ) -> None:
            del parent
            assert hidden_volume_available
            type(self).requested_minimum = minimum_capacity
            type(self).requested_system_mode = system_disk

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

    class SystemDiskManager:
        def __init__(self) -> None:
            self.mounted_drive: str | None = None
            self.create_call: dict[str, object] | None = None
            self.mount_call: dict[str, object] | None = None

        def create_and_mount(
            self,
            container_path: Path,
            master_key: bytes,
            **options: object,
        ) -> str:
            progress = options.pop("progress")
            assert callable(progress)
            progress(50, "Форматирование")
            self.create_call = {
                "container_path": container_path,
                "master_key": master_key,
                **options,
            }
            self.mounted_drive = "Y:"
            progress(100, "Готово")
            return self.mounted_drive

        def mount(
            self,
            container_path: Path,
            master_key: bytes,
            **options: object,
        ) -> str:
            progress = options.pop("progress")
            assert callable(progress)
            self.mount_call = {
                "container_path": container_path,
                "master_key": master_key,
                **options,
            }
            self.mounted_drive = "X:"
            progress(100, "Готово")
            return self.mounted_drive

        def unmount(self) -> None:
            self.mounted_drive = None

    def unexpected_legacy_creation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Legacy WinFsp container path was used.")

    monkeypatch.setattr(
        main_window_module, "WindowsSystemDiskManager", SystemDiskManager
    )
    monkeypatch.setattr(
        main_window_module, "ContainerCreationDialog", CreationDialog
    )
    monkeypatch.setattr(
        main_window_module.EncryptedContainer,
        "create",
        unexpected_legacy_creation,
    )
    monkeypatch.setattr(
        main_window_module.QDesktopServices, "openUrl", lambda _url: True
    )
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profile_service.create_profile("Test", password)
    manager = SystemDiskManager()
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(),
        mount_manager=manager,
    )
    window.session = profile_service.unlock_with_password(password)
    window._show_dashboard()
    window.show()
    application.processEvents()

    window._create_container()
    deadline = time.monotonic() + 5
    while window._busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert CreationDialog.requested_minimum == 32 * 1024 * 1024
    assert CreationDialog.requested_system_mode
    assert manager.mounted_drive == "Y:"
    assert manager.create_call is not None
    assert manager.create_call["container_path"] == tmp_path / "system.cpgv"
    assert manager.create_call["logical_capacity"] == 64 * 1024 * 1024
    assert manager.create_call["label"] == "System disk"
    assert manager.create_call["file_system"] == "EXFAT"
    assert manager.create_call["context_menu_labels"] == (
        "Открыть зашифрованный диск",
        "Сведения о диске",
        "Настройки доступа",
        "Увеличить диск",
        "Отключить зашифрованный диск",
    )

    manager.mounted_drive = None
    window._mount_container(tmp_path / "existing-system.cpgv")
    deadline = time.monotonic() + 5
    while window._busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert manager.mounted_drive == "X:"
    assert manager.mount_call is not None
    assert manager.mount_call["context_menu_labels"] == (
        "Открыть зашифрованный диск",
        "Сведения о диске",
        "Настройки доступа",
        "Увеличить диск",
        "Отключить зашифрованный диск",
    )
    window._sync_tray_state()
    assert window._tray_exit_action.isEnabled()
    assert "диск останется подключённым" in window._tray_exit_action.text()

    manager.mounted_drive = None
    window.close()
    application.processEvents()


def test_direct_open_auto_routes_system_disk_and_hides_to_tray(
    monkeypatch, tmp_path: Path
) -> None:
    class AutomaticDiskManager:
        automatically_selects_backend = True

        def __init__(self) -> None:
            self.mounted_drive: str | None = None
            self.uses_windows_system_disk = False
            self.mount_call: dict[str, object] | None = None

        def mount(
            self,
            source: Path,
            key: bytes,
            **options: object,
        ) -> str:
            progress = options.pop("progress")
            assert callable(progress)
            self.mount_call = {
                "source": source,
                "key": key,
                **options,
            }
            progress(3, "Проверка типа зашифрованного диска")
            self.uses_windows_system_disk = True
            self.mounted_drive = "R:"
            progress(100, "Виртуальный диск готов")
            return self.mounted_drive

        def unmount(self) -> None:
            self.mounted_drive = None
            self.uses_windows_system_disk = False

    opened_urls: list[str] = []
    monkeypatch.setattr(
        main_window_module.QDesktopServices,
        "openUrl",
        lambda url: opened_urls.append(url.toLocalFile()) or True,
    )
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profile_service.create_profile("Test", password)
    manager = AutomaticDiskManager()
    container_path = tmp_path / "automatic-system.cpgv"
    container_path.touch()
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(),
        mount_manager=manager,  # type: ignore[arg-type]
        startup_container=container_path,
    )
    window.session = profile_service.unlock_with_password(password)
    window._show_dashboard()
    window.show()
    application.processEvents()
    window._direct_mount_pending = True

    window._mount_container(container_path)
    deadline = time.monotonic() + 5
    while (window._busy or window.isVisible()) and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert manager.mount_call is not None
    assert manager.mount_call["source"] == container_path
    assert manager.mount_call["context_menu_labels"] == (
        "Открыть зашифрованный диск",
        "Сведения о диске",
        "Настройки доступа",
        "Увеличить диск",
        "Отключить зашифрованный диск",
    )
    assert manager.uses_windows_system_disk
    assert manager.mounted_drive == "R:"
    assert opened_urls[-1].rstrip("\\/") == "R:"
    assert not window.isVisible()
    assert window._tray_exit_action.isEnabled()

    manager.mounted_drive = None
    manager.uses_windows_system_disk = False
    window.close()
    application.processEvents()


def test_automatic_manager_creates_selected_fast_windows_disk(
    monkeypatch, tmp_path: Path
) -> None:
    class CreationDialog:
        container_path = tmp_path / "automatic-created.cpgv"
        data_capacity = 96 * 1024 * 1024
        volume_label = "Fast disk"
        file_system = "NTFS"
        system_disk = True
        options: dict[str, object] | None = None

        def __init__(self, parent: object = None, **options: object) -> None:
            del parent
            type(self).options = options

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

    class AutomaticDiskManager:
        automatically_selects_backend = True
        uses_windows_system_disk = False

        def __init__(self) -> None:
            self.mounted_drive: str | None = None
            self.create_call: dict[str, object] | None = None

        def create_and_mount(
            self,
            container_path: Path,
            master_key: bytes,
            **options: object,
        ) -> str:
            progress = options.pop("progress")
            assert callable(progress)
            progress(82, "Ожидание разрешения Windows")
            self.create_call = {
                "container_path": container_path,
                "master_key": master_key,
                **options,
            }
            self.uses_windows_system_disk = True
            self.mounted_drive = "Q:"
            progress(100, "Виртуальный диск готов")
            return self.mounted_drive

        def unmount(self) -> None:
            self.mounted_drive = None
            self.uses_windows_system_disk = False

    def unexpected_legacy_creation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("WinFsp creation was used for the selected fast disk.")

    monkeypatch.setattr(
        main_window_module, "ContainerCreationDialog", CreationDialog
    )
    monkeypatch.setattr(main_window_module, "winspd_driver_available", lambda: True)
    monkeypatch.setattr(main_window_module, "mount_backend_available", lambda: True)
    monkeypatch.setattr(
        main_window_module.EncryptedContainer,
        "create",
        unexpected_legacy_creation,
    )
    monkeypatch.setattr(
        main_window_module.QDesktopServices, "openUrl", lambda _url: True
    )
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profile_service.create_profile("Test", password)
    manager = AutomaticDiskManager()
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(),
        mount_manager=manager,  # type: ignore[arg-type]
    )
    window.session = profile_service.unlock_with_password(password)
    window._show_dashboard()
    window.show()
    application.processEvents()

    assert window._disk_backend_available()
    window._create_container()
    deadline = time.monotonic() + 5
    while window._busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert CreationDialog.options == {
        "minimum_capacity": 32 * 1024 * 1024,
        "allow_backend_choice": True,
        "system_backend_available": True,
        "winfsp_backend_available": True,
        "hidden_volume_available": True,
    }
    assert manager.create_call is not None
    assert manager.create_call["container_path"] == tmp_path / "automatic-created.cpgv"
    assert manager.create_call["logical_capacity"] == 96 * 1024 * 1024
    assert manager.create_call["file_system"] == "NTFS"
    assert manager.mounted_drive == "Q:"

    manager.mounted_drive = None
    manager.uses_windows_system_disk = False
    window.close()
    application.processEvents()


def test_hidden_disk_creation_uses_dual_password_windows_workflow(
    monkeypatch, tmp_path: Path
) -> None:
    class CreationDialog:
        container_path = tmp_path / "hidden-created.cpgv"
        data_capacity = 96 * 1024 * 1024
        volume_label = "Outer"
        file_system = "NTFS"
        system_disk = True
        hidden_volume = True

        def __init__(self, parent: object = None, **_options: object) -> None:
            del parent

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

    class HiddenDialog:
        request = HiddenVolumeCreationRequest(
            32 * 1024 * 1024,
            "outer correct horse battery staple",
            "hidden correct horse battery staple",
            "Private",
        )

        def __init__(
            self,
            outer_capacity: int,
            outer_label: str,
            parent: object = None,
        ) -> None:
            del parent
            assert outer_capacity == 96 * 1024 * 1024
            assert outer_label == "Outer"

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

    class Manager:
        automatically_selects_backend = True
        uses_windows_system_disk = False

        def __init__(self) -> None:
            self.mounted_drive: str | None = None
            self.hidden_call: dict[str, object] | None = None

        def create_hidden_and_mount(
            self,
            path: Path,
            outer_password: str,
            hidden_password: str,
            **options: object,
        ) -> str:
            progress = options.pop("progress")
            assert callable(progress)
            self.hidden_call = {
                "path": path,
                "outer_password": outer_password,
                "hidden_password": hidden_password,
                **options,
            }
            self.uses_windows_system_disk = True
            self.mounted_drive = "H:"
            progress(100, "Скрытый виртуальный диск готов")
            return self.mounted_drive

        def unmount(self) -> None:
            self.mounted_drive = None

    monkeypatch.setattr(main_window_module, "ContainerCreationDialog", CreationDialog)
    monkeypatch.setattr(main_window_module, "HiddenVolumeCreationDialog", HiddenDialog)
    monkeypatch.setattr(main_window_module, "winspd_driver_available", lambda: True)
    monkeypatch.setattr(main_window_module, "mount_backend_available", lambda: True)
    monkeypatch.setattr(main_window_module.QDesktopServices, "openUrl", lambda _url: True)
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    service.create_profile("Test", password)
    manager = Manager()
    window = MainWindow(
        repository,
        service,
        FileCryptoService(),
        mount_manager=manager,  # type: ignore[arg-type]
    )
    window.session = service.unlock_with_password(password)
    window._show_dashboard()
    window.show()
    application.processEvents()

    window._create_container()
    deadline = time.monotonic() + 5
    while window._busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert manager.hidden_call is not None
    assert manager.hidden_call["outer_password"].startswith("outer")
    assert manager.hidden_call["hidden_password"].startswith("hidden")
    assert manager.hidden_call["outer_capacity"] == 96 * 1024 * 1024
    assert manager.hidden_call["hidden_capacity"] == 32 * 1024 * 1024
    assert manager.hidden_call["context_menu_labels"] == (
        "Открыть зашифрованный диск",
        "Сведения о диске",
        "Настройки доступа",
        "Изменить пароль диска",
        "",
        "Отключить зашифрованный диск",
    )
    assert manager.mounted_drive == "H:"
    manager.mounted_drive = None
    window.close()
    application.processEvents()


def test_opaque_disk_falls_back_to_compact_password_dialog(
    monkeypatch, tmp_path: Path
) -> None:
    source = tmp_path / "hidden.cpgv"
    source.touch()

    class UnlockDialog:
        request = OpaqueVolumeUnlockRequest(
            "outer correct horse battery staple",
            "hidden correct horse battery staple",
        )

        def __init__(self, selected: Path, parent: object = None) -> None:
            del parent
            assert selected == source

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

    class Manager:
        automatically_selects_backend = True
        uses_windows_system_disk = False

        def __init__(self) -> None:
            self.mounted_drive: str | None = None
            self.opaque_call: dict[str, object] | None = None

        def mount(self, *_args: object, **_options: object) -> str:
            raise InvalidBlockVolumeError("Opaque header")

        def mount_opaque(
            self,
            path: Path,
            password: str,
            **options: object,
        ) -> str:
            progress = options.pop("progress")
            assert callable(progress)
            self.opaque_call = {
                "path": path,
                "password": password,
                **options,
            }
            self.uses_windows_system_disk = True
            self.mounted_drive = "O:"
            progress(100, "Виртуальный диск подключён")
            return self.mounted_drive

        def unmount(self) -> None:
            self.mounted_drive = None

    monkeypatch.setattr(main_window_module, "OpaqueVolumeUnlockDialog", UnlockDialog)
    monkeypatch.setattr(main_window_module.QDesktopServices, "openUrl", lambda _url: True)
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    profile_password = "correct horse battery staple"
    service.create_profile("Test", profile_password)
    manager = Manager()
    window = MainWindow(
        repository,
        service,
        FileCryptoService(),
        mount_manager=manager,  # type: ignore[arg-type]
    )
    window.session = service.unlock_with_password(profile_password)
    window._show_dashboard()
    window.show()
    application.processEvents()

    window._mount_container(source)
    deadline = time.monotonic() + 5
    while window._busy and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert manager.opaque_call is not None
    assert manager.opaque_call["password"].startswith("outer")
    assert manager.opaque_call["hidden_protection_password"].startswith("hidden")
    assert manager.opaque_call["context_menu_labels"][3] == (
        "Изменить пароль диска"
    )
    assert manager.opaque_call["context_menu_labels"][4] == ""
    assert manager.mounted_drive == "O:"
    manager.mounted_drive = None
    window.close()
    application.processEvents()


def test_closing_window_keeps_mounted_disk_running(tmp_path: Path) -> None:
    class MountedDisk:
        mounted_drive = "Z:"

        def __init__(self) -> None:
            self.unmount_calls = 0

        def unmount(self) -> None:
            self.unmount_calls += 1

    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    mounted_disk = MountedDisk()
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(),
        mount_manager=mounted_disk,
    )
    window.show()
    application.processEvents()
    event = QCloseEvent()

    window.closeEvent(event)

    assert not event.isAccepted()
    assert window.isHidden()
    assert mounted_disk.unmount_calls == 0
    assert not window._tray_exit_action.isEnabled()

    mounted_disk.mounted_drive = None
    window.close()
    application.processEvents()


def test_unlocked_window_keeps_file_and_container_actions(tmp_path: Path) -> None:
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profile_service = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profile_service.create_profile("Test", password)
    window = MainWindow(repository, profile_service, FileCryptoService())
    window.session = profile_service.unlock_with_password(password)
    window._show_dashboard()

    button_names = {
        button.text() for button in window.findChildren(QPushButton)
    }
    assert "Зашифровать файл" in button_names
    assert "Расшифровать файл .cpgp" in button_names
    assert "Создать контейнер-диск" in button_names
    assert "Подключить контейнер .cpgv" in button_names
    about_buttons = [
        button
        for button in window.centralWidget().findChildren(QPushButton)
        if button.toolTip() == "О программе"
    ]
    assert len(about_buttons) == 1
    assert about_buttons[0].text() == ""
    assert not about_buttons[0].icon().isNull()
    settings_buttons = [
        button
        for button in window.centralWidget().findChildren(QPushButton)
        if button.toolTip() == "Настройки доступа"
    ]
    assert len(settings_buttons) == 1
    assert settings_buttons[0].text() == ""
    assert not settings_buttons[0].icon().isNull()
    assert window.findChildren(QScrollArea) == []
    assert all(
        not button.icon().isNull()
        for button in window.findChildren(QPushButton)
        if button.text() in {
            "Зашифровать файл",
            "Расшифровать файл .cpgp",
            "Создать контейнер-диск",
            "Подключить контейнер .cpgv",
        }
    )

    window.close()
    application.processEvents()
