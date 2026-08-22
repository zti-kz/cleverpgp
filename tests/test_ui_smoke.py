import os
import time
from collections.abc import Callable
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nacl import pwhash  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import QCloseEvent  # noqa: E402
from PySide6.QtWidgets import QApplication, QPushButton, QScrollArea  # noqa: E402

from biopgp.core.file_crypto import FileCryptoService  # noqa: E402
from biopgp.core.profile_service import KdfParameters, ProfileService  # noqa: E402
from biopgp.core.storage import ProfileRepository  # noqa: E402
from biopgp.ui.main_window import MainWindow  # noqa: E402


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
