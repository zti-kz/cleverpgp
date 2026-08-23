from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QApplication

from biopgp.config import APP_NAME, ORGANIZATION_NAME, database_path
from biopgp.core.file_crypto import FileCryptoService
from biopgp.core.mount import VaultMountManager
from biopgp.core.profile_service import ProfileService
from biopgp.core.storage import ProfileRepository
from biopgp.localization import set_language
from biopgp.ui.main_window import MainWindow
from biopgp.ui.icons import line_icon

if TYPE_CHECKING:
    from biopgp.core.windows_storage import WindowsSystemDiskManager


def default_mount_manager(
    *,
    force_system_disk: bool = False,
) -> VaultMountManager | WindowsSystemDiskManager:
    if (
        force_system_disk
        or os.environ.get("CLEVERPGP_DISK_BACKEND", "").casefold() == "winspd"
    ):
        from biopgp.core.windows_storage import WindowsSystemDiskManager

        return WindowsSystemDiskManager()
    return VaultMountManager()


def main(
    container_path: Path | None = None,
    *,
    startup_action: str | None = None,
    startup_drive: str | None = None,
) -> int:
    application = QApplication(sys.argv)
    application.setApplicationName(APP_NAME)
    application.setOrganizationName(ORGANIZATION_NAME)
    application.setWindowIcon(line_icon("shield", "#38bdf8"))

    repository = ProfileRepository(database_path())
    repository.initialize()
    selected_language = set_language(repository.get_setting("language"))
    repository.set_setting("language", selected_language)
    profile_service = ProfileService(repository)
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(),
        mount_manager=default_mount_manager(
            force_system_disk=startup_action == "resize"
        ),
        startup_container=container_path,
        startup_action=startup_action,
        startup_drive=startup_drive,
    )
    if container_path is None:
        # The regular application uses the whole available desktop while
        # keeping the taskbar and standard window controls accessible.
        window.showMaximized()
    else:
        # Opening a .cpgv directly shows only the compact unlock card. After a
        # successful mount the window is hidden and the process stays in tray.
        window.show()
        screen = window.screen()
        if screen is not None:
            geometry = screen.availableGeometry()
            window.move(geometry.center() - window.rect().center())
    return application.exec()
