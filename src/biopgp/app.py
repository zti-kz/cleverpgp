from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QApplication

from biopgp.config import APP_NAME, ORGANIZATION_NAME, database_path
from biopgp.core.file_crypto import FileCryptoService
from biopgp.core.mount import VaultMountManager
from biopgp.core.mount_router import AutomaticMountManager
from biopgp.core.profile_service import ProfileService
from biopgp.core.storage import ProfileRepository
from biopgp.localization import set_language
from biopgp.ui.main_window import MainWindow
from biopgp.ui.icons import line_icon
from biopgp.ui.key_dialogs import PublicKeyImportDialog

if TYPE_CHECKING:
    from biopgp.core.windows_storage import WindowsSystemDiskManager


def default_mount_manager(
    *,
    force_system_disk: bool = False,
) -> VaultMountManager | WindowsSystemDiskManager | AutomaticMountManager:
    if (
        force_system_disk
        or os.environ.get("CLEVERPGP_DISK_BACKEND", "").casefold() == "winspd"
    ):
        from biopgp.core.windows_storage import WindowsSystemDiskManager

        return WindowsSystemDiskManager()
    return AutomaticMountManager()


def main(
    container_path: Path | None = None,
    *,
    startup_action: str | None = None,
    startup_drive: str | None = None,
    public_key_path: Path | None = None,
) -> int:
    application = QApplication(sys.argv)
    application.setApplicationName(APP_NAME)
    application.setOrganizationName(ORGANIZATION_NAME)
    application.setWindowIcon(line_icon("shield", "#38bdf8"))

    repository = ProfileRepository(database_path())
    repository.initialize()
    selected_language = set_language(repository.get_setting("language"))
    repository.set_setting("language", selected_language)
    if public_key_path is not None:
        dialog = PublicKeyImportDialog(repository, public_key_path)
        dialog.show()
        screen = dialog.screen()
        if screen is not None:
            geometry = screen.availableGeometry()
            dialog.move(geometry.center() - dialog.rect().center())
        return application.exec()

    profile_service = ProfileService(repository)
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(repository),
        mount_manager=default_mount_manager(
            force_system_disk=startup_action == "resize"
        ),
        startup_container=container_path,
        startup_action=startup_action,
        startup_drive=startup_drive,
    )
    compact_operation = startup_action in {"resize", "settings"}
    if container_path is None and not compact_operation:
        # The regular application uses the whole available desktop while
        # keeping the taskbar and standard window controls accessible.
        window.showMaximized()
    else:
        # Direct container and Explorer operations show only the compact
        # authentication window. Mounting or resizing then returns to tray.
        window.show()
        screen = window.screen()
        if screen is not None:
            geometry = screen.availableGeometry()
            window.move(geometry.center() - window.rect().center())
    return application.exec()
