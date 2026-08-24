from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QApplication

from cleverpgp.config import APP_NAME, ORGANIZATION_NAME, database_path
from cleverpgp.core.file_crypto import FileCryptoService
from cleverpgp.core.mount import VaultMountManager
from cleverpgp.core.mount_router import AutomaticMountManager
from cleverpgp.core.profile_service import ProfileService
from cleverpgp.core.storage import ProfileRepository
from cleverpgp.localization import set_language
from cleverpgp.ui.main_window import MainWindow
from cleverpgp.ui.icons import line_icon
from cleverpgp.ui.key_dialogs import PublicKeyImportDialog
from cleverpgp.ui.screen_bounds import fit_window_to_screen, install_screen_bounds

if TYPE_CHECKING:
    from cleverpgp.core.windows_storage import WindowsSystemDiskManager


def default_mount_manager(
    *,
    force_system_disk: bool = False,
) -> VaultMountManager | WindowsSystemDiskManager | AutomaticMountManager:
    if (
        force_system_disk
        or os.environ.get("CLEVERPGP_DISK_BACKEND", "").casefold() == "winspd"
    ):
        from cleverpgp.core.windows_storage import WindowsSystemDiskManager

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
    install_screen_bounds(application)

    repository = ProfileRepository(database_path())
    repository.initialize()
    selected_language = set_language(repository.get_setting("language"))
    repository.set_setting("language", selected_language)
    if public_key_path is not None:
        dialog = PublicKeyImportDialog(repository, public_key_path)
        dialog.show()
        fit_window_to_screen(dialog)
        return application.exec()

    profile_service = ProfileService(repository)
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(repository),
        mount_manager=default_mount_manager(
            force_system_disk=startup_action in {"resize", "algorithm"}
        ),
        startup_container=container_path,
        startup_action=startup_action,
        startup_drive=startup_drive,
    )
    compact_operation = startup_action in {"resize", "settings", "algorithm"}
    if container_path is None and not compact_operation:
        # The regular application uses the whole available desktop while
        # keeping the taskbar and standard window controls accessible.
        window.showMaximized()
    else:
        # Direct container and Explorer operations show only the compact
        # authentication window. Mounting or resizing then returns to tray.
        window.show()
        fit_window_to_screen(window)
    return application.exec()
