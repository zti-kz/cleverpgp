from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QCoreApplication
from PySide6.QtWidgets import QApplication

from cleverpgp.config import APP_NAME, ORGANIZATION_NAME, database_path
from cleverpgp.core.file_crypto import FileCryptoService
from cleverpgp.core.mount import VaultMountManager
from cleverpgp.core.mount_router import AutomaticMountManager
from cleverpgp.core.profile_service import ProfileService
from cleverpgp.core.storage import ProfileRepository
from cleverpgp.localization import set_language
from cleverpgp.single_instance import SingleApplicationInstance
from cleverpgp.ui.main_window import MainWindow
from cleverpgp.ui.icons import line_icon
from cleverpgp.ui.key_dialogs import PublicKeyImportDialog
from cleverpgp.ui.key_manager_dialog import KeyManagerDialog
from cleverpgp.ui.screen_bounds import fit_window_to_screen, install_screen_bounds

if TYPE_CHECKING:
    from cleverpgp.core.windows_storage import WindowsSystemDiskManager


def default_mount_manager(
    *,
    force_system_disk: bool = False,
    recover_existing: bool = True,
) -> VaultMountManager | WindowsSystemDiskManager | AutomaticMountManager:
    if (
        force_system_disk
        or os.environ.get("CLEVERPGP_DISK_BACKEND", "").casefold() == "winspd"
    ):
        from cleverpgp.core.windows_storage import WindowsSystemDiskManager

        return WindowsSystemDiskManager(recover_existing=recover_existing)
    return AutomaticMountManager(recover_existing=recover_existing)


def main(
    container_path: Path | None = None,
    *,
    startup_action: str | None = None,
    startup_drive: str | None = None,
    public_key_path: Path | None = None,
    private_key_path: Path | None = None,
) -> int:
    application = QApplication(sys.argv)
    application.setApplicationName(APP_NAME)
    application.setOrganizationName(ORGANIZATION_NAME)
    application.setWindowIcon(line_icon("shield", "#38bdf8"))
    install_screen_bounds(application)

    regular_shell = (
        container_path is None
        and startup_action is None
        and public_key_path is None
        and private_key_path is None
    )
    instance: SingleApplicationInstance | None = None
    # Unit tests replace QApplication with a mock. The identity check keeps
    # real local IPC limited to an actual Qt application object.
    if regular_shell and QCoreApplication.instance() is application:
        instance = SingleApplicationInstance(application)
        if not instance.acquire():
            return 0
        setattr(application, "_cleverpgp_single_instance", instance)
        application.aboutToQuit.connect(instance.close)

    repository = ProfileRepository(database_path())
    repository.initialize()
    # The installer normally writes this setting before the first launch.  A
    # defensive Russian default keeps a direct/portable launch predictable and
    # avoids silently following the Windows locale.
    selected_language = set_language(repository.get_setting("language") or "ru")
    repository.set_setting("language", selected_language)
    if public_key_path is not None:
        dialog = PublicKeyImportDialog(repository, public_key_path)
        dialog.show()
        fit_window_to_screen(dialog)
        return application.exec()
    if private_key_path is not None:
        dialog = KeyManagerDialog(
            repository,
            import_private_path=private_key_path,
        )
        dialog.show()
        fit_window_to_screen(dialog)
        return application.exec()

    profile_service = ProfileService(repository)
    window = MainWindow(
        repository,
        profile_service,
        FileCryptoService(repository),
        mount_manager=default_mount_manager(
            force_system_disk=startup_action in {"resize", "algorithm"},
            recover_existing=container_path is None,
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
    elif container_path is not None:
        # A double-click opens only the disk authentication window. The hidden
        # controller keeps serving the disk without flashing a second shell.
        window.hide()
    else:
        # Direct container and Explorer operations show only the compact
        # authentication window. Mounting or resizing then returns to tray.
        window.show()
        fit_window_to_screen(window)
    if instance is not None:
        instance.activation_requested.connect(window._show_from_tray)
        instance.shutdown_requested.connect(window._shutdown_for_uninstall)
    return application.exec()
