import os
from unittest.mock import patch
from pathlib import Path

from cleverpgp.__main__ import main
from cleverpgp.app import default_mount_manager, main as application_main


def test_shell_mode_is_dispatched_to_shell_entrypoint() -> None:
    with patch("cleverpgp.shell.main", return_value=7) as shell_main:
        result = main(["--shell", "encrypt", "report.txt"])

    assert result == 7
    shell_main.assert_called_once_with(["encrypt", "report.txt"])


def test_windows_resize_helper_is_dispatched_without_gui() -> None:
    with patch(
        "cleverpgp.core.windows_resize.run_windows_resize_helper",
        return_value=0,
    ) as helper:
        result = main(
            [
                "--windows-resize-helper",
                "request.json",
                "response.json",
            ]
        )

    assert result == 0
    helper.assert_called_once_with(Path("request.json"), Path("response.json"))


def test_windows_format_helper_is_dispatched_without_gui() -> None:
    with patch(
        "cleverpgp.core.windows_format.run_windows_format_helper",
        return_value=0,
    ) as helper:
        result = main(
            [
                "--windows-format-helper",
                "request.json",
                "response.json",
            ]
        )

    assert result == 0
    helper.assert_called_once_with(Path("request.json"), Path("response.json"))


def test_resize_drive_mode_forces_system_disk_window() -> None:
    with patch("cleverpgp.app.main", return_value=0) as application_main:
        result = main(["--resize-drive", "Z:\\"])

    assert result == 0
    application_main.assert_called_once_with(
        startup_action="resize",
        startup_drive="Z:\\",
    )


def test_algorithm_change_mode_forces_system_disk_window() -> None:
    with patch("cleverpgp.app.main", return_value=0) as application_main:
        result = main(["--change-disk-algorithm", "Z:\\"])

    assert result == 0
    application_main.assert_called_once_with(
        startup_action="algorithm",
        startup_drive="Z:\\",
    )


def test_regular_mode_opens_main_application() -> None:
    with patch("cleverpgp.app.main", return_value=3) as application_main:
        result = main([])

    assert result == 3
    application_main.assert_called_once_with()


def test_container_mode_opens_selected_encrypted_disk(tmp_path: Path) -> None:
    container = tmp_path / "private.cpgv"
    with patch("cleverpgp.app.main", return_value=0) as application_main:
        result = main(["--container", str(container)])

    assert result == 0
    application_main.assert_called_once_with(container.resolve())


def test_public_key_mode_opens_compact_import_window(tmp_path: Path) -> None:
    public_key = tmp_path / "alice.cpgk"
    with patch("cleverpgp.app.main", return_value=0) as application_main:
        result = main(["--import-key", str(public_key)])

    assert result == 0
    application_main.assert_called_once_with(public_key_path=public_key.resolve())


def test_public_key_extension_is_opened_directly(tmp_path: Path) -> None:
    public_key = tmp_path / "alice.cpgk"
    with patch("cleverpgp.app.main", return_value=0) as application_main:
        result = main([str(public_key)])

    assert result == 0
    application_main.assert_called_once_with(public_key_path=public_key.resolve())


def test_old_container_extension_is_not_registered_for_direct_open(tmp_path: Path) -> None:
    container = tmp_path / "private.bpgv"
    with patch("cleverpgp.app.main", return_value=0) as application_main:
        result = main([str(container)])

    assert result == 0
    application_main.assert_called_once_with()


def test_unmount_mode_is_dispatched_to_drive_control() -> None:
    with patch("cleverpgp.core.mount.unmount_drive", return_value="Z:") as unmount:
        result = main(["--unmount", "Z:\\"])

    assert result == 0
    unmount.assert_called_once_with("Z:\\")


def test_disk_info_mode_opens_only_compact_information_window() -> None:
    with patch(
        "cleverpgp.ui.disk_info_dialog.run_disk_info_dialog",
        return_value=0,
    ) as disk_info:
        result = main(["--disk-info", "Z:\\"])

    assert result == 0
    disk_info.assert_called_once_with("Z:\\")


def test_disk_password_mode_opens_only_compact_password_window() -> None:
    with patch(
        "cleverpgp.ui.disk_password_dialog.run_disk_password_change_dialog",
        return_value=0,
    ) as password_dialog:
        result = main(["--change-disk-password", "Z:\\"])

    assert result == 0
    password_dialog.assert_called_once_with("Z:\\")


def test_settings_mode_opens_access_settings_window() -> None:
    with patch("cleverpgp.app.main", return_value=0) as application_main:
        result = main(["--settings", "Z:\\"])

    assert result == 0
    application_main.assert_called_once_with(
        startup_action="settings",
        startup_drive="Z:\\",
    )


def test_runtime_check_mode_is_dispatched(tmp_path: Path) -> None:
    marker = tmp_path / "runtime.json"
    with patch("cleverpgp.runtime_check.run", return_value=0) as runtime_check:
        result = main(["--runtime-check", str(marker)])

    assert result == 0
    runtime_check.assert_called_once_with(marker)


def test_virtual_disk_check_mode_is_dispatched(tmp_path: Path) -> None:
    marker = tmp_path / "virtual-disk.json"
    with patch(
        "cleverpgp.runtime_check.run_virtual_disk", return_value=0
    ) as runtime_check:
        result = main(["--virtual-disk-check", str(marker)])

    assert result == 0
    runtime_check.assert_called_once_with(marker)


def test_winspd_pipe_check_mode_is_dispatched(tmp_path: Path) -> None:
    marker = tmp_path / "winspd.json"
    stgtest = tmp_path / "stgtest-x64.exe"
    with patch(
        "cleverpgp.runtime_check.run_winspd_pipe", return_value=0
    ) as runtime_check:
        result = main(["--winspd-pipe-check", str(marker), str(stgtest)])

    assert result == 0
    runtime_check.assert_called_once_with(marker, stgtest)


def test_winspd_host_mode_is_dispatched(tmp_path: Path) -> None:
    request = tmp_path / ("request-" + "a" * 32 + ".json")
    with patch("cleverpgp.core.disk_host.run_disk_host", return_value=0) as host:
        result = main(["--winspd-host", str(request)])

    assert result == 0
    host.assert_called_once_with(request)


def test_application_opens_main_window_maximized() -> None:
    with (
        patch("cleverpgp.app.QApplication") as application_type,
        patch("cleverpgp.app.ProfileRepository") as repository_type,
        patch("cleverpgp.app.ProfileService"),
        patch("cleverpgp.app.FileCryptoService"),
        patch("cleverpgp.app.MainWindow") as window_type,
        patch("cleverpgp.app.line_icon"),
    ):
        application_type.return_value.exec.return_value = 0

        result = application_main()

    assert result == 0
    repository_type.return_value.initialize.assert_called_once_with()
    window_type.return_value.showMaximized.assert_called_once_with()


def test_public_key_import_does_not_open_main_window(tmp_path: Path) -> None:
    public_key = tmp_path / "alice.cpgk"
    with (
        patch("cleverpgp.app.QApplication") as application_type,
        patch("cleverpgp.app.ProfileRepository"),
        patch("cleverpgp.app.ProfileService") as profile_service_type,
        patch("cleverpgp.app.MainWindow") as window_type,
        patch("cleverpgp.app.PublicKeyImportDialog") as dialog_type,
        patch("cleverpgp.app.line_icon"),
    ):
        application_type.return_value.exec.return_value = 0

        result = application_main(public_key_path=public_key)

    assert result == 0
    dialog_type.assert_called_once()
    dialog_type.return_value.show.assert_called_once_with()
    profile_service_type.assert_not_called()
    window_type.assert_not_called()


def test_direct_container_open_uses_compact_window(tmp_path: Path) -> None:
    container = tmp_path / "private.cpgv"
    with (
        patch("cleverpgp.app.QApplication") as application_type,
        patch("cleverpgp.app.ProfileRepository"),
        patch("cleverpgp.app.ProfileService"),
        patch("cleverpgp.app.FileCryptoService"),
        patch("cleverpgp.app.MainWindow") as window_type,
        patch("cleverpgp.app.line_icon"),
    ):
        application_type.return_value.exec.return_value = 0

        result = application_main(container)

    assert result == 0
    window_type.return_value.show.assert_called_once_with()
    window_type.return_value.showMaximized.assert_not_called()


def test_explorer_settings_launch_uses_compact_window() -> None:
    with (
        patch("cleverpgp.app.QApplication") as application_type,
        patch("cleverpgp.app.ProfileRepository"),
        patch("cleverpgp.app.ProfileService"),
        patch("cleverpgp.app.FileCryptoService"),
        patch("cleverpgp.app.MainWindow") as window_type,
        patch("cleverpgp.app.line_icon"),
    ):
        application_type.return_value.exec.return_value = 0

        result = application_main(startup_action="settings")

    assert result == 0
    assert window_type.call_args.kwargs["startup_action"] == "settings"
    window_type.return_value.show.assert_called_once_with()
    window_type.return_value.showMaximized.assert_not_called()


def test_explorer_resize_launch_uses_compact_window() -> None:
    with (
        patch("cleverpgp.app.QApplication") as application_type,
        patch("cleverpgp.app.ProfileRepository"),
        patch("cleverpgp.app.ProfileService"),
        patch("cleverpgp.app.FileCryptoService"),
        patch("cleverpgp.app.MainWindow") as window_type,
        patch("cleverpgp.app.line_icon"),
    ):
        application_type.return_value.exec.return_value = 0

        result = application_main(
            startup_action="resize",
            startup_drive="Z:",
        )

    assert result == 0
    assert window_type.call_args.kwargs["startup_action"] == "resize"
    assert window_type.call_args.kwargs["startup_drive"] == "Z:"
    window_type.return_value.show.assert_called_once_with()
    window_type.return_value.showMaximized.assert_not_called()


def test_explorer_algorithm_change_uses_compact_window() -> None:
    with (
        patch("cleverpgp.app.QApplication") as application_type,
        patch("cleverpgp.app.ProfileRepository"),
        patch("cleverpgp.app.ProfileService"),
        patch("cleverpgp.app.FileCryptoService"),
        patch("cleverpgp.app.MainWindow") as window_type,
        patch("cleverpgp.app.line_icon"),
    ):
        application_type.return_value.exec.return_value = 0

        result = application_main(
            startup_action="algorithm",
            startup_drive="Z:",
        )

    assert result == 0
    assert window_type.call_args.kwargs["startup_action"] == "algorithm"
    assert window_type.call_args.kwargs["startup_drive"] == "Z:"
    window_type.return_value.show.assert_called_once_with()
    window_type.return_value.showMaximized.assert_not_called()


def test_winspd_backend_is_enabled_only_by_explicit_environment_setting() -> None:
    with (
        patch.dict(os.environ, {"CLEVERPGP_DISK_BACKEND": "winspd"}),
        patch(
            "cleverpgp.core.windows_storage.WindowsSystemDiskManager"
        ) as manager_type,
    ):
        manager = default_mount_manager()

    assert manager is manager_type.return_value


def test_default_backend_automatically_selects_container_format() -> None:
    with (
        patch.dict(os.environ, {"CLEVERPGP_DISK_BACKEND": ""}),
        patch("cleverpgp.app.AutomaticMountManager") as manager_type,
    ):
        manager = default_mount_manager()

    assert manager is manager_type.return_value


def test_resize_startup_forces_winspd_backend() -> None:
    with patch(
        "cleverpgp.core.windows_storage.WindowsSystemDiskManager"
    ) as manager_type:
        manager = default_mount_manager(force_system_disk=True)

    assert manager is manager_type.return_value
