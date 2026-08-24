from __future__ import annotations

import multiprocessing
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    multiprocessing.freeze_support()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["--winspd-host"] and len(arguments) == 2:
        from cleverpgp.core.disk_host import run_disk_host

        return run_disk_host(Path(arguments[1]))
    if arguments[:1] == ["--windows-resize-helper"] and len(arguments) == 3:
        from cleverpgp.core.windows_resize import run_windows_resize_helper

        return run_windows_resize_helper(Path(arguments[1]), Path(arguments[2]))
    if arguments[:1] == ["--windows-format-helper"] and len(arguments) == 3:
        from cleverpgp.core.windows_format import run_windows_format_helper

        return run_windows_format_helper(Path(arguments[1]), Path(arguments[2]))
    if arguments[:1] == ["--windows-create-helper"] and len(arguments) == 2:
        from cleverpgp.core.disk_creation import run_windows_create_helper

        return run_windows_create_helper(Path(arguments[1]))
    if arguments[:1] == ["--restart-after-process"] and len(arguments) == 2:
        from cleverpgp.core.process_restart import restart_after_process_exit

        try:
            process_id = int(arguments[1])
        except ValueError:
            return 1
        return restart_after_process_exit(process_id)
    if arguments[:1] == ["--purge-local-profile"] and len(arguments) in (1, 2):
        from cleverpgp.core.profile_purge import purge_local_profile

        return purge_local_profile(
            Path(arguments[1]) if len(arguments) == 2 else None
        )
    if arguments == ["--launch-uninstaller"]:
        from cleverpgp.core.uninstall_launcher import launch_uninstaller

        return launch_uninstaller()
    if arguments[:1] == ["--runtime-check"] and len(arguments) == 2:
        marker = Path(arguments[1])
        try:
            from cleverpgp.runtime_check import run

            return run(marker)
        except BaseException as error:
            marker.write_text(
                f"Clever PGP runtime check failed: {error!r}", encoding="utf-8"
            )
            return 1
    if arguments[:1] == ["--ui-worker-check"] and len(arguments) == 2:
        marker = Path(arguments[1])
        try:
            from cleverpgp.runtime_check import run_ui_worker

            return run_ui_worker(marker)
        except BaseException as error:
            marker.write_text(
                f"Clever PGP UI worker check failed: {error!r}",
                encoding="utf-8",
            )
            return 1
    if arguments[:1] == ["--block-create-check-child"] and len(arguments) == 2:
        marker = Path(arguments[1])
        try:
            from cleverpgp.runtime_check import run_block_create_child

            return run_block_create_child(marker)
        except BaseException as error:
            marker.write_text(
                f"Clever PGP isolated block creation failed: {error!r}",
                encoding="utf-8",
            )
            return 1
    if arguments[:1] == ["--virtual-disk-check"] and len(arguments) == 2:
        marker = Path(arguments[1])
        try:
            from cleverpgp.runtime_check import run_virtual_disk

            return run_virtual_disk(marker)
        except BaseException as error:
            marker.write_text(
                f"Clever PGP virtual disk check failed: {error!r}",
                encoding="utf-8",
            )
            return 1
    if arguments[:1] == ["--winspd-pipe-check"] and len(arguments) == 3:
        marker = Path(arguments[1])
        try:
            from cleverpgp.runtime_check import run_winspd_pipe

            return run_winspd_pipe(marker, Path(arguments[2]))
        except BaseException as error:
            marker.write_text(
                f"Clever PGP WinSpd check failed: {error!r}",
                encoding="utf-8",
            )
            return 1
    if arguments[:1] == ["--shell"]:
        from cleverpgp.shell import main as shell_main

        return shell_main(arguments[1:])
    if arguments[:1] == ["--unmount"] and len(arguments) == 2:
        from cleverpgp.core.mount import unmount_drive

        try:
            unmount_drive(arguments[1])
        except Exception:
            return 1
        return 0
    if arguments[:1] == ["--disk-info"] and len(arguments) == 2:
        from cleverpgp.ui.disk_info_dialog import run_disk_info_dialog

        return run_disk_info_dialog(arguments[1])
    if arguments[:1] == ["--change-disk-password"] and len(arguments) == 2:
        from cleverpgp.ui.disk_password_dialog import (
            run_disk_password_change_dialog,
        )

        return run_disk_password_change_dialog(arguments[1])

    from cleverpgp.app import main as application_main

    if arguments[:1] == ["--settings"] and len(arguments) in (1, 2):
        return application_main(
            startup_action="settings",
            startup_drive=arguments[1] if len(arguments) == 2 else None,
        )
    if arguments[:1] == ["--resize-drive"] and len(arguments) == 2:
        return application_main(
            startup_action="resize",
            startup_drive=arguments[1],
        )
    if arguments[:1] == ["--change-disk-algorithm"] and len(arguments) == 2:
        return application_main(
            startup_action="algorithm",
            startup_drive=arguments[1],
        )
    if arguments[:1] == ["--container"] and len(arguments) == 2:
        return application_main(Path(arguments[1]).expanduser().resolve())
    if arguments[:1] == ["--import-key"] and len(arguments) == 2:
        return application_main(
            public_key_path=Path(arguments[1]).expanduser().resolve()
        )
    if (
        len(arguments) == 1
        and Path(arguments[0]).suffix.lower() == ".cpgv"
    ):
        return application_main(Path(arguments[0]).expanduser().resolve())
    if (
        len(arguments) == 1
        and Path(arguments[0]).suffix.lower() == ".cpgk"
    ):
        return application_main(
            public_key_path=Path(arguments[0]).expanduser().resolve()
        )
    return application_main()


if __name__ == "__main__":
    raise SystemExit(main())
