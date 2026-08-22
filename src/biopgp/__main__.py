from __future__ import annotations

import multiprocessing
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    multiprocessing.freeze_support()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["--runtime-check"] and len(arguments) == 2:
        marker = Path(arguments[1])
        try:
            from biopgp.runtime_check import run

            return run(marker)
        except BaseException as error:
            marker.write_text(
                f"Clever PGP runtime check failed: {error!r}", encoding="utf-8"
            )
            return 1
    if arguments[:1] == ["--virtual-disk-check"] and len(arguments) == 2:
        marker = Path(arguments[1])
        try:
            from biopgp.runtime_check import run_virtual_disk

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
            from biopgp.runtime_check import run_winspd_pipe

            return run_winspd_pipe(marker, Path(arguments[2]))
        except BaseException as error:
            marker.write_text(
                f"Clever PGP WinSpd check failed: {error!r}",
                encoding="utf-8",
            )
            return 1
    if arguments[:1] == ["--shell"]:
        from biopgp.shell import main as shell_main

        return shell_main(arguments[1:])
    if arguments[:1] == ["--unmount"] and len(arguments) == 2:
        from biopgp.core.mount import unmount_drive

        try:
            unmount_drive(arguments[1])
        except Exception:
            return 1
        return 0

    from biopgp.app import main as application_main

    if arguments[:1] == ["--container"] and len(arguments) == 2:
        return application_main(Path(arguments[1]).expanduser().resolve())
    if (
        len(arguments) == 1
        and Path(arguments[0]).suffix.lower() == ".cpgv"
    ):
        return application_main(Path(arguments[0]).expanduser().resolve())
    return application_main()


if __name__ == "__main__":
    raise SystemExit(main())
