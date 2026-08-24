from __future__ import annotations

import ctypes
import subprocess
import sys
from pathlib import Path

from cleverpgp.config import app_data_directory


def launch_uninstaller() -> int:
    """Start the installed uninstaller with the exact current-user profile path."""

    application_directory = Path(sys.executable).expanduser().resolve().parent
    candidates = sorted(
        application_directory.glob("unins*.exe"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return 1
    uninstaller = candidates[0]
    parameters = f'/PROFILEPATH="{app_data_directory().resolve()}"'
    if sys.platform == "win32":
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            str(uninstaller),
            parameters,
            str(application_directory),
            1,
        )
        return 0 if int(result) > 32 else 1
    try:
        subprocess.Popen([str(uninstaller), parameters])
    except OSError:
        return 1
    return 0
