from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "Clever PGP"
ORGANIZATION_NAME = "Almas Oskenbay"
# Keep the existing directory during upgrades. The uninstaller separately asks
# whether this encrypted local profile should be retained or removed.
APP_DATA_DIRECTORY_NAME = "BioPGP"
DATABASE_FILENAME = "biopgp.sqlite3"


def app_data_directory() -> Path:
    """Return the per-user application data directory without creating it."""
    override = os.environ.get("BIOPGP_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()

    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / APP_DATA_DIRECTORY_NAME
        return Path.home() / "AppData" / "Local" / APP_DATA_DIRECTORY_NAME

    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home).expanduser() / APP_NAME.lower()
    return Path.home() / ".local" / "share" / APP_NAME.lower()


def database_path() -> Path:
    return app_data_directory() / DATABASE_FILENAME


def bundled_models_directory() -> Path:
    override = os.environ.get("BIOPGP_MODELS_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "models"
    return Path(__file__).resolve().parents[2] / "models"
