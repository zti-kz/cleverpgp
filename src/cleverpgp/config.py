from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

APP_NAME = "Clever PGP"
ORGANIZATION_NAME = "Almas Oskenbay"
APP_DATA_DIRECTORY_NAME = "CleverPGP"
DATABASE_FILENAME = "cleverpgp.sqlite3"
_LEGACY_APP_DATA_DIRECTORY_NAME = "BioPGP"
_LEGACY_DATABASE_FILENAME = "biopgp.sqlite3"


def app_data_directory() -> Path:
    """Return the per-user application data directory without creating it."""
    override = os.environ.get("CLEVERPGP_DATA_DIR")
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
    migrate_legacy_app_data()
    return app_data_directory() / DATABASE_FILENAME


def migrate_legacy_app_data() -> None:
    """Move an earlier local profile to the CleverPGP directory once.

    Existing data in the destination always wins. Conflicting legacy files are
    deliberately retained instead of being overwritten or deleted.
    """

    if sys.platform != "win32" or os.environ.get("CLEVERPGP_DATA_DIR"):
        return
    base_value = os.environ.get("LOCALAPPDATA")
    base = (
        Path(base_value)
        if base_value
        else Path.home() / "AppData" / "Local"
    )
    legacy = base / _LEGACY_APP_DATA_DIRECTORY_NAME
    destination = base / APP_DATA_DIRECTORY_NAME
    if not legacy.is_dir() or legacy == destination:
        return
    if not destination.exists():
        try:
            legacy.replace(destination)
        except OSError:
            shutil.copytree(legacy, destination, dirs_exist_ok=False)
            shutil.rmtree(legacy)
    else:
        for source in tuple(legacy.iterdir()):
            target = destination / source.name
            if target.exists():
                continue
            try:
                source.replace(target)
            except OSError:
                if source.is_dir():
                    shutil.copytree(source, target)
                    shutil.rmtree(source)
                else:
                    shutil.copy2(source, target)
                    source.unlink()
        try:
            legacy.rmdir()
        except OSError:
            pass

    old_database = destination / _LEGACY_DATABASE_FILENAME
    new_database = destination / DATABASE_FILENAME
    if old_database.is_file() and not new_database.exists():
        old_database.replace(new_database)


def bundled_models_directory() -> Path:
    override = os.environ.get("CLEVERPGP_MODELS_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "models"
    return Path(__file__).resolve().parents[2] / "models"
