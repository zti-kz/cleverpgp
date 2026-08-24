from __future__ import annotations

import os
import shutil
import stat
import sys
import time
from pathlib import Path

from cleverpgp.config import APP_DATA_DIRECTORY_NAME, app_data_directory

_LEGACY_DIRECTORY_NAME = "BioPGP"


def purge_local_profile(
    explicit_path: Path | None = None,
    *,
    retries: int = 30,
) -> int:
    """Delete only per-user Clever PGP state; never touch user containers."""

    try:
        targets = _validated_profile_targets(explicit_path)
    except (OSError, ValueError):
        return 1
    for target in targets:
        for attempt in range(max(1, retries)):
            try:
                shutil.rmtree(target, onexc=_clear_read_only)
            except FileNotFoundError:
                break
            except OSError:
                if attempt + 1 >= max(1, retries):
                    return 1
                time.sleep(0.1)
            else:
                break
        if target.exists():
            return 1
    return 0


def _validated_profile_targets(
    explicit_path: Path | None = None,
) -> tuple[Path, ...]:
    if explicit_path is not None:
        target = Path(explicit_path).expanduser().resolve()
        if target.name != APP_DATA_DIRECTORY_NAME:
            raise ValueError("unsafe profile directory")
        base = target.parent
        if base.name.casefold() != "local" or base.parent.name.casefold() != "appdata":
            raise ValueError("unsafe profile directory")
        return (target, (base / _LEGACY_DIRECTORY_NAME).resolve())
    override = os.environ.get("CLEVERPGP_DATA_DIR")
    if override:
        target = app_data_directory().resolve()
        if target.parent == target:
            raise ValueError("unsafe profile directory")
        return (target,)
    if sys.platform != "win32":
        return (app_data_directory().resolve(),)
    base_value = os.environ.get("LOCALAPPDATA")
    base = (
        Path(base_value).expanduser().resolve()
        if base_value
        else (Path.home() / "AppData" / "Local").resolve()
    )
    targets = (
        (base / APP_DATA_DIRECTORY_NAME).resolve(),
        (base / _LEGACY_DIRECTORY_NAME).resolve(),
    )
    if any(
        target.parent != base
        or target.name not in {APP_DATA_DIRECTORY_NAME, _LEGACY_DIRECTORY_NAME}
        for target in targets
    ):
        raise ValueError("unsafe profile directory")
    return targets


def _clear_read_only(function: object, path: str, error: BaseException) -> None:
    del function, error
    os.chmod(path, stat.S_IWRITE)
    if Path(path).is_dir():
        os.rmdir(path)
    else:
        os.unlink(path)
