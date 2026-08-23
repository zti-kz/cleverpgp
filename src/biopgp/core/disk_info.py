from __future__ import annotations

import platform
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from biopgp.core.disk_control import DiskControlStore
from biopgp.core.errors import MountUnavailableError
from biopgp.core.mount import CONTROL_PATH, normalized_drive_name
from biopgp.core.windows_storage import (
    inspect_windows_volume,
    validate_cleverpgp_volume,
)


@dataclass(frozen=True, slots=True)
class MountedDiskInfo:
    drive: str
    backend: str
    file_system: str
    capacity: int
    free_space: int

    @property
    def used_space(self) -> int:
        return max(0, self.capacity - self.free_space)


class _DiskUsage(Protocol):
    total: int
    used: int
    free: int


def inspect_mounted_cleverpgp_disk(
    drive: str,
    *,
    control_store: DiskControlStore | None = None,
) -> MountedDiskInfo:
    """Return read-only information only for a live Clever PGP disk."""

    if platform.system() != "Windows":
        raise MountUnavailableError(
            "Сведения о подключённом диске пока доступны только в Windows."
        )
    normalized = normalized_drive_name(drive)
    root = Path(f"{normalized}\\")
    store = control_store or DiskControlStore()
    record = store.find_by_drive(normalized)
    if record is not None:
        store.send(record, "ping", timeout=1.0)
        volume = inspect_windows_volume(normalized)
        validate_cleverpgp_volume(
            volume,
            expected_disk_size=volume.disk_size,
        )
        usage = _disk_usage(root)
        return MountedDiskInfo(
            drive=normalized,
            backend="Виртуальный диск Windows",
            file_system=volume.file_system,
            capacity=int(usage.total),
            free_space=min(int(usage.free), int(usage.total)),
        )

    control = root / CONTROL_PATH.lstrip("/")
    try:
        is_cleverpgp = control.exists()
    except OSError:
        is_cleverpgp = False
    if not is_cleverpgp:
        raise MountUnavailableError(
            f"Диск {normalized} не является подключённым диском Clever PGP."
        )
    usage = _disk_usage(root)
    return MountedDiskInfo(
        drive=normalized,
        backend="Виртуальная файловая система",
        file_system="FUSE",
        capacity=int(usage.total),
        free_space=min(int(usage.free), int(usage.total)),
    )


def _disk_usage(root: Path) -> _DiskUsage:
    try:
        usage = shutil.disk_usage(root)
    except OSError as error:
        raise MountUnavailableError(
            "Windows не предоставила сведения о ёмкости диска."
        ) from error
    if usage.total <= 0 or usage.free < 0:
        raise MountUnavailableError("Windows вернула некорректный размер диска.")
    return usage
