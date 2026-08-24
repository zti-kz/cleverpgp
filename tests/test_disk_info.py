from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from cleverpgp.core.disk_control import DiskControlRecord
from cleverpgp.core.disk_crypto import XCHACHA20_POLY1305
from cleverpgp.core.disk_info import inspect_mounted_cleverpgp_disk
from cleverpgp.core.errors import MountUnavailableError
from cleverpgp.core.windows_storage import WindowsVolumeInfo


class FakeControlStore:
    def __init__(self, record: DiskControlRecord | None) -> None:
        self.record = record
        self.sent: list[tuple[DiskControlRecord, str, float]] = []

    def find_by_drive(self, drive: str) -> DiskControlRecord | None:
        return self.record if drive == "Z:" else None

    def send(
        self,
        record: DiskControlRecord,
        command: str,
        *,
        timeout: float = 3.0,
    ) -> None:
        self.sent.append((record, command, timeout))

    def algorithm(self, record: DiskControlRecord) -> str | None:
        return XCHACHA20_POLY1305 if record is self.record else None


def system_record(tmp_path: Path) -> DiskControlRecord:
    return DiskControlRecord(
        volume_id=b"v" * 16,
        drive="Z:",
        port=23456,
        process_id=4321,
        protected_token=b"protected",
        path=tmp_path / "mount.json",
    )


def system_volume() -> WindowsVolumeInfo:
    return WindowsVolumeInfo(
        disk_number=7,
        partition_number=1,
        drive="Z:",
        friendly_name="CleverPGP",
        serial_number="serial-7",
        unique_id="unique-7",
        bus_type="File Backed Virtual",
        disk_size=256 * 1024 * 1024,
        partition_size=255 * 1024 * 1024,
        partition_offset=1024 * 1024,
        partition_style="MBR",
        file_system="NTFS",
        data_partition_count=1,
        is_boot=False,
        is_system=False,
    )


def test_system_disk_information_requires_live_authenticated_record(
    tmp_path: Path,
) -> None:
    record = system_record(tmp_path)
    store = FakeControlStore(record)
    usage = SimpleNamespace(total=250 * 1024 * 1024, free=100 * 1024 * 1024)
    with (
        patch("cleverpgp.core.disk_info.platform.system", return_value="Windows"),
        patch(
            "cleverpgp.core.disk_info.inspect_windows_volume",
            return_value=system_volume(),
        ) as inspect,
        patch("cleverpgp.core.disk_info.shutil.disk_usage", return_value=usage),
    ):
        info = inspect_mounted_cleverpgp_disk(
            "z:\\",
            control_store=store,  # type: ignore[arg-type]
        )

    assert info.drive == "Z:"
    assert info.backend == "Виртуальный диск Windows"
    assert info.file_system == "NTFS"
    assert info.capacity == usage.total
    assert info.free_space == usage.free
    assert info.used_space == usage.total - usage.free
    assert info.algorithm == XCHACHA20_POLY1305
    assert store.sent == [(record, "ping", 1.0)]
    inspect.assert_called_once_with("Z:")


def test_winfsp_disk_information_checks_marker_without_opening_control_file() -> None:
    store = FakeControlStore(None)
    usage = SimpleNamespace(total=64 * 1024 * 1024, free=20 * 1024 * 1024)
    with (
        patch("cleverpgp.core.disk_info.platform.system", return_value="Windows"),
        patch("cleverpgp.core.disk_info.Path.exists", return_value=True),
        patch("cleverpgp.core.disk_info.Path.open") as open_file,
        patch("cleverpgp.core.disk_info.shutil.disk_usage", return_value=usage),
    ):
        info = inspect_mounted_cleverpgp_disk(
            "Z:",
            control_store=store,  # type: ignore[arg-type]
        )

    assert info.backend == "Виртуальная файловая система"
    assert info.file_system == "FUSE"
    open_file.assert_not_called()


def test_disk_information_rejects_an_unrelated_drive() -> None:
    store = FakeControlStore(None)
    with (
        patch("cleverpgp.core.disk_info.platform.system", return_value="Windows"),
        patch("cleverpgp.core.disk_info.Path.exists", return_value=False),
        patch("cleverpgp.core.disk_info.shutil.disk_usage") as disk_usage,
        pytest.raises(MountUnavailableError, match="не является"),
    ):
        inspect_mounted_cleverpgp_disk(
            "C:",
            control_store=store,  # type: ignore[arg-type]
        )

    disk_usage.assert_not_called()
