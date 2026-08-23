from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from biopgp.core.disk_control import DiskControlRecord
from biopgp.core.errors import MountUnavailableError
from biopgp.core.windows_resize import (
    WindowsResizeExchange,
    run_elevated_ntfs_extension,
    run_windows_resize_helper,
)
from biopgp.core.windows_storage import (
    WindowsVolumeInfo,
    WindowsVolumeResizeResult,
)


def volume_info(*, unique_id: str = "unique-7") -> WindowsVolumeInfo:
    return WindowsVolumeInfo(
        disk_number=7,
        partition_number=1,
        drive="Z:",
        friendly_name="CleverPGP",
        serial_number="serial-7",
        unique_id=unique_id,
        bus_type="File Backed Virtual",
        disk_size=256 * 1024 * 1024,
        partition_size=127 * 1024 * 1024,
        partition_offset=1024 * 1024,
        partition_style="MBR",
        file_system="NTFS",
        data_partition_count=1,
        is_boot=False,
        is_system=False,
    )


def control_record(directory: Path) -> DiskControlRecord:
    volume_id = b"v" * 16
    return DiskControlRecord(
        volume_id=volume_id,
        drive="Z:",
        port=23456,
        process_id=4321,
        protected_token=b"protected",
        path=directory / f"mount-{volume_id.hex()}.json",
    )


class FakeControlStore:
    def __init__(self, directory: Path, record: DiskControlRecord) -> None:
        self.directory = directory.resolve()
        self.record = record
        self.commands: list[tuple[DiskControlRecord, str, float]] = []

    def records(self) -> tuple[DiskControlRecord, ...]:
        return (self.record,)

    def send(
        self,
        record: DiskControlRecord,
        command: str,
        *,
        timeout: float = 3.0,
    ) -> None:
        self.commands.append((record, command, timeout))


def test_elevated_helper_requires_live_control_record_and_exact_disk(
    tmp_path: Path,
) -> None:
    mounted_directory = tmp_path / "mounted-disks"
    resize_directory = tmp_path / "resize-requests"
    mounted_directory.mkdir()
    exchange = WindowsResizeExchange(resize_directory)
    record = control_record(mounted_directory)
    store = FakeControlStore(mounted_directory, record)
    info = volume_info()
    paths = exchange.create(record, info)
    result = WindowsVolumeResizeResult(
        disk_size=info.disk_size,
        partition_size=info.disk_size - info.partition_offset,
        file_system="NTFS",
    )

    with (
        patch(
            "biopgp.core.windows_resize.inspect_windows_volume",
            return_value=info,
        ) as inspect,
        patch(
            "biopgp.core.windows_resize.extend_cleverpgp_ntfs_partition",
            return_value=result,
        ) as extend,
    ):
        exit_code = run_windows_resize_helper(
            paths.request_path,
            paths.response_path,
            exchange=exchange,
            control_store=store,  # type: ignore[arg-type]
        )

    assert exit_code == 0
    assert exchange.consume(paths) == result
    assert store.commands == [(record, "ping", 1.0)]
    inspect.assert_called_once_with("Z:")
    extend.assert_called_once_with(
        info,
        expected_disk_size=info.disk_size,
        expected_partition_size=info.partition_size,
    )
    exchange.cleanup(paths)


def test_elevated_helper_refuses_identity_change_before_partition_command(
    tmp_path: Path,
) -> None:
    mounted_directory = tmp_path / "mounted-disks"
    resize_directory = tmp_path / "resize-requests"
    mounted_directory.mkdir()
    exchange = WindowsResizeExchange(resize_directory)
    record = control_record(mounted_directory)
    store = FakeControlStore(mounted_directory, record)
    paths = exchange.create(record, volume_info())

    with (
        patch(
            "biopgp.core.windows_resize.inspect_windows_volume",
            return_value=volume_info(unique_id="changed"),
        ),
        patch(
            "biopgp.core.windows_resize.extend_cleverpgp_ntfs_partition",
        ) as extend,
    ):
        exit_code = run_windows_resize_helper(
            paths.request_path,
            paths.response_path,
            exchange=exchange,
            control_store=store,  # type: ignore[arg-type]
        )

    assert exit_code == 1
    with pytest.raises(MountUnavailableError, match="Параметры диска изменились"):
        exchange.consume(paths)
    extend.assert_not_called()
    exchange.cleanup(paths)


def test_parent_uses_one_time_files_and_passes_no_key_to_elevated_command(
    tmp_path: Path,
) -> None:
    mounted_directory = tmp_path / "mounted-disks"
    mounted_directory.mkdir()
    exchange = WindowsResizeExchange(tmp_path / "resize-requests")
    record = control_record(mounted_directory)
    info = volume_info()
    expected = WindowsVolumeResizeResult(
        disk_size=info.disk_size,
        partition_size=info.disk_size - info.partition_offset,
        file_system="NTFS",
    )
    captured: list[str] = []

    def launch(command: list[str], *, timeout: float) -> int:
        assert timeout == 12.0
        captured.extend(command)
        request_path = Path(command[-2])
        response_path = Path(command[-1])
        request = exchange.read(request_path)
        exchange.write_success(response_path, request.request_id, expected)
        return 0

    with patch("biopgp.core.windows_resize._launch_elevated", side_effect=launch):
        result = run_elevated_ntfs_extension(
            record,
            info,
            exchange=exchange,
            command_prefix=("CleverPGP.exe",),
            timeout=12.0,
        )

    assert result == expected
    assert captured[1] == "--windows-resize-helper"
    assert all("master" not in argument.casefold() for argument in captured)
    assert list(exchange.directory.glob("*.json")) == []
