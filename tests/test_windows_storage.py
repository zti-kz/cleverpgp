from __future__ import annotations

from unittest.mock import patch

import pytest

from biopgp.core.errors import MountUnavailableError
from biopgp.core.windows_storage import (
    WindowsDiskInfo,
    format_ephemeral_cleverpgp_disk,
    select_new_cleverpgp_disk,
)


def disk(
    number: int,
    name: str,
    size: int,
    partition_style: str = "MBR",
) -> WindowsDiskInfo:
    return WindowsDiskInfo(
        number=number,
        friendly_name=name,
        serial_number=f"serial-{number}",
        unique_id=f"unique-{number}",
        size=size,
        partition_style=partition_style,
    )


def test_selects_only_new_disk_with_exact_identity_and_size() -> None:
    expected_size = 128 * 1024 * 1024
    existing = [disk(0, "Physical SSD", 1024**4)]
    candidate = disk(7, "CleverPGP", expected_size)

    assert select_new_cleverpgp_disk(
        existing,
        [*existing, candidate],
        expected_size=expected_size,
    ) == candidate


@pytest.mark.parametrize(
    "new_disks",
    [
        [],
        [disk(7, "Physical disk", 128 * 1024 * 1024)],
        [disk(7, "CleverPGP", 64 * 1024 * 1024)],
        [
            disk(7, "CleverPGP", 128 * 1024 * 1024),
            disk(8, "WinSpd", 128 * 1024 * 1024),
        ],
    ],
)
def test_refuses_missing_mismatched_or_ambiguous_targets(
    new_disks: list[WindowsDiskInfo],
) -> None:
    existing = [disk(0, "Physical SSD", 1024**4)]

    with pytest.raises(MountUnavailableError):
        select_new_cleverpgp_disk(
            existing,
            [*existing, *new_disks],
            expected_size=128 * 1024 * 1024,
        )


def test_refuses_unexpected_partition_table() -> None:
    expected_size = 128 * 1024 * 1024
    candidate = disk(7, "CleverPGP", expected_size, "GPT")

    with pytest.raises(MountUnavailableError):
        select_new_cleverpgp_disk([], [candidate], expected_size=expected_size)


def test_format_command_revalidates_target_before_destructive_operation() -> None:
    expected_size = 128 * 1024 * 1024
    candidate = disk(7, "CleverPGP", expected_size)
    with patch(
        "biopgp.core.windows_storage._run_powershell",
        return_value='{"DriveLetter":"Z"}',
    ) as run_powershell:
        drive = format_ephemeral_cleverpgp_disk(
            candidate,
            expected_size=expected_size,
            file_system="NTFS",
        )

    script = run_powershell.call_args.args[0]
    assert drive == "Z:"
    assert "Get-Disk -Number 7" in script
    assert f"$disk.Size -ne [UInt64]{expected_size}" in script
    assert "$disk.FriendlyName -notmatch 'CleverPGP|WinSpd'" in script
    assert "$disk.PartitionStyle -ne 'MBR'" in script
    assert "$partition.Offset -ne [UInt64]1048576" in script
    assert script.index("Get-Disk -Number 7") < script.index("Format-Volume")
    assert script.index("$partition.Offset") < script.index("Format-Volume")
