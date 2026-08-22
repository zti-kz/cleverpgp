from __future__ import annotations

from unittest.mock import patch
from pathlib import Path

import pytest
from nacl import secret, utils

from biopgp.core.block_volume import EncryptedBlockVolume
from biopgp.core.disk_control import DiskControlEndpoint
from biopgp.core.errors import MountUnavailableError
from biopgp.core.winspd import WINDOWS_BLOCK_STORAGE_FORMAT
from biopgp.core.windows_storage import (
    WindowsDiskInfo,
    WindowsSystemDiskManager,
    disk_drive_letters,
    format_ephemeral_cleverpgp_disk,
    select_new_cleverpgp_disk,
    winspd_driver_available,
)


class FakeProcessManager:
    def __init__(self) -> None:
        self.running = False
        self.started: tuple[Path, bytes] | None = None
        self.stopped = False

    def start(
        self,
        container_path: Path,
        master_key: bytes,
        **_kwargs: object,
    ) -> None:
        self.started = (container_path, master_key)
        self.running = True

    def stop(self) -> None:
        self.running = False
        self.stopped = True


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


def test_unicode_volume_label_is_encoded_not_interpolated() -> None:
    expected_size = 128 * 1024 * 1024
    candidate = disk(7, "CleverPGP", expected_size)
    with patch(
        "biopgp.core.windows_storage._run_powershell",
        return_value='{"DriveLetter":"Z"}',
    ) as run_powershell:
        format_ephemeral_cleverpgp_disk(
            candidate,
            expected_size=expected_size,
            file_system="NTFS",
        )

    script = run_powershell.call_args.args[0]
    assert "[Convert]::FromBase64String" in script
    assert "-NewFileSystemLabel $label" in script


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('"Z"', ["Z:"]),
        ('["Y","Z"]', ["Y:", "Z:"]),
        ("[]", []),
    ],
)
def test_disk_drive_letters_normalizes_powershell_json(
    raw: str,
    expected: list[str],
) -> None:
    with patch("biopgp.core.windows_storage._run_powershell", return_value=raw):
        assert disk_drive_letters(7) == expected


def test_winspd_driver_is_unavailable_outside_windows() -> None:
    with patch("biopgp.core.windows_storage.sys.platform", "linux"):
        assert not winspd_driver_available()


def test_system_manager_mounts_formatted_volume_and_waits_for_removal(
    tmp_path: Path,
) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    container_path = tmp_path / "system.cpgv"
    volume = EncryptedBlockVolume.create(
        container_path,
        key,
        logical_capacity=1024 * 1024,
        storage_format=WINDOWS_BLOCK_STORAGE_FORMAT,
    )
    volume.close()
    process_manager = FakeProcessManager()
    system_disk = disk(7, "CleverPGP", 1024 * 1024)

    with (
        patch("biopgp.core.windows_storage.list_windows_disks", return_value=[]),
        patch(
            "biopgp.core.windows_storage.wait_for_new_cleverpgp_disk",
            return_value=system_disk,
        ),
        patch("biopgp.core.windows_storage.wait_for_drive_letter", return_value="Z:"),
        patch("biopgp.core.windows_storage.wait_for_disk_removal") as removed,
    ):
        manager = WindowsSystemDiskManager(process_manager)  # type: ignore[arg-type]
        assert manager.mount(container_path, key) == "Z:"
        assert manager.mounted_drive == "Z:"
        manager.unmount()

    assert process_manager.started == (container_path, key)
    assert process_manager.stopped
    removed.assert_called_once_with(7)


def test_system_manager_publishes_and_removes_external_control_state(
    tmp_path: Path,
) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    container_path = tmp_path / "controlled.cpgv"
    volume = EncryptedBlockVolume.create(
        container_path,
        key,
        logical_capacity=1024 * 1024,
        storage_format=WINDOWS_BLOCK_STORAGE_FORMAT,
    )
    volume.close()
    process_manager = FakeProcessManager()
    process_manager.control_endpoint = DiskControlEndpoint(
        b"v" * 16,
        23456,
        b"t" * 32,
    )
    process_manager.process_id = 4321
    system_disk = disk(7, "CleverPGP", 1024 * 1024)
    record = object()

    class FakeStore:
        published: tuple[object, str, int] | None = None
        removed: object | None = None

        def publish(
            self,
            endpoint: object,
            *,
            drive: str,
            process_id: int,
        ) -> object:
            type(self).published = (endpoint, drive, process_id)
            return record

        @staticmethod
        def remove(selected: object | None) -> None:
            FakeStore.removed = selected

    class FakeContextMenu:
        registered: tuple[str, str, str] | None = None
        removed = False

        def register(
            self,
            drive: str,
            *,
            open_label: str,
            unmount_label: str,
        ) -> None:
            type(self).registered = (drive, open_label, unmount_label)

        def remove(self) -> None:
            type(self).removed = True

    with (
        patch("biopgp.core.windows_storage.list_windows_disks", return_value=[]),
        patch(
            "biopgp.core.windows_storage.wait_for_new_cleverpgp_disk",
            return_value=system_disk,
        ),
        patch("biopgp.core.windows_storage.wait_for_drive_letter", return_value="Z:"),
        patch("biopgp.core.windows_storage.wait_for_disk_removal"),
    ):
        manager = WindowsSystemDiskManager(process_manager)  # type: ignore[arg-type]
        manager._control_store = FakeStore()  # type: ignore[assignment]
        manager._context_menu = FakeContextMenu()  # type: ignore[assignment]
        assert manager.mount(
            container_path,
            key,
            context_menu_labels=("Open disk", "Unmount disk"),
        ) == "Z:"
        manager.unmount()

    assert FakeStore.published == (
        process_manager.control_endpoint,
        "Z:",
        4321,
    )
    assert FakeStore.removed is record
    assert FakeContextMenu.registered == ("Z:", "Open disk", "Unmount disk")
    assert FakeContextMenu.removed
