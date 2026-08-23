from __future__ import annotations

import json
from dataclasses import replace
from unittest.mock import patch
from pathlib import Path

import pytest
from nacl import secret, utils

from biopgp.core.block_volume import EncryptedBlockVolume
from biopgp.core.disk_control import DiskControlEndpoint, DiskControlRecord
from biopgp.core.errors import MountUnavailableError
from biopgp.core.winspd import WINDOWS_BLOCK_STORAGE_FORMAT
from biopgp.core.windows_storage import (
    WindowsDiskInfo,
    WindowsSystemDiskManager,
    WindowsVolumeInfo,
    disk_drive_letters,
    extend_cleverpgp_ntfs_partition,
    format_ephemeral_cleverpgp_disk,
    inspect_windows_volume,
    select_new_cleverpgp_disk,
    validate_cleverpgp_ntfs_volume,
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


def mounted_volume(
    *,
    file_system: str = "NTFS",
    disk_size: int = 256 * 1024 * 1024,
    partition_size: int = 127 * 1024 * 1024,
) -> WindowsVolumeInfo:
    return WindowsVolumeInfo(
        disk_number=7,
        partition_number=1,
        drive="Z:",
        friendly_name="CleverPGP",
        serial_number="serial-7",
        unique_id="unique-7",
        bus_type="File Backed Virtual",
        disk_size=disk_size,
        partition_size=partition_size,
        partition_offset=1024 * 1024,
        partition_style="MBR",
        file_system=file_system,
        data_partition_count=1,
        is_boot=False,
        is_system=False,
    )


def test_inspects_volume_by_drive_letter() -> None:
    raw = json.dumps(
        {
            "DiskNumber": 7,
            "PartitionNumber": 1,
            "DriveLetter": "Z",
            "FriendlyName": "CleverPGP",
            "SerialNumber": "serial-7",
            "UniqueId": "unique-7",
            "BusType": "File Backed Virtual",
            "DiskSize": 256 * 1024 * 1024,
            "PartitionSize": 127 * 1024 * 1024,
            "PartitionOffset": 1024 * 1024,
            "PartitionStyle": "MBR",
            "FileSystem": "NTFS",
            "DataPartitionCount": 1,
            "IsBoot": False,
            "IsSystem": False,
        }
    )
    with patch(
        "biopgp.core.windows_storage._run_powershell",
        return_value=raw,
    ) as run_powershell:
        info = inspect_windows_volume("z:\\")

    assert info == mounted_volume()
    assert "Get-Partition -DriveLetter 'Z'" in run_powershell.call_args.args[0]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"friendly_name": "Physical SSD"}, "не принадлежит"),
        ({"partition_style": "GPT"}, "MBR"),
        ({"is_boot": True}, "загрузочный"),
        ({"is_system": True}, "Системный"),
        ({"data_partition_count": 2}, "ровно один"),
        ({"partition_offset": 2 * 1024 * 1024}, "отступ"),
        ({"file_system": "exFAT"}, "только для NTFS"),
    ],
)
def test_ntfs_resize_validation_rejects_wrong_target(
    changes: dict[str, object],
    message: str,
) -> None:
    original = mounted_volume()
    values = {
        field: getattr(original, field)
        for field in WindowsVolumeInfo.__dataclass_fields__
    }
    values.update(changes)
    with pytest.raises(MountUnavailableError, match=message):
        validate_cleverpgp_ntfs_volume(WindowsVolumeInfo(**values))


def test_ntfs_extension_revalidates_identity_before_resize() -> None:
    info = mounted_volume()
    expected_partition_size = info.partition_size
    resized_partition = info.disk_size - info.partition_offset
    raw = json.dumps(
        {
            "DiskSize": info.disk_size,
            "PartitionSize": resized_partition,
            "FileSystem": "NTFS",
        }
    )
    with patch(
        "biopgp.core.windows_storage._run_powershell",
        return_value=raw,
    ) as run_powershell:
        result = extend_cleverpgp_ntfs_partition(
            info,
            expected_disk_size=info.disk_size,
            expected_partition_size=expected_partition_size,
        )

    script = run_powershell.call_args.args[0]
    assert result.partition_size == resized_partition
    assert "Get-Partition -DriveLetter 'Z'" in script
    assert "$disk.FriendlyName -ne $expectedFriendly" in script
    assert "$disk.UniqueId -ne $expectedUnique" in script
    assert "$disk.BusType -ne $expectedBus" in script
    assert "$disk.IsBoot" in script
    assert "$dataPartitions.Count -ne 1" in script
    assert script.index("Get-Disk -Number 7") < script.index("Resize-Partition")
    assert script.index("$volume.FileSystem -ne 'NTFS'") < script.index(
        "Resize-Partition"
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
    assert "$disk.FriendlyName -ne $expectedFriendly" in script
    assert "$disk.SerialNumber -ne $expectedSerial" in script
    assert "$disk.UniqueId -ne $expectedUnique" in script
    assert "$disk.PartitionStyle -ne 'MBR'" in script
    assert "$disk.IsBoot -or [Boolean]$disk.IsSystem" in script
    assert "$partition.Offset -ne [UInt64]1048576" in script
    assert script.index("Get-Disk -Number 7") < script.index("Format-Volume")
    assert script.index("$partition.Offset") < script.index("Format-Volume")


def test_refuses_new_disk_marked_as_boot_or_system() -> None:
    expected_size = 128 * 1024 * 1024
    candidate = replace(
        disk(7, "CleverPGP", expected_size),
        is_system=True,
    )

    with pytest.raises(MountUnavailableError):
        select_new_cleverpgp_disk([], [candidate], expected_size=expected_size)


def test_system_manager_formats_new_disk_only_through_uac_helper(
    tmp_path: Path,
) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    container_path = tmp_path / "new-system.cpgv"
    expected_size = 64 * 1024 * 1024
    selected_disk = disk(7, "CleverPGP", expected_size)
    endpoint = DiskControlEndpoint(b"v" * 16, 23456, b"t" * 32)
    process_manager = FakeProcessManager()
    process_manager.control_endpoint = endpoint
    process_manager.process_id = 4321

    class CreatedVolume:
        @staticmethod
        def close() -> None:
            return None

    def create_volume(path: Path, *_args: object, **_kwargs: object) -> CreatedVolume:
        path.write_bytes(b"new encrypted disk")
        return CreatedVolume()

    manager = WindowsSystemDiskManager(  # type: ignore[arg-type]
        process_manager,
        recover_existing=False,
    )
    with (
        patch("biopgp.core.windows_storage.WinSpdLibrary"),
        patch(
            "biopgp.core.windows_storage.create_windows_block_volume",
            side_effect=create_volume,
        ),
        patch("biopgp.core.windows_storage.list_windows_disks", return_value=[]),
        patch(
            "biopgp.core.windows_storage.wait_for_new_cleverpgp_disk",
            return_value=selected_disk,
        ),
        patch(
            "biopgp.core.windows_format.run_elevated_windows_format",
            return_value="Z:",
        ) as elevated_format,
        patch.object(manager, "_publish_control_record", return_value=None),
    ):
        drive = manager.create_and_mount(
            container_path,
            key,
            logical_capacity=expected_size,
            label="Private",
            file_system="NTFS",
        )

    assert drive == "Z:"
    assert container_path.is_file()
    elevated_format.assert_called_once_with(
        endpoint,
        selected_disk,
        file_system="NTFS",
        label="Private",
    )


def test_system_manager_removes_unformatted_image_after_uac_failure(
    tmp_path: Path,
) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    container_path = tmp_path / "cancelled-system.cpgv"
    expected_size = 64 * 1024 * 1024
    selected_disk = disk(7, "CleverPGP", expected_size)
    process_manager = FakeProcessManager()
    process_manager.control_endpoint = DiskControlEndpoint(
        b"v" * 16,
        23456,
        b"t" * 32,
    )

    class CreatedVolume:
        @staticmethod
        def close() -> None:
            return None

    def create_volume(path: Path, *_args: object, **_kwargs: object) -> CreatedVolume:
        path.write_bytes(b"unformatted encrypted disk")
        return CreatedVolume()

    manager = WindowsSystemDiskManager(  # type: ignore[arg-type]
        process_manager,
        recover_existing=False,
    )
    with (
        patch("biopgp.core.windows_storage.WinSpdLibrary"),
        patch(
            "biopgp.core.windows_storage.create_windows_block_volume",
            side_effect=create_volume,
        ),
        patch("biopgp.core.windows_storage.list_windows_disks", return_value=[]),
        patch(
            "biopgp.core.windows_storage.wait_for_new_cleverpgp_disk",
            return_value=selected_disk,
        ),
        patch(
            "biopgp.core.windows_format.run_elevated_windows_format",
            side_effect=MountUnavailableError("UAC cancelled"),
        ),
    ):
        with pytest.raises(MountUnavailableError, match="UAC cancelled"):
            manager.create_and_mount(
                container_path,
                key,
                logical_capacity=expected_size,
                label="Private",
            )

    assert process_manager.stopped
    assert not container_path.exists()


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
        manager = WindowsSystemDiskManager(  # type: ignore[arg-type]
            process_manager,
            recover_existing=False,
        )
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
            container_path: Path,
        ) -> object:
            assert container_path == Path(tmp_path / "controlled.cpgv")
            type(self).published = (endpoint, drive, process_id)
            return record

        @staticmethod
        def remove(selected: object | None) -> None:
            FakeStore.removed = selected

    class FakeContextMenu:
        registered: tuple[str, str, str, str, str, str] | None = None
        removed = False

        def register(
            self,
            drive: str,
            *,
            open_label: str,
            info_label: str,
            settings_label: str,
            resize_label: str,
            unmount_label: str,
        ) -> None:
            type(self).registered = (
                drive,
                open_label,
                info_label,
                settings_label,
                resize_label,
                unmount_label,
            )

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
        manager = WindowsSystemDiskManager(  # type: ignore[arg-type]
            process_manager,
            recover_existing=False,
        )
        manager._control_store = FakeStore()  # type: ignore[assignment]
        manager._context_menu = FakeContextMenu()  # type: ignore[assignment]
        assert manager.mount(
            container_path,
            key,
            context_menu_labels=("Open disk", "Access settings", "Unmount disk"),
        ) == "Z:"
        manager.unmount()

    assert FakeStore.published == (
        process_manager.control_endpoint,
        "Z:",
        4321,
    )
    assert FakeStore.removed is record
    assert FakeContextMenu.registered == (
        "Z:",
        "Open disk",
        "Сведения о диске",
        "Access settings",
        "Увеличить диск",
        "Unmount disk",
    )
    assert FakeContextMenu.removed


def test_system_manager_retains_state_when_safe_unmount_is_not_confirmed() -> None:
    class RefusingProcessManager:
        running = True
        control_endpoint = None
        process_id = None

        def stop(self) -> None:
            raise MountUnavailableError("files are busy")

    record = object()
    manager = WindowsSystemDiskManager(  # type: ignore[arg-type]
        RefusingProcessManager(),
        recover_existing=False,
    )
    manager._drive = "Z:"
    manager._disk = disk(7, "CleverPGP", 128 * 1024 * 1024)
    manager._control_record = record  # type: ignore[assignment]

    with pytest.raises(MountUnavailableError, match="files are busy"):
        manager.unmount()

    assert manager._drive == "Z:"
    assert manager._disk is not None
    assert manager._control_record is record


def test_system_manager_recovers_and_unmounts_detached_host(
    tmp_path: Path,
) -> None:
    record = DiskControlRecord(
        volume_id=b"v" * 16,
        drive="Z:",
        port=23456,
        process_id=4321,
        protected_token=b"protected-token",
        path=tmp_path / "mount.json",
    )
    drive_state = {"Z:": True}

    class RecoverableStore:
        def __init__(self) -> None:
            self.commands: list[tuple[str, float]] = []
            self.removed: list[DiskControlRecord] = []

        def records(self) -> tuple[DiskControlRecord, ...]:
            return () if self.removed else (record,)

        def send(
            self,
            selected: DiskControlRecord,
            command: str,
            *,
            timeout: float = 3.0,
        ) -> None:
            assert selected is record
            self.commands.append((command, timeout))
            if command == "stop":
                drive_state[selected.drive] = False

        def remove(self, selected: DiskControlRecord | None) -> None:
            if selected is not None:
                self.removed.append(selected)

    class ContextMenu:
        removed = False

        def remove(self) -> None:
            self.removed = True

    store = RecoverableStore()
    menu = ContextMenu()
    process_manager = FakeProcessManager()
    manager = WindowsSystemDiskManager(
        process_manager,  # type: ignore[arg-type]
        control_store=store,  # type: ignore[arg-type]
        context_menu=menu,  # type: ignore[arg-type]
        drive_available=lambda drive: drive_state.get(drive, False),
    )

    assert manager.mounted_drive == "Z:"
    assert process_manager.started is None
    manager.unmount()

    assert manager.mounted_drive is None
    assert [command for command, _timeout in store.commands] == [
        "ping",
        "ping",
        "stop",
    ]
    assert store.removed == [record]
    assert menu.removed


def test_system_manager_removes_stale_detached_host_state(
    tmp_path: Path,
) -> None:
    record = DiskControlRecord(
        volume_id=b"v" * 16,
        drive="Z:",
        port=23456,
        process_id=4321,
        protected_token=b"protected-token",
        path=tmp_path / "mount.json",
    )

    class StaleStore:
        removed: list[DiskControlRecord] = []

        @classmethod
        def records(cls) -> tuple[DiskControlRecord, ...]:
            return () if cls.removed else (record,)

        @staticmethod
        def send(
            _record: DiskControlRecord,
            _command: str,
            *,
            timeout: float = 3.0,
        ) -> None:
            del timeout
            raise MountUnavailableError("host is gone")

        @classmethod
        def remove(cls, selected: DiskControlRecord | None) -> None:
            if selected is not None:
                cls.removed.append(selected)

    class ContextMenu:
        removed = False

        def remove(self) -> None:
            self.removed = True

    menu = ContextMenu()
    manager = WindowsSystemDiskManager(
        FakeProcessManager(),  # type: ignore[arg-type]
        control_store=StaleStore(),  # type: ignore[arg-type]
        context_menu=menu,  # type: ignore[arg-type]
        drive_available=lambda _drive: False,
    )

    assert manager.mounted_drive is None
    assert StaleStore.removed == [record]
    assert menu.removed


def test_system_manager_refreshes_record_after_external_resize_remount(
    tmp_path: Path,
) -> None:
    container_path = (tmp_path / "resized.cpgv").resolve()
    old_record = DiskControlRecord(
        volume_id=b"v" * 16,
        drive="Z:",
        port=23456,
        process_id=4321,
        protected_token=b"old-protected-token",
        path=tmp_path / "mount.json",
    )
    new_record = replace(
        old_record,
        port=23457,
        process_id=4322,
        protected_token=b"new-protected-token",
    )

    class RefreshedStore:
        commands: list[DiskControlRecord] = []

        @classmethod
        def send(
            cls,
            selected: DiskControlRecord,
            command: str,
            *,
            timeout: float = 3.0,
        ) -> None:
            assert command == "ping"
            assert timeout == 0.35
            cls.commands.append(selected)
            if selected == old_record:
                raise MountUnavailableError("old host is gone")

        @staticmethod
        def find_by_drive(drive: str) -> DiskControlRecord | None:
            assert drive == "Z:"
            return new_record

        @staticmethod
        def container_path(selected: DiskControlRecord) -> Path:
            assert selected == new_record
            return container_path

    manager = WindowsSystemDiskManager(
        FakeProcessManager(),  # type: ignore[arg-type]
        control_store=RefreshedStore(),  # type: ignore[arg-type]
        drive_available=lambda _drive: True,
        recover_existing=False,
    )
    manager._control_record = old_record
    manager._drive = "Z:"

    assert manager.mounted_drive == "Z:"
    assert manager._control_record == new_record
    assert manager.mounted_container == container_path
    assert RefreshedStore.commands == [old_record, new_record, new_record]


def test_system_manager_grows_remounts_and_extends_ntfs(
    tmp_path: Path,
) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    container_path = tmp_path / "resize-system.cpgv"
    container_path.write_bytes(b"container")
    old_size = 128 * 1024 * 1024
    new_size = 256 * 1024 * 1024
    old_partition_size = old_size - 1024 * 1024
    original = mounted_volume(
        disk_size=old_size,
        partition_size=old_partition_size,
    )
    resized = replace(original, disk_number=8, disk_size=new_size)
    old_record = DiskControlRecord(
        b"v" * 16,
        "Z:",
        23456,
        4321,
        b"protected",
        tmp_path / "old-record.json",
    )
    new_record = replace(old_record, port=23457, path=tmp_path / "new-record.json")

    class ActiveProcessManager(FakeProcessManager):
        def __init__(self) -> None:
            super().__init__()
            self.running = True

    class ResizeStore:
        commands: list[tuple[object, str, float]] = []

        @classmethod
        def send(
            cls,
            record: object,
            command: str,
            *,
            timeout: float = 3.0,
        ) -> None:
            cls.commands.append((record, command, timeout))

    process = ActiveProcessManager()
    manager = WindowsSystemDiskManager(  # type: ignore[arg-type]
        process,
        recover_existing=False,
    )
    manager._control_store = ResizeStore()  # type: ignore[assignment]
    manager._drive = "Z:"
    manager._container_path = container_path
    manager._control_record = old_record
    manager._context_menu_labels = ("Open", "Settings", "Unmount")
    events: list[str] = []
    progress: list[tuple[int, str]] = []

    def unmount() -> None:
        events.append("unmount")
        process.running = False
        manager._drive = None
        manager._container_path = None
        manager._control_record = None

    def resize_backend(
        path: Path,
        selected_key: bytes,
        *,
        logical_capacity: int,
        progress: object,
    ) -> int:
        events.append("grow-container")
        assert path == container_path
        assert selected_key == key
        assert logical_capacity == new_size
        progress(1, 1)  # type: ignore[operator]
        return logical_capacity

    def mount(
        path: Path,
        selected_key: bytes,
        *,
        context_menu_labels: tuple[str, ...] | None,
        progress: object,
    ) -> str:
        events.append("remount")
        assert path == container_path
        assert selected_key == key
        assert context_menu_labels == ("Open", "Settings", "Unmount")
        process.running = True
        manager._drive = "Z:"
        manager._container_path = container_path
        manager._control_record = new_record
        if progress is not None:
            progress(100, "mounted")  # type: ignore[operator]
        return "Z:"

    def extend(
        record: DiskControlRecord,
        info: WindowsVolumeInfo,
    ) -> object:
        events.append("extend-ntfs")
        assert record is new_record
        assert info == resized
        return type(
            "Result",
            (),
            {
                "disk_size": new_size,
                "partition_size": new_size - 1024 * 1024,
                "file_system": "NTFS",
            },
        )()

    with (
        patch(
            "biopgp.core.windows_storage.inspect_windows_volume",
            side_effect=[original, resized],
        ),
        patch(
            "biopgp.core.windows_storage.resize_windows_block_volume",
            side_effect=resize_backend,
        ),
        patch.object(manager, "unmount", side_effect=unmount),
        patch.object(manager, "mount", side_effect=mount),
    ):
        drive = manager.resize_mounted_disk(
            key,
            logical_capacity=new_size,
            progress=lambda value, message: progress.append((value, message)),
            elevated_extender=extend,  # type: ignore[arg-type]
        )

    assert drive == "Z:"
    assert events == ["unmount", "grow-container", "remount", "extend-ntfs"]
    assert ResizeStore.commands == [(old_record, "ping", 1.0)]
    assert progress[-1] == (100, "Системный диск увеличен")


def test_system_manager_can_retry_only_ntfs_extension_after_uac_cancel(
    tmp_path: Path,
) -> None:
    container_path = tmp_path / "retry-system.cpgv"
    container_path.write_bytes(b"container")
    info = mounted_volume(
        disk_size=256 * 1024 * 1024,
        partition_size=127 * 1024 * 1024,
    )
    record = DiskControlRecord(
        b"v" * 16,
        "Z:",
        23456,
        4321,
        b"protected",
        tmp_path / "record.json",
    )

    class ActiveProcessManager(FakeProcessManager):
        def __init__(self) -> None:
            super().__init__()
            self.running = True

    class Store:
        @staticmethod
        def send(*_args: object, **_kwargs: object) -> None:
            return None

    manager = WindowsSystemDiskManager(  # type: ignore[arg-type]
        ActiveProcessManager(),
        recover_existing=False,
    )
    manager._control_store = Store()  # type: ignore[assignment]
    manager._drive = "Z:"
    manager._container_path = container_path
    manager._control_record = record
    result = type(
        "Result",
        (),
        {
            "disk_size": info.disk_size,
            "partition_size": info.disk_size - info.partition_offset,
            "file_system": "NTFS",
        },
    )()

    with (
        patch(
            "biopgp.core.windows_storage.inspect_windows_volume",
            return_value=info,
        ),
        patch.object(manager, "unmount") as unmount,
    ):
        assert manager.resize_mounted_disk(
            b"k" * 32,
            logical_capacity=info.disk_size,
            elevated_extender=lambda _record, _info: result,  # type: ignore[arg-type]
        ) == "Z:"

    unmount.assert_not_called()
