from __future__ import annotations

from pathlib import Path

import pytest

from biopgp.core.block_container import BLOCK_VAULT_STORAGE_FORMAT
from biopgp.core.block_volume import (
    GENERIC_STORAGE_FORMAT,
    MIN_LOGICAL_CAPACITY,
    EncryptedBlockVolume,
)
from biopgp.core.errors import InvalidContainerError
from biopgp.core.mount_router import (
    BACKEND_WINDOWS,
    BACKEND_WINFSP,
    AutomaticMountManager,
    detect_container_backend,
)
from biopgp.core.winspd import WINDOWS_BLOCK_STORAGE_FORMAT

MASTER_KEY = bytes(range(32))
OTHER_KEY = bytes(reversed(range(32)))


class FakeSystemManager:
    def __init__(
        self,
        *,
        mounted_drive: str | None = None,
        mounted_container: Path | None = None,
    ) -> None:
        self.mounted_drive = mounted_drive
        self.mounted_container = mounted_container
        self.create_calls: list[dict[str, object]] = []
        self.hidden_create_calls: list[dict[str, object]] = []
        self.mount_calls: list[dict[str, object]] = []
        self.opaque_mount_calls: list[dict[str, object]] = []
        self.password_change_calls: list[dict[str, object]] = []
        self.unmount_calls = 0
        self.prepare_calls = 0

    def prepare_backend(self) -> None:
        self.prepare_calls += 1

    def mount(
        self,
        container_path: Path,
        master_key: bytes,
        *,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: object = None,
    ) -> str:
        self.mount_calls.append(
            {
                "container_path": container_path,
                "master_key": master_key,
                "context_menu_labels": context_menu_labels,
                "progress": progress,
            }
        )
        self.mounted_drive = "S:"
        self.mounted_container = container_path
        return self.mounted_drive

    def create_and_mount(
        self,
        container_path: Path,
        master_key: bytes,
        **options: object,
    ) -> str:
        self.create_calls.append(
            {
                "container_path": container_path,
                "master_key": master_key,
                **options,
            }
        )
        self.mounted_drive = "N:"
        self.mounted_container = container_path
        return self.mounted_drive

    def create_hidden_and_mount(
        self,
        container_path: Path,
        outer_password: str,
        hidden_password: str,
        **options: object,
    ) -> str:
        self.hidden_create_calls.append(
            {
                "container_path": container_path,
                "outer_password": outer_password,
                "hidden_password": hidden_password,
                **options,
            }
        )
        self.mounted_drive = "H:"
        self.mounted_container = container_path
        return self.mounted_drive

    def mount_opaque(
        self,
        container_path: Path,
        password: str,
        **options: object,
    ) -> str:
        self.opaque_mount_calls.append(
            {
                "container_path": container_path,
                "password": password,
                **options,
            }
        )
        self.mounted_drive = "O:"
        self.mounted_container = container_path
        return self.mounted_drive

    def unmount(self) -> None:
        self.unmount_calls += 1
        self.mounted_drive = None
        self.mounted_container = None

    def change_opaque_password(
        self,
        current_password: str,
        new_password: str,
        **options: object,
    ) -> Path:
        assert self.mounted_container is not None
        source = self.mounted_container
        self.password_change_calls.append(
            {
                "current_password": current_password,
                "new_password": new_password,
                **options,
            }
        )
        self.mounted_drive = None
        self.mounted_container = None
        return source


class FakeWinFspManager:
    def __init__(self) -> None:
        self.mounted_drive: str | None = None
        self.mount_calls: list[dict[str, object]] = []
        self.unmount_calls = 0

    def mount(
        self,
        container_path: Path,
        master_key: bytes,
        drive: str | None = None,
        *,
        progress: object = None,
    ) -> str:
        self.mount_calls.append(
            {
                "container_path": container_path,
                "master_key": master_key,
                "drive": drive,
                "progress": progress,
            }
        )
        self.mounted_drive = drive or "W:"
        return self.mounted_drive

    def unmount(self) -> None:
        self.unmount_calls += 1
        self.mounted_drive = None


def create_volume(
    path: Path,
    storage_format: str,
    *,
    password: str | None = None,
) -> None:
    with EncryptedBlockVolume.create(
        path,
        MASTER_KEY,
        logical_capacity=MIN_LOGICAL_CAPACITY,
        storage_format=storage_format,
        password=password,
    ):
        pass


def test_detect_container_backend_authenticates_exact_storage_format(
    tmp_path: Path,
) -> None:
    system_path = tmp_path / "system.cpgv"
    winfsp_path = tmp_path / "winfsp.cpgv"
    create_volume(system_path, WINDOWS_BLOCK_STORAGE_FORMAT)
    create_volume(winfsp_path, BLOCK_VAULT_STORAGE_FORMAT)

    assert detect_container_backend(system_path, MASTER_KEY) == BACKEND_WINDOWS
    assert detect_container_backend(winfsp_path, MASTER_KEY) == BACKEND_WINFSP


def test_system_container_routes_to_windows_manager(tmp_path: Path) -> None:
    container_path = tmp_path / "system.cpgv"
    create_volume(container_path, WINDOWS_BLOCK_STORAGE_FORMAT)
    system = FakeSystemManager()
    winfsp = FakeWinFspManager()
    progress_events: list[tuple[int, str]] = []
    labels = ("open", "info", "access", "unmount")
    manager = AutomaticMountManager(
        system_manager=system,
        winfsp_manager=winfsp,  # type: ignore[arg-type]
    )

    mounted = manager.mount(
        container_path,
        MASTER_KEY,
        context_menu_labels=labels,
        progress=lambda value, message: progress_events.append((value, message)),
    )

    assert mounted == "S:"
    assert manager.active_backend == BACKEND_WINDOWS
    assert manager.uses_windows_system_disk
    assert manager.mounted_container == container_path.resolve()
    assert system.mount_calls[0]["context_menu_labels"] == labels
    assert not winfsp.mount_calls
    assert progress_events[0][0] == 3


def test_prepares_system_backend_before_background_creation() -> None:
    system = FakeSystemManager()
    manager = AutomaticMountManager(
        system_manager=system,
        winfsp_manager=FakeWinFspManager(),  # type: ignore[arg-type]
    )

    manager.prepare_system_backend()

    assert system.prepare_calls == 1


def test_block_vault_routes_to_winfsp_manager(tmp_path: Path) -> None:
    container_path = tmp_path / "vault.cpgv"
    create_volume(container_path, BLOCK_VAULT_STORAGE_FORMAT)
    system = FakeSystemManager()
    winfsp = FakeWinFspManager()
    manager = AutomaticMountManager(
        system_manager=system,
        winfsp_manager=winfsp,  # type: ignore[arg-type]
    )

    mounted = manager.mount(container_path, MASTER_KEY, drive="V:")

    assert mounted == "V:"
    assert manager.active_backend == BACKEND_WINFSP
    assert not manager.uses_windows_system_disk
    assert manager.mounted_container == container_path.resolve()
    assert winfsp.mount_calls[0]["drive"] == "V:"
    assert not system.mount_calls


def test_portable_password_routes_disk_without_original_profile_key(
    tmp_path: Path,
) -> None:
    container_path = tmp_path / "portable-system.cpgv"
    password = "correct portable disk password"
    create_volume(
        container_path,
        WINDOWS_BLOCK_STORAGE_FORMAT,
        password=password,
    )
    system = FakeSystemManager()
    manager = AutomaticMountManager(
        system_manager=system,
        winfsp_manager=FakeWinFspManager(),  # type: ignore[arg-type]
    )

    mounted = manager.mount_opaque(container_path, password)

    assert mounted == "S:"
    assert len(system.mount_calls) == 1
    portable_key = system.mount_calls[0]["master_key"]
    assert isinstance(portable_key, bytes)
    assert portable_key != MASTER_KEY
    with EncryptedBlockVolume.open(container_path, portable_key):
        pass
    assert not system.opaque_mount_calls


def test_fast_windows_disk_creation_routes_without_removing_winfsp(
    tmp_path: Path,
) -> None:
    container_path = tmp_path / "new-system.cpgv"
    system = FakeSystemManager()
    winfsp = FakeWinFspManager()
    manager = AutomaticMountManager(
        system_manager=system,
        winfsp_manager=winfsp,  # type: ignore[arg-type]
    )
    progress = object()

    mounted = manager.create_and_mount(
        container_path,
        MASTER_KEY,
        logical_capacity=64 * 1024 * 1024,
        file_system="NTFS",
        progress=progress,
    )

    assert mounted == "N:"
    assert manager.active_backend == BACKEND_WINDOWS
    assert manager.uses_windows_system_disk
    assert manager.mounted_container == container_path.resolve()
    assert system.create_calls == [
        {
            "container_path": container_path.resolve(),
            "master_key": MASTER_KEY,
            "logical_capacity": 64 * 1024 * 1024,
            "file_system": "NTFS",
            "progress": progress,
        }
    ]
    assert not winfsp.mount_calls


def test_hidden_creation_and_password_mount_route_only_to_windows(
    tmp_path: Path,
) -> None:
    container_path = tmp_path / "hidden.cpgv"
    system = FakeSystemManager()
    winfsp = FakeWinFspManager()
    manager = AutomaticMountManager(
        system_manager=system,
        winfsp_manager=winfsp,  # type: ignore[arg-type]
    )

    created = manager.create_hidden_and_mount(
        container_path,
        "outer correct horse battery staple",
        "hidden correct horse battery staple",
        outer_capacity=96 * 1024 * 1024,
        hidden_capacity=32 * 1024 * 1024,
    )

    assert created == "H:"
    assert system.hidden_create_calls[0]["container_path"] == (
        container_path.resolve()
    )
    assert manager.active_backend == BACKEND_WINDOWS
    manager.unmount()

    opened = manager.mount_opaque(
        container_path,
        "hidden correct horse battery staple",
        hidden_protection_password=None,
    )

    assert opened == "O:"
    assert system.opaque_mount_calls[0]["container_path"] == (
        container_path.resolve()
    )
    assert not winfsp.mount_calls


def test_opaque_password_change_routes_only_to_active_windows_manager(
    tmp_path: Path,
) -> None:
    source = (tmp_path / "hidden.cpgv").resolve()
    system = FakeSystemManager(mounted_drive="H:", mounted_container=source)
    manager = AutomaticMountManager(
        system_manager=system,
        winfsp_manager=FakeWinFspManager(),  # type: ignore[arg-type]
    )
    progress = object()

    changed = manager.change_opaque_password(
        "current password long enough",
        "replacement password long enough",
        progress=progress,
    )

    assert changed == source
    assert system.password_change_calls == [
        {
            "current_password": "current password long enough",
            "new_password": "replacement password long enough",
            "progress": progress,
        }
    ]


@pytest.mark.parametrize(
    ("storage_format", "key"),
    [
        (WINDOWS_BLOCK_STORAGE_FORMAT, OTHER_KEY),
        (GENERIC_STORAGE_FORMAT, MASTER_KEY),
    ],
)
def test_invalid_or_unknown_container_is_rejected_before_mount(
    tmp_path: Path,
    storage_format: str,
    key: bytes,
) -> None:
    container_path = tmp_path / f"unknown-{storage_format}.cpgv"
    create_volume(container_path, storage_format)
    system = FakeSystemManager()
    winfsp = FakeWinFspManager()
    manager = AutomaticMountManager(
        system_manager=system,
        winfsp_manager=winfsp,  # type: ignore[arg-type]
    )

    with pytest.raises(InvalidContainerError):
        manager.mount(container_path, key)

    assert not system.mount_calls
    assert not winfsp.mount_calls


def test_running_system_disk_is_recovered_and_can_be_detached(tmp_path: Path) -> None:
    container_path = (tmp_path / "running.cpgv").resolve()
    system = FakeSystemManager(
        mounted_drive="R:",
        mounted_container=container_path,
    )
    winfsp = FakeWinFspManager()
    manager = AutomaticMountManager(
        system_manager=system,
        winfsp_manager=winfsp,  # type: ignore[arg-type]
    )

    assert manager.mounted_drive == "R:"
    assert manager.mounted_container == container_path
    assert manager.active_backend == BACKEND_WINDOWS
    assert manager.uses_windows_system_disk

    manager.unmount()

    assert system.unmount_calls == 1
    assert manager.mounted_drive is None
    assert manager.active_backend is None


def test_same_manager_can_open_each_supported_backend_in_sequence(
    tmp_path: Path,
) -> None:
    system_path = tmp_path / "system.cpgv"
    winfsp_path = tmp_path / "vault.cpgv"
    create_volume(system_path, WINDOWS_BLOCK_STORAGE_FORMAT)
    create_volume(winfsp_path, BLOCK_VAULT_STORAGE_FORMAT)
    system = FakeSystemManager()
    winfsp = FakeWinFspManager()
    manager = AutomaticMountManager(
        system_manager=system,
        winfsp_manager=winfsp,  # type: ignore[arg-type]
    )

    assert manager.mount(system_path, MASTER_KEY) == "S:"
    manager.unmount()
    assert manager.mount(winfsp_path, MASTER_KEY) == "W:"

    assert len(system.mount_calls) == 1
    assert system.unmount_calls == 1
    assert len(winfsp.mount_calls) == 1
    assert manager.active_backend == BACKEND_WINFSP
