from __future__ import annotations

import errno
from pathlib import Path
from unittest.mock import patch

import pytest
from nacl import secret, utils

from cleverpgp.core.block_container import BlockVaultContainer
from cleverpgp.core.container import MIN_DATA_CAPACITY, EncryptedContainer
from cleverpgp.core.mount import (
    VaultFuseOperations,
    mount_backend_available,
    mount_fuse_options,
    unmount_drive,
)


def test_fuse_operations_map_regular_file_actions(tmp_path: Path) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    container = EncryptedContainer.create(
        tmp_path / "mounted.cpgv", key, data_capacity=MIN_DATA_CAPACITY
    )
    operations = VaultFuseOperations(container)

    operations("mkdir", "/folder", 0o755)
    handle = operations("create", "/folder/test.txt", 0o644)
    assert operations("write", "/folder/test.txt", b"hello", 0, handle) == 5
    assert operations("read", "/folder/test.txt", 5, 0, handle) == b"hello"
    operations("flush", "/folder/test.txt", handle)
    assert operations("readdir", "/folder", 0) == [".", "..", "test.txt"]
    operations("rename", "/folder/test.txt", "/folder/final.txt")
    operations("unlink", "/folder/final.txt")
    operations("rmdir", "/folder")
    container.close()

    with EncryptedContainer.open(tmp_path / "mounted.cpgv", key) as reopened:
        assert reopened.list_directory("/") == []


def test_fuse_operations_translate_missing_path(tmp_path: Path) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    container = EncryptedContainer.create(
        tmp_path / "errors.cpgv", key, data_capacity=MIN_DATA_CAPACITY
    )
    operations = VaultFuseOperations(container)
    with pytest.raises(OSError) as caught:
        operations("getattr", "/missing")
    assert caught.value.errno == errno.ENOENT
    container.close()


def test_fuse_operations_use_block_container_without_full_payload_save(
    tmp_path: Path,
) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    container = BlockVaultContainer.create(
        tmp_path / "block-mounted.cpgv", key, data_capacity=2 * MIN_DATA_CAPACITY
    )
    operations = VaultFuseOperations(container)
    handle = operations("create", "/movie.bin", 0o644)
    payload = b"m" * MIN_DATA_CAPACITY

    assert operations("write", "/movie.bin", payload, 0, handle) == len(payload)
    operations("flush", "/movie.bin", handle)
    container.close(save=False)

    with BlockVaultContainer.open(tmp_path / "block-mounted.cpgv", key) as reopened:
        assert reopened.read_file("/movie.bin") == payload


def test_mount_backend_is_absent_on_clean_test_machine() -> None:
    assert isinstance(mount_backend_available(), bool)


def test_windows_mount_is_owned_by_the_current_user() -> None:
    with patch("cleverpgp.core.mount.platform.system", return_value="Windows"):
        options = mount_fuse_options("Clever PGP")

    assert options["uid"] == -1
    assert options["gid"] == -1
    assert options["umask"] == 0
    assert options["create_umask"] == 0


def test_windows_unmount_uses_system_disk_control_when_fuse_marker_is_absent(
    monkeypatch,
) -> None:
    record = object()

    class FakeControlStore:
        removed: object | None = None
        sent: tuple[object, str] | None = None

        def find_by_drive(self, drive: str) -> object | None:
            return record if drive == "Z:" else None

        def send(self, selected: object, command: str) -> None:
            type(self).sent = (selected, command)

        @staticmethod
        def remove(selected: object) -> None:
            FakeControlStore.removed = selected

    class FakeContextMenu:
        removed = False

        def remove(self) -> None:
            type(self).removed = True

    drive_checks = iter((True, True, False, False))
    monkeypatch.setattr(
        "cleverpgp.core.disk_control.DiskControlStore", FakeControlStore
    )
    monkeypatch.setattr(
        "cleverpgp.core.windows_shell.WindowsDriveContextMenu", FakeContextMenu
    )
    with (
        patch("cleverpgp.core.mount.platform.system", return_value="Windows"),
        patch("cleverpgp.core.mount.Path.open", side_effect=OSError),
        patch(
            "cleverpgp.core.mount._drive_in_use",
            side_effect=lambda _drive: next(drive_checks),
        ),
        patch("cleverpgp.core.mount.time.sleep"),
    ):
        assert unmount_drive("z:\\") == "Z:"

    assert FakeControlStore.sent == (record, "stop")
    assert FakeControlStore.removed is record
    assert FakeContextMenu.removed
