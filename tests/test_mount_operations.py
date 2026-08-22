from __future__ import annotations

import errno
from pathlib import Path

import pytest
from nacl import secret, utils

from biopgp.core.container import MIN_DATA_CAPACITY, EncryptedContainer
from biopgp.core.mount import (
    VaultFuseOperations,
    mount_backend_available,
    mount_fuse_options,
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


def test_mount_backend_is_absent_on_clean_test_machine() -> None:
    assert isinstance(mount_backend_available(), bool)


def test_windows_mount_is_owned_by_the_current_user() -> None:
    from unittest.mock import patch

    with patch("biopgp.core.mount.platform.system", return_value="Windows"):
        options = mount_fuse_options("Clever PGP")

    assert options["uid"] == -1
    assert options["gid"] == -1
    assert options["umask"] == 0
    assert options["create_umask"] == 0
