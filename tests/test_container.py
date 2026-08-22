from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from nacl import secret, utils

from biopgp.core.container import (
    CONTAINER_SUFFIX,
    DATABASE_RESERVE,
    HEADER_AREA_SIZE,
    MAGIC,
    MIN_DATA_CAPACITY,
    PREFIX,
    EncryptedContainer,
)
from biopgp.core.errors import (
    ContainerDirectoryNotEmptyError,
    ContainerEntryExistsError,
    ContainerFullError,
    InvalidContainerError,
    ValidationError,
)
from biopgp.core import container as container_module


def master_key() -> bytes:
    return utils.random(secret.SecretBox.KEY_SIZE)


def test_container_is_fixed_size_and_contains_no_plaintext(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / f"private{CONTAINER_SUFFIX}"

    container = EncryptedContainer.create(
        path, key, data_capacity=MIN_DATA_CAPACITY, label="Личные файлы"
    )
    initial_size = path.stat().st_size
    container.create_file("/secret.txt")
    container.write_file("/secret.txt", b"this must never be visible")
    container.close()

    raw = path.read_bytes()
    assert raw.startswith(MAGIC)
    assert b"this must never be visible" not in raw
    assert b"secret.txt" not in raw
    assert path.stat().st_size == initial_size
    assert initial_size > MIN_DATA_CAPACITY + DATABASE_RESERVE + HEADER_AREA_SIZE


def test_container_crud_survives_reopen(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "work.cpgv"

    with EncryptedContainer.create(
        path, key, data_capacity=MIN_DATA_CAPACITY, label="Работа"
    ) as container:
        container.create_directory("/Проекты")
        container.create_file("/Проекты/report.bin")
        container.write_file("/Проекты/report.bin", b"abc", offset=4)
        assert container.read_file("/Проекты/report.bin") == b"\x00\x00\x00\x00abc"
        container.truncate_file("/Проекты/report.bin", 10)
        container.rename("/Проекты/report.bin", "/Проекты/final.bin")
        container.rename("/Проекты/final.bin", "/Проекты/FINAL.bin")

    with EncryptedContainer.open(path, key) as reopened:
        assert reopened.label == "Работа"
        assert [node.name for node in reopened.list_directory("/")] == ["Проекты"]
        assert reopened.read_file("/проекты/FINAL.BIN") == b"\x00\x00\x00\x00abc\x00\x00\x00"
        assert reopened.list_directory("/Проекты")[0].name == "FINAL.bin"
        reopened.remove("/Проекты/final.bin")
        reopened.remove("/Проекты")
        assert reopened.list_directory("/") == []


def test_container_rejects_wrong_key_and_tampering(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "vault.cpgv"
    container = EncryptedContainer.create(
        path, key, data_capacity=MIN_DATA_CAPACITY
    )
    container.close()

    with pytest.raises(InvalidContainerError):
        EncryptedContainer.open(path, master_key())

    raw = bytearray(path.read_bytes())
    raw[PREFIX.size + HEADER_AREA_SIZE + 64] ^= 0x01
    path.write_bytes(raw)
    with pytest.raises(InvalidContainerError):
        EncryptedContainer.open(path, key)


def test_container_enforces_namespace_and_capacity(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "small.cpgv"
    with EncryptedContainer.create(
        path, key, data_capacity=MIN_DATA_CAPACITY
    ) as container:
        container.create_directory("/folder")
        container.create_file("/folder/file")
        with pytest.raises(ContainerEntryExistsError):
            container.create_file("/FOLDER/FILE")
        with pytest.raises(ContainerDirectoryNotEmptyError):
            container.remove("/folder")
        with pytest.raises(ContainerFullError):
            container.write_file("/folder/file", b"x" * (MIN_DATA_CAPACITY + 1))
        assert container.read_file("/folder/file") == b""


def test_unsaved_changes_are_not_persisted(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "buffered.cpgv"
    container = EncryptedContainer.create(
        path, key, data_capacity=MIN_DATA_CAPACITY
    )
    container.create_file("/draft", persist=False)
    container.write_file("/draft", b"buffered", persist=False)
    container.close(save=False)

    with EncryptedContainer.open(path, key) as reopened:
        assert reopened.list_directory("/") == []


def test_old_container_signature_is_rejected(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "old-signature.cpgv"
    container = EncryptedContainer.create(
        path, key, data_capacity=MIN_DATA_CAPACITY
    )
    container.close()
    raw = bytearray(path.read_bytes())
    raw[:9] = b"BPGPVAULT"
    path.write_bytes(raw)

    with pytest.raises(InvalidContainerError):
        EncryptedContainer.open(path, key)


def test_container_capacity_is_not_limited_to_512_mb(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "large-logical-capacity.cpgv"
    one_gibibyte = 1024 * 1024 * 1024

    container = EncryptedContainer.create(
        path, key, data_capacity=one_gibibyte
    )
    container.close()

    assert path.stat().st_size > one_gibibyte
    with EncryptedContainer.open(path, key) as reopened:
        assert reopened.data_capacity == one_gibibyte


def test_container_rejects_capacity_larger_than_selected_drive(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        container_module.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=MIN_DATA_CAPACITY),
    )

    with pytest.raises(
        ValidationError,
        match="Недостаточно свободного места на выбранном накопителе",
    ):
        EncryptedContainer.create(
            tmp_path / "too-large.cpgv",
            master_key(),
            data_capacity=MIN_DATA_CAPACITY,
        )


def test_storage_limit_uses_container_location(monkeypatch, tmp_path: Path) -> None:
    observed: list[Path] = []
    free_bytes = 20 * MIN_DATA_CAPACITY

    def disk_usage(path: Path) -> SimpleNamespace:
        observed.append(Path(path))
        return SimpleNamespace(free=free_bytes)

    monkeypatch.setattr(container_module.shutil, "disk_usage", disk_usage)
    target = tmp_path / "chosen" / "disk.cpgv"
    target.parent.mkdir()

    reported_free, maximum = EncryptedContainer.storage_space(target)

    assert observed == [target.parent.resolve()]
    assert reported_free == free_bytes
    assert maximum < reported_free
    assert maximum == (
        reported_free
        - EncryptedContainer._container_file_size(container_module.DATABASE_RESERVE)
    )
