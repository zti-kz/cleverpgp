from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from nacl import secret, utils

from biopgp.core.block_container import (
    METADATA_BLOCKS,
    METADATA_SLOT_BLOCKS,
    BlockVaultContainer,
)
from biopgp.core.block_volume import (
    HEADER_AREA_SIZE,
    HEADER_PREFIX,
    LOGICAL_BLOCK_SIZE,
    PHYSICAL_SLOT_SIZE,
)
from biopgp.core.errors import (
    ContainerEntryNotFoundError,
    ContainerFullError,
    InvalidContainerError,
)


def master_key() -> bytes:
    return utils.random(secret.SecretBox.KEY_SIZE)


def test_block_container_persists_files_directories_and_sparse_ranges(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "files.cpgv"
    marker = b"plain-block-container-marker"

    with BlockVaultContainer.create(
        path, key, data_capacity=4 * 1024 * 1024, label="Рабочий диск"
    ) as container:
        container.create_directory("/Документы")
        container.create_file("/Документы/Отчёт.txt", persist=False)
        container.write_file(
            "/Документы/Отчёт.txt", marker, offset=LOGICAL_BLOCK_SIZE + 7
        )
        assert container.read_file("/документы/отчёт.TXT") == (
            bytes(LOGICAL_BLOCK_SIZE + 7) + marker
        )

    assert marker not in path.read_bytes()
    with BlockVaultContainer.open(path, key) as reopened:
        assert reopened.label == "Рабочий диск"
        assert reopened.read_file(
            "/Документы/Отчёт.txt", offset=LOGICAL_BLOCK_SIZE + 7
        ) == marker


def test_only_touched_data_blocks_change_on_overwrite(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "random-access.cpgv"
    payload = b"A" * (8 * LOGICAL_BLOCK_SIZE)

    with BlockVaultContainer.create(
        path, key, data_capacity=2 * 1024 * 1024
    ) as container:
        container.create_file("/movie.bin", persist=False)
        container.write_file("/movie.bin", payload)
    before = path.read_bytes()

    with BlockVaultContainer.open(path, key) as reopened:
        reopened.write_file(
            "/movie.bin", b"changed".ljust(LOGICAL_BLOCK_SIZE, b"!"), offset=0
        )
    after = path.read_bytes()

    data_start = HEADER_PREFIX.size + HEADER_AREA_SIZE
    before_slots = [
        before[offset : offset + PHYSICAL_SLOT_SIZE]
        for offset in range(data_start, len(before), PHYSICAL_SLOT_SIZE)
    ]
    after_slots = [
        after[offset : offset + PHYSICAL_SLOT_SIZE]
        for offset in range(data_start, len(after), PHYSICAL_SLOT_SIZE)
    ]
    changed_data_slots = [
        index
        for index in range(METADATA_BLOCKS, len(before_slots))
        if before_slots[index] != after_slots[index]
    ]
    assert len(changed_data_slots) == 1


def test_previous_metadata_checkpoint_survives_interrupted_latest_save(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "checkpoint.cpgv"
    with BlockVaultContainer.create(
        path, key, data_capacity=2 * 1024 * 1024
    ) as container:
        container.create_file("/stable.txt")
        container.create_file("/latest.txt")

    data_start = HEADER_PREFIX.size + HEADER_AREA_SIZE
    latest_slot = 1  # create=1, stable=2, latest=3
    offset = data_start + latest_slot * METADATA_SLOT_BLOCKS * PHYSICAL_SLOT_SIZE
    with path.open("r+b") as stream:
        stream.seek(offset + 13)
        original = stream.read(1)
        stream.seek(offset + 13)
        stream.write(bytes([original[0] ^ 1]))

    with BlockVaultContainer.open(path, key) as recovered:
        assert recovered.node("/stable.txt").name == "stable.txt"
        with pytest.raises(ContainerEntryNotFoundError):
            recovered.node("/latest.txt")


def test_truncate_erases_tail_and_capacity_is_enforced(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "truncate.cpgv"
    capacity = 1024 * 1024
    with BlockVaultContainer.create(
        path, key, data_capacity=capacity
    ) as container:
        container.create_file("/data.bin", persist=False)
        container.write_file("/data.bin", b"secret-tail", offset=100, persist=False)
        container.truncate_file("/data.bin", 103, persist=False)
        container.truncate_file("/data.bin", 111)
        assert container.read_file("/data.bin", offset=100) == b"sec" + bytes(8)
        with pytest.raises(ContainerFullError):
            container.truncate_file("/data.bin", capacity + 1)


def test_uncommitted_overwrite_of_full_disk_keeps_previous_data(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "full-disk.cpgv"
    capacity = 1024 * 1024
    original = b"A" * capacity
    with BlockVaultContainer.create(
        path, key, data_capacity=capacity
    ) as container:
        container.create_file("/full.bin", persist=False)
        container.write_file("/full.bin", original)

    container = BlockVaultContainer.open(path, key)
    container.write_file(
        "/full.bin", b"B" * LOGICAL_BLOCK_SIZE, offset=0, persist=False
    )
    container.close(save=False)

    with BlockVaultContainer.open(path, key) as recovered:
        assert recovered.read_file(
            "/full.bin", length=LOGICAL_BLOCK_SIZE
        ) == b"A" * LOGICAL_BLOCK_SIZE


def test_full_disk_can_be_overwritten_in_reserve_sized_checkpoints(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "full-rewrite.cpgv"
    capacity = 2 * 1024 * 1024
    with BlockVaultContainer.create(
        path, key, data_capacity=capacity
    ) as container:
        container.create_file("/full.bin", persist=False)
        container.write_file("/full.bin", b"A" * capacity)

    with BlockVaultContainer.open(path, key) as container:
        container.write_file(
            "/full.bin", b"B" * (1024 * 1024), offset=0, persist=False
        )
        container.write_file(
            "/full.bin",
            b"C" * (1024 * 1024),
            offset=1024 * 1024,
            persist=False,
        )

    with BlockVaultContainer.open(path, key) as reopened:
        assert reopened.read_file(
            "/full.bin", length=LOGICAL_BLOCK_SIZE
        ) == b"B" * LOGICAL_BLOCK_SIZE
        assert reopened.read_file(
            "/full.bin", offset=1024 * 1024, length=LOGICAL_BLOCK_SIZE
        ) == b"C" * LOGICAL_BLOCK_SIZE


def test_wrong_profile_and_data_tampering_are_rejected(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "integrity.cpgv"
    with BlockVaultContainer.create(
        path, key, data_capacity=1024 * 1024
    ) as container:
        container.create_file("/proof.bin", persist=False)
        container.write_file("/proof.bin", b"proof")

    with pytest.raises(InvalidContainerError):
        BlockVaultContainer.open(path, master_key())

    with BlockVaultContainer.open(path, key) as container:
        physical = container._nodes[2].blocks[0][0]
    slot_offset = (
        HEADER_PREFIX.size
        + HEADER_AREA_SIZE
        + (METADATA_BLOCKS + physical) * PHYSICAL_SLOT_SIZE
    )
    with path.open("r+b") as stream:
        stream.seek(slot_offset + 21)
        original = stream.read(1)
        stream.seek(slot_offset + 21)
        stream.write(bytes([original[0] ^ 1]))

    with BlockVaultContainer.open(path, key) as reopened:
        with pytest.raises(InvalidContainerError):
            reopened.read_file("/proof.bin")


def test_large_sequential_file_round_trip(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "large.cpgv"
    payload = hashlib.sha512(b"Clever PGP").digest() * (128 * 1024)
    with BlockVaultContainer.create(
        path, key, data_capacity=16 * 1024 * 1024
    ) as container:
        container.create_file("/movie.bin", persist=False)
        for offset in range(0, len(payload), 1024 * 1024):
            chunk = payload[offset : offset + 1024 * 1024]
            container.write_file(
                "/movie.bin", chunk, offset=offset, persist=False
            )
        container.save()

    with BlockVaultContainer.open(path, key) as reopened:
        assert hashlib.sha256(reopened.read_file("/movie.bin")).digest() == hashlib.sha256(
            payload
        ).digest()
