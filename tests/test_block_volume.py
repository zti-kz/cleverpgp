from __future__ import annotations

from pathlib import Path

import pytest
from nacl import secret, utils

from biopgp.core.block_volume import (
    HEADER_AREA_SIZE,
    HEADER_PREFIX,
    LOGICAL_BLOCK_SIZE,
    PHYSICAL_SLOT_SIZE,
    BlockIntegrityError,
    EncryptedBlockVolume,
    InvalidBlockVolumeError,
)


def master_key() -> bytes:
    return utils.random(secret.SecretBox.KEY_SIZE)


def test_block_volume_supports_independent_random_access(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "blocks.cpgv"
    capacity = 1024 * 1024
    progress: list[tuple[int, int]] = []

    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=capacity,
        label="Блочный диск",
        progress=lambda complete, total: progress.append((complete, total)),
    ) as volume:
        assert volume.logical_capacity == capacity
        assert volume.label == "Блочный диск"
        assert volume.read_blocks(0, 2) == bytes(2 * LOGICAL_BLOCK_SIZE)
        volume.write_blocks(3, b"A" * LOGICAL_BLOCK_SIZE)
        volume.write_blocks(8, b"B" * (2 * LOGICAL_BLOCK_SIZE))
        assert volume.read_blocks(3, 1) == b"A" * LOGICAL_BLOCK_SIZE
        assert volume.read_blocks(8, 2) == b"B" * (2 * LOGICAL_BLOCK_SIZE)

    assert progress[-1][0] == progress[-1][1]
    with EncryptedBlockVolume.open(path, key) as reopened:
        assert reopened.read_blocks(3, 1) == b"A" * LOGICAL_BLOCK_SIZE
        assert reopened.read_blocks(4, 1) == bytes(LOGICAL_BLOCK_SIZE)


def test_rewriting_one_block_does_not_rewrite_other_blocks(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "rewrite.cpgv"
    volume = EncryptedBlockVolume.create(
        path, key, logical_capacity=1024 * 1024
    )
    volume.close()
    before = path.read_bytes()

    with EncryptedBlockVolume.open(path, key) as reopened:
        reopened.write_blocks(7, b"changed".ljust(LOGICAL_BLOCK_SIZE, b"\0"))
    after = path.read_bytes()

    data_start = HEADER_PREFIX.size + HEADER_AREA_SIZE
    changed_start = data_start + 7 * PHYSICAL_SLOT_SIZE
    changed_end = changed_start + PHYSICAL_SLOT_SIZE
    assert before[:changed_start] == after[:changed_start]
    assert before[changed_end:] == after[changed_end:]
    assert before[changed_start:changed_end] != after[changed_start:changed_end]


def test_block_tampering_and_block_swaps_are_detected(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "integrity.cpgv"
    volume = EncryptedBlockVolume.create(
        path, key, logical_capacity=1024 * 1024
    )
    volume.close()

    data_start = HEADER_PREFIX.size + HEADER_AREA_SIZE
    with path.open("r+b") as stream:
        stream.seek(data_start)
        first = stream.read(PHYSICAL_SLOT_SIZE)
        second = stream.read(PHYSICAL_SLOT_SIZE)
        stream.seek(data_start)
        stream.write(second)
        stream.write(first)

    with EncryptedBlockVolume.open(path, key) as reopened:
        with pytest.raises(BlockIntegrityError):
            reopened.read_blocks(0, 1)


def test_old_ciphertext_cannot_be_replayed_in_a_new_write_context(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "replay.cpgv"
    with EncryptedBlockVolume.create(
        path, key, logical_capacity=1024 * 1024
    ) as volume:
        volume.write_blocks(
            5, b"old".ljust(LOGICAL_BLOCK_SIZE, b"!"), context=b"generation-one"
        )
        volume.flush()
        data_start = HEADER_PREFIX.size + HEADER_AREA_SIZE
        slot_offset = data_start + 5 * PHYSICAL_SLOT_SIZE
        with path.open("rb") as stream:
            stream.seek(slot_offset)
            old_slot = stream.read(PHYSICAL_SLOT_SIZE)
        volume.write_blocks(
            5, b"new".ljust(LOGICAL_BLOCK_SIZE, b"?"), context=b"generation-two"
        )
        volume.flush()

    with path.open("r+b") as stream:
        stream.seek(slot_offset)
        stream.write(old_slot)

    with EncryptedBlockVolume.open(path, key) as reopened:
        with pytest.raises(BlockIntegrityError):
            reopened.read_blocks(5, 1, context=b"generation-two")


def test_wrong_profile_and_header_tampering_are_rejected(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "header.cpgv"
    volume = EncryptedBlockVolume.create(
        path, key, logical_capacity=1024 * 1024
    )
    volume.close()

    with pytest.raises(InvalidBlockVolumeError):
        EncryptedBlockVolume.open(path, master_key())

    raw = bytearray(path.read_bytes())
    raw[HEADER_PREFIX.size + 20] ^= 1
    path.write_bytes(raw)
    with pytest.raises(InvalidBlockVolumeError):
        EncryptedBlockVolume.open(path, key)


def test_plaintext_is_absent_and_physical_overhead_is_explicit(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "layout.cpgv"
    capacity = 1024 * 1024
    marker = b"plaintext-sector-marker".ljust(LOGICAL_BLOCK_SIZE, b"!")

    with EncryptedBlockVolume.create(
        path, key, logical_capacity=capacity
    ) as volume:
        volume.write_blocks(1, marker)
        expected_size = EncryptedBlockVolume.physical_size(volume.block_count)

    assert path.stat().st_size == expected_size
    assert expected_size > capacity
    assert marker not in path.read_bytes()
