from __future__ import annotations

from pathlib import Path

import pytest

from biopgp.core.block_volume import (
    LOGICAL_BLOCK_SIZE,
    MIN_LOGICAL_CAPACITY,
    BlockIntegrityError,
    BlockVolumeError,
    EncryptedBlockVolume,
)
from biopgp.core.hidden_volume import (
    HiddenBlockVolume,
    HiddenRegionProtectedVolume,
)
from biopgp.core.errors import ValidationError


MASTER_KEY = b"o" * 32
HIDDEN_KEY = b"h" * 32
STORAGE_FORMAT = "CLEVERPGP-WINDOWS-BLOCK-V1"


def create_cover(tmp_path: Path) -> EncryptedBlockVolume:
    return EncryptedBlockVolume.create(
        tmp_path / "hidden.cpgv",
        MASTER_KEY,
        logical_capacity=4 * MIN_LOGICAL_CAPACITY,
        storage_format=STORAGE_FORMAT,
    )


def test_hidden_blocks_round_trip_without_changing_outer_prefix(tmp_path: Path) -> None:
    cover = create_cover(tmp_path)
    outer_marker = b"outer" + bytes(LOGICAL_BLOCK_SIZE - len("outer"))
    cover.write_blocks(4, outer_marker)
    progress: list[tuple[int, int]] = []

    hidden = HiddenBlockVolume.create(
        cover,
        HIDDEN_KEY,
        logical_capacity=MIN_LOGICAL_CAPACITY,
        storage_format=STORAGE_FORMAT,
        progress=lambda completed, total: progress.append((completed, total)),
    )
    descriptor = hidden.descriptor
    payload = b"A" * LOGICAL_BLOCK_SIZE + b"B" * LOGICAL_BLOCK_SIZE
    hidden.write_blocks(3, payload)
    hidden.flush()

    assert hidden.read_blocks(3, 2) == payload
    assert cover.read_blocks(4, 1) == outer_marker
    assert descriptor.region_start_block + descriptor.region_block_count == (
        cover.block_count
    )
    assert progress[-1] == (hidden.block_count, hidden.block_count)

    hidden.close()
    reopened = HiddenBlockVolume.open(cover, HIDDEN_KEY, descriptor)
    assert reopened.read_blocks(3, 2) == payload
    reopened.close()
    cover.close()


def test_hidden_stream_crosses_cover_block_boundaries(tmp_path: Path) -> None:
    cover = create_cover(tmp_path)
    hidden = HiddenBlockVolume.create(
        cover,
        HIDDEN_KEY,
        logical_capacity=MIN_LOGICAL_CAPACITY,
        storage_format=STORAGE_FORMAT,
    )
    payload = b"1" * LOGICAL_BLOCK_SIZE + b"2" * LOGICAL_BLOCK_SIZE

    hidden.write_blocks(101, payload)

    assert hidden.read_blocks(101, 2) == payload
    assert hidden.read_blocks(100, 1) == bytes(LOGICAL_BLOCK_SIZE)
    assert hidden.read_blocks(103, 1) == bytes(LOGICAL_BLOCK_SIZE)
    hidden.close()
    cover.close()


def test_wrong_hidden_key_and_outer_overwrite_are_detected(tmp_path: Path) -> None:
    cover = create_cover(tmp_path)
    hidden = HiddenBlockVolume.create(
        cover,
        HIDDEN_KEY,
        logical_capacity=MIN_LOGICAL_CAPACITY,
        storage_format=STORAGE_FORMAT,
    )
    descriptor = hidden.descriptor
    hidden.close()

    wrong_key_view = HiddenBlockVolume.open(cover, b"x" * 32, descriptor)
    with pytest.raises(BlockIntegrityError):
        wrong_key_view.read_blocks(0, 1)
    wrong_key_view.close()

    cover.write_blocks(
        descriptor.region_start_block,
        b"x" * LOGICAL_BLOCK_SIZE,
    )
    damaged = HiddenBlockVolume.open(cover, HIDDEN_KEY, descriptor)
    with pytest.raises(BlockIntegrityError):
        damaged.read_blocks(0, 1)
    damaged.close()
    cover.close()


def test_outer_protection_latches_after_hidden_region_write(tmp_path: Path) -> None:
    cover = create_cover(tmp_path)
    hidden = HiddenBlockVolume.create(
        cover,
        HIDDEN_KEY,
        logical_capacity=MIN_LOGICAL_CAPACITY,
        storage_format=STORAGE_FORMAT,
    )
    descriptor = hidden.descriptor
    hidden.close()
    protected = HiddenRegionProtectedVolume(cover, descriptor)

    protected.write_blocks(2, b"a" * LOGICAL_BLOCK_SIZE)
    assert not protected.damage_prevented

    with pytest.raises(BlockVolumeError, match="защиты скрытого тома"):
        protected.write_blocks(
            descriptor.region_start_block,
            b"b" * LOGICAL_BLOCK_SIZE,
        )
    assert protected.damage_prevented

    with pytest.raises(BlockVolumeError, match="только для чтения"):
        protected.write_blocks(3, b"c" * LOGICAL_BLOCK_SIZE)
    assert protected.read_blocks(2, 1) == b"a" * LOGICAL_BLOCK_SIZE
    protected.close()
    cover.close()


def test_invalid_outer_write_does_not_change_protection_state(tmp_path: Path) -> None:
    cover = create_cover(tmp_path)
    hidden = HiddenBlockVolume.create(
        cover,
        HIDDEN_KEY,
        logical_capacity=MIN_LOGICAL_CAPACITY,
        storage_format=STORAGE_FORMAT,
    )
    descriptor = hidden.descriptor
    hidden.close()
    protected = HiddenRegionProtectedVolume(cover, descriptor)

    with pytest.raises(ValidationError, match="границы внешнего диска"):
        protected.write_blocks(-1, b"x" * LOGICAL_BLOCK_SIZE)

    assert not protected.damage_prevented
    protected.write_blocks(1, b"y" * LOGICAL_BLOCK_SIZE)
    protected.close()
    cover.close()


def test_hidden_capacity_reserves_nonce_and_authentication_overhead() -> None:
    required = HiddenBlockVolume.required_region_blocks(MIN_LOGICAL_CAPACITY)

    assert required > MIN_LOGICAL_CAPACITY // LOGICAL_BLOCK_SIZE
    assert required * LOGICAL_BLOCK_SIZE >= (
        MIN_LOGICAL_CAPACITY // LOGICAL_BLOCK_SIZE
    ) * (LOGICAL_BLOCK_SIZE + 40)
