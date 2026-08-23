from __future__ import annotations

from pathlib import Path

import pytest
from nacl import pwhash

from biopgp.core.block_volume import (
    LOGICAL_BLOCK_SIZE,
    MIN_LOGICAL_CAPACITY,
    BlockIntegrityError,
    BlockVolumeError,
)
from biopgp.core.errors import AuthenticationError
from biopgp.core.hidden_volume import HiddenBlockVolume
from biopgp.core.opaque_block_volume import (
    OPAQUE_BLOCK_AAD,
    OpaqueBlockVolume,
    OpaqueCoverBlockVolume,
)
from biopgp.core.opaque_volume_header import (
    OPAQUE_HEADER_MAGIC,
    HeaderKdfParameters,
    OpaqueVolumeHeaderStore,
)


OUTER_PASSWORD = "outer correct horse battery staple"
HIDDEN_PASSWORD = "hidden correct horse battery staple"
STORAGE_FORMAT = "CLEVERPGP-WINDOWS-BLOCK-V1"


@pytest.fixture
def header_store() -> OpaqueVolumeHeaderStore:
    return OpaqueVolumeHeaderStore(
        HeaderKdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        )
    )


def create_outer(
    tmp_path: Path,
    header_store: OpaqueVolumeHeaderStore,
):
    return OpaqueBlockVolume.create_outer(
        tmp_path / "stealth.cpgv",
        OUTER_PASSWORD,
        logical_capacity=4 * MIN_LOGICAL_CAPACITY,
        label="Outer private disk",
        storage_format=STORAGE_FORMAT,
        header_store=header_store,
    )


def test_v4_outer_volume_is_opaque_and_random_access(
    tmp_path: Path,
    header_store: OpaqueVolumeHeaderStore,
) -> None:
    progress: list[tuple[int, int]] = []
    session = OpaqueBlockVolume.create_outer(
        tmp_path / "stealth.cpgv",
        OUTER_PASSWORD,
        logical_capacity=MIN_LOGICAL_CAPACITY,
        label="Outer private disk",
        storage_format=STORAGE_FORMAT,
        header_store=header_store,
        progress=lambda completed, total: progress.append((completed, total)),
    )
    path = session.path
    payload = b"A" * LOGICAL_BLOCK_SIZE + b"B" * LOGICAL_BLOCK_SIZE
    session.write_blocks(8, payload)
    session.close()

    raw = path.read_bytes()
    assert len(raw) == OpaqueCoverBlockVolume.physical_size(
        MIN_LOGICAL_CAPACITY // LOGICAL_BLOCK_SIZE
    )
    assert OPAQUE_HEADER_MAGIC not in raw
    assert OPAQUE_BLOCK_AAD not in raw
    assert b"Outer private disk" not in raw
    assert progress[-1][0] == progress[-1][1]

    reopened = OpaqueBlockVolume.open(
        path,
        OUTER_PASSWORD,
        header_store=header_store,
    )
    assert reopened.role == "outer"
    assert reopened.read_blocks(8, 2) == payload
    reopened.close()


def test_v4_wrong_password_is_rejected(
    tmp_path: Path,
    header_store: OpaqueVolumeHeaderStore,
) -> None:
    session = create_outer(tmp_path, header_store)
    path = session.path
    session.close()

    with pytest.raises(AuthenticationError):
        OpaqueBlockVolume.open(
            path,
            "wrong password is still long enough",
            header_store=header_store,
        )


def test_authenticated_header_opens_without_forwarding_password(
    tmp_path: Path,
    header_store: OpaqueVolumeHeaderStore,
) -> None:
    session = create_outer(tmp_path, header_store)
    path = session.path
    session.close()
    with path.open("rb") as stream:
        header = header_store.unlock(stream, OUTER_PASSWORD)

    reopened = OpaqueBlockVolume.open_with_header(path, header)

    assert reopened.role == "outer"
    reopened.write_blocks(3, b"direct" + bytes(LOGICAL_BLOCK_SIZE - 6))
    assert reopened.read_blocks(3, 1).startswith(b"direct")
    reopened.close()


def test_v4_session_supports_mapped_ciphertext_io(
    tmp_path: Path,
    header_store: OpaqueVolumeHeaderStore,
) -> None:
    session = create_outer(tmp_path, header_store)
    path = session.path
    payload = b"mapped-v4".ljust(8 * LOGICAL_BLOCK_SIZE, b"!")

    assert session.enable_mapped_io()
    session.write_blocks(32, payload)
    session.flush()
    assert session.read_blocks(32, 8) == payload
    session.close()

    reopened = OpaqueBlockVolume.open(
        path,
        OUTER_PASSWORD,
        header_store=header_store,
    )
    assert reopened.read_blocks(32, 8) == payload
    reopened.close()


def test_hidden_password_opens_nested_authenticated_blocks(
    tmp_path: Path,
    header_store: OpaqueVolumeHeaderStore,
) -> None:
    outer = create_outer(tmp_path, header_store)
    path = outer.path
    outer_marker = b"outer" + bytes(LOGICAL_BLOCK_SIZE - 5)
    outer.write_blocks(4, outer_marker)
    cover_blocks = outer.block_count
    outer.close()
    region_blocks = HiddenBlockVolume.required_region_blocks(
        MIN_LOGICAL_CAPACITY
    )

    OpaqueBlockVolume.add_hidden_in_verified_free_region(
        path,
        OUTER_PASSWORD,
        HIDDEN_PASSWORD,
        logical_capacity=MIN_LOGICAL_CAPACITY,
        region_start_block=cover_blocks - region_blocks,
        label="Hidden private disk",
        storage_format=STORAGE_FORMAT,
        header_store=header_store,
    )

    hidden = OpaqueBlockVolume.open(
        path,
        HIDDEN_PASSWORD,
        header_store=header_store,
    )
    assert hidden.role == "hidden"
    assert hidden.label == "Hidden private disk"
    hidden.write_blocks(7, b"hidden" + bytes(LOGICAL_BLOCK_SIZE - 6))
    assert hidden.read_blocks(7, 1).startswith(b"hidden")
    hidden.close()

    outer = OpaqueBlockVolume.open(
        path,
        OUTER_PASSWORD,
        header_store=header_store,
    )
    assert outer.role == "outer"
    assert outer.read_blocks(4, 1) == outer_marker
    outer.close()


def test_outer_protection_rejects_hidden_region_writes(
    tmp_path: Path,
    header_store: OpaqueVolumeHeaderStore,
) -> None:
    outer = create_outer(tmp_path, header_store)
    path = outer.path
    cover_blocks = outer.block_count
    outer.close()
    region_blocks = HiddenBlockVolume.required_region_blocks(
        MIN_LOGICAL_CAPACITY
    )
    protected_start = cover_blocks - region_blocks
    OpaqueBlockVolume.add_hidden_in_verified_free_region(
        path,
        OUTER_PASSWORD,
        HIDDEN_PASSWORD,
        logical_capacity=MIN_LOGICAL_CAPACITY,
        region_start_block=protected_start,
        storage_format=STORAGE_FORMAT,
        header_store=header_store,
    )

    protected = OpaqueBlockVolume.open_outer_with_hidden_protection(
        path,
        OUTER_PASSWORD,
        HIDDEN_PASSWORD,
        header_store=header_store,
    )
    protected.write_blocks(2, b"a" * LOGICAL_BLOCK_SIZE)
    with pytest.raises(BlockVolumeError, match="защиты скрытого тома"):
        protected.write_blocks(protected_start, b"b" * LOGICAL_BLOCK_SIZE)
    assert protected.damage_prevented
    with pytest.raises(BlockVolumeError, match="только для чтения"):
        protected.write_blocks(3, b"c" * LOGICAL_BLOCK_SIZE)
    protected.close()


def test_v4_cover_tampering_is_detected(
    tmp_path: Path,
    header_store: OpaqueVolumeHeaderStore,
) -> None:
    session = create_outer(tmp_path, header_store)
    path = session.path
    session.close()
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(raw)

    reopened = OpaqueBlockVolume.open(
        path,
        OUTER_PASSWORD,
        header_store=header_store,
    )
    with pytest.raises(BlockIntegrityError):
        reopened.read_blocks(reopened.block_count - 1, 1)
    reopened.close()
