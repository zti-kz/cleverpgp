from __future__ import annotations

import io

import pytest
from nacl import pwhash

from cleverpgp.core.errors import AuthenticationError, ValidationError
from cleverpgp.core.hidden_volume import HiddenVolumeDescriptor
from cleverpgp.core.opaque_volume_header import (
    BANK_SIZE,
    OPAQUE_HEADER_MAGIC,
    OPAQUE_HEADER_RESERVED_SIZE,
    ROLE_AREA_SIZE,
    HeaderKdfParameters,
    OpaqueVolumeHeader,
    OpaqueVolumeHeaderStore,
)


OUTER_PASSWORD = "outer correct horse battery staple"
HIDDEN_PASSWORD = "hidden correct horse battery staple"
NEW_OUTER_PASSWORD = "new outer correct horse battery staple"
NEW_HIDDEN_PASSWORD = "new hidden correct horse battery staple"
COVER_ID = b"v" * 16
COVER_KEY = b"c" * 32
HIDDEN_ID = b"i" * 16
HIDDEN_KEY = b"h" * 32


@pytest.fixture
def store() -> OpaqueVolumeHeaderStore:
    return OpaqueVolumeHeaderStore(
        HeaderKdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        )
    )


def outer_header() -> OpaqueVolumeHeader:
    return OpaqueVolumeHeader(
        role="outer",
        generation=1,
        cover_volume_id=COVER_ID,
        cover_key=COVER_KEY,
        cover_block_count=4096,
        label="Outer research disk",
        storage_format="CLEVERPGP-WINDOWS-BLOCK-V1",
        created_at="2026-08-23T03:00:00+00:00",
        outer_projection_block_count=3000,
    )


def hidden_header() -> OpaqueVolumeHeader:
    descriptor = HiddenVolumeDescriptor(
        volume_id=HIDDEN_ID,
        region_start_block=3000,
        region_block_count=259,
        hidden_block_count=256,
        label="Hidden research disk",
        storage_format="CLEVERPGP-WINDOWS-BLOCK-V1",
    )
    return OpaqueVolumeHeader(
        role="hidden",
        generation=1,
        cover_volume_id=COVER_ID,
        cover_key=COVER_KEY,
        cover_block_count=4096,
        label=descriptor.label,
        storage_format=descriptor.storage_format,
        created_at="2026-08-23T03:05:00+00:00",
        hidden_key=HIDDEN_KEY,
        hidden_descriptor=descriptor,
    )


def initialized_stream(
    store: OpaqueVolumeHeaderStore,
) -> io.BytesIO:
    stream = io.BytesIO()
    store.initialize(stream, OUTER_PASSWORD, outer_header())
    return stream


def test_outer_header_is_opaque_and_unlocks_by_password(
    store: OpaqueVolumeHeaderStore,
) -> None:
    stream = initialized_stream(store)
    raw = stream.getvalue()

    assert len(raw) == OPAQUE_HEADER_RESERVED_SIZE
    assert OPAQUE_HEADER_MAGIC not in raw
    assert b"Outer research disk" not in raw
    assert COVER_KEY not in raw

    unlocked = store.unlock(stream, OUTER_PASSWORD)
    assert unlocked == outer_header()


def test_hidden_password_selects_hidden_header_without_changing_outer_area(
    store: OpaqueVolumeHeaderStore,
) -> None:
    stream = initialized_stream(store)
    original_outer_area = stream.getvalue()[:ROLE_AREA_SIZE]
    progress: list[tuple[int, int]] = []

    store.add_hidden(
        stream,
        OUTER_PASSWORD,
        HIDDEN_PASSWORD,
        hidden_header(),
        progress=lambda completed, total: progress.append((completed, total)),
    )
    raw = stream.getvalue()

    assert raw[:ROLE_AREA_SIZE] == original_outer_area
    assert OPAQUE_HEADER_MAGIC not in raw
    assert b"Hidden research disk" not in raw
    assert HIDDEN_KEY not in raw
    assert store.unlock(stream, OUTER_PASSWORD).role == "outer"
    assert store.unlock(stream, HIDDEN_PASSWORD) == hidden_header()
    assert progress[-1] == (4, 4)


def test_wrong_password_and_absent_hidden_header_have_same_public_error(
    store: OpaqueVolumeHeaderStore,
) -> None:
    stream = initialized_stream(store)

    with pytest.raises(
        AuthenticationError,
        match="Неверный пароль или повреждён заголовок диска",
    ):
        store.unlock(stream, "wrong password is still long enough")


def test_one_corrupted_bank_falls_back_to_authenticated_copy(
    store: OpaqueVolumeHeaderStore,
) -> None:
    stream = initialized_stream(store)
    raw = bytearray(stream.getvalue())
    raw[BANK_SIZE // 2] ^= 1
    stream = io.BytesIO(raw)

    assert store.unlock(stream, OUTER_PASSWORD) == outer_header()

    raw = bytearray(stream.getvalue())
    raw[BANK_SIZE + BANK_SIZE // 2] ^= 1
    stream = io.BytesIO(raw)
    with pytest.raises(AuthenticationError):
        store.unlock(stream, OUTER_PASSWORD)


def test_hidden_password_must_differ_from_outer_password(
    store: OpaqueVolumeHeaderStore,
) -> None:
    stream = initialized_stream(store)

    with pytest.raises(ValidationError, match="должны различаться"):
        store.add_hidden(
            stream,
            OUTER_PASSWORD,
            OUTER_PASSWORD,
            hidden_header(),
        )


def test_hidden_header_must_reference_the_authenticated_cover(
    store: OpaqueVolumeHeaderStore,
) -> None:
    stream = initialized_stream(store)
    invalid = OpaqueVolumeHeader(
        role="hidden",
        generation=1,
        cover_volume_id=b"x" * 16,
        cover_key=COVER_KEY,
        cover_block_count=4096,
        label="Hidden research disk",
        storage_format="CLEVERPGP-WINDOWS-BLOCK-V1",
        created_at="2026-08-23T03:05:00+00:00",
        hidden_key=HIDDEN_KEY,
        hidden_descriptor=hidden_header().hidden_descriptor,
    )

    with pytest.raises(ValidationError, match="не относится"):
        store.add_hidden(
            stream,
            OUTER_PASSWORD,
            HIDDEN_PASSWORD,
            invalid,
        )


@pytest.mark.parametrize("header_factory", [outer_header, hidden_header])
def test_unlocked_header_round_trips_only_inside_protected_transfer(
    header_factory,
) -> None:
    header = header_factory()

    payload = OpaqueVolumeHeaderStore.serialize_for_protected_transfer(header)
    restored = OpaqueVolumeHeaderStore.deserialize_protected_transfer(payload)

    assert restored == header


def test_outer_password_changes_without_touching_hidden_role(
    store: OpaqueVolumeHeaderStore,
) -> None:
    stream = initialized_stream(store)
    store.add_hidden(
        stream,
        OUTER_PASSWORD,
        HIDDEN_PASSWORD,
        hidden_header(),
    )
    hidden_area_before = stream.getvalue()[ROLE_AREA_SIZE:]
    progress: list[tuple[int, int]] = []

    changed = store.change_password(
        stream,
        OUTER_PASSWORD,
        NEW_OUTER_PASSWORD,
        expected_volume_id=COVER_ID,
        progress=lambda completed, total: progress.append((completed, total)),
    )

    assert changed.role == "outer"
    assert changed.generation == 2
    assert stream.getvalue()[ROLE_AREA_SIZE:] == hidden_area_before
    assert store.unlock(stream, NEW_OUTER_PASSWORD) == changed
    assert store.unlock(stream, HIDDEN_PASSWORD) == hidden_header()
    with pytest.raises(AuthenticationError):
        store.unlock(stream, OUTER_PASSWORD)
    assert progress[-1][0] == progress[-1][1]


def test_password_change_rejects_password_of_other_role_without_writing(
    store: OpaqueVolumeHeaderStore,
) -> None:
    stream = initialized_stream(store)
    store.add_hidden(
        stream,
        OUTER_PASSWORD,
        HIDDEN_PASSWORD,
        hidden_header(),
    )
    before = stream.getvalue()

    with pytest.raises(ValidationError, match="уже открывает"):
        store.change_password(
            stream,
            OUTER_PASSWORD,
            HIDDEN_PASSWORD,
        )

    assert stream.getvalue() == before


def test_hidden_password_changes_without_touching_outer_role(
    store: OpaqueVolumeHeaderStore,
) -> None:
    stream = initialized_stream(store)
    store.add_hidden(
        stream,
        OUTER_PASSWORD,
        HIDDEN_PASSWORD,
        hidden_header(),
    )
    outer_area_before = stream.getvalue()[:ROLE_AREA_SIZE]

    changed = store.change_password(
        stream,
        HIDDEN_PASSWORD,
        NEW_HIDDEN_PASSWORD,
        expected_volume_id=HIDDEN_ID,
    )

    assert changed.role == "hidden"
    assert changed.generation == 2
    assert stream.getvalue()[:ROLE_AREA_SIZE] == outer_area_before
    assert store.unlock(stream, OUTER_PASSWORD) == outer_header()
    assert store.unlock(stream, NEW_HIDDEN_PASSWORD) == changed
    with pytest.raises(AuthenticationError):
        store.unlock(stream, HIDDEN_PASSWORD)


def test_password_change_requires_the_mounted_projection_identity(
    store: OpaqueVolumeHeaderStore,
) -> None:
    stream = initialized_stream(store)

    with pytest.raises(ValidationError, match="подключённому диску"):
        store.validate_password_change(
            stream,
            OUTER_PASSWORD,
            NEW_OUTER_PASSWORD,
            expected_volume_id=b"x" * 16,
        )


def test_interrupted_second_bank_write_keeps_new_password_usable(
    store: OpaqueVolumeHeaderStore,
) -> None:
    class InterruptedStream(io.BytesIO):
        interrupted = False

        def write(self, payload: bytes) -> int:
            if self.tell() == BANK_SIZE and not self.interrupted:
                self.interrupted = True
                super().write(payload[: len(payload) // 2])
                raise OSError("simulated interruption")
            return super().write(payload)

    original = initialized_stream(store)
    stream = InterruptedStream(original.getvalue())

    with pytest.raises(OSError, match="simulated interruption"):
        store.change_password(
            stream,
            OUTER_PASSWORD,
            NEW_OUTER_PASSWORD,
        )

    assert store.unlock(stream, NEW_OUTER_PASSWORD).role == "outer"


def test_interrupted_first_bank_write_keeps_old_password_usable(
    store: OpaqueVolumeHeaderStore,
) -> None:
    class InterruptedStream(io.BytesIO):
        interrupted = False

        def write(self, payload: bytes) -> int:
            if self.tell() == 0 and not self.interrupted:
                self.interrupted = True
                super().write(payload[: len(payload) // 2])
                raise OSError("simulated interruption")
            return super().write(payload)

    original = initialized_stream(store)
    stream = InterruptedStream(original.getvalue())

    with pytest.raises(OSError, match="simulated interruption"):
        store.change_password(
            stream,
            OUTER_PASSWORD,
            NEW_OUTER_PASSWORD,
        )

    assert store.unlock(stream, OUTER_PASSWORD).role == "outer"
