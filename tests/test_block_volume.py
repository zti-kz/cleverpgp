from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from nacl import secret, utils

from biopgp.core.block_volume import (
    HEADER_AREA_SIZE,
    HEADER_PREFIX,
    LOGICAL_BLOCK_SIZE,
    NONCE_SIZE,
    PHYSICAL_SLOT_SIZE,
    BlockIntegrityError,
    EncryptedBlockVolume,
    InvalidBlockVolumeError,
)
from biopgp.core.disk_crypto import (
    AES256_GCM,
    XCHACHA20_POLY1305,
    disk_cipher_available,
)
from biopgp.core.errors import ValidationError
from biopgp.core.mapped_stream import MappedFileStream


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
        assert volume.storage_format == "CLEVERPGP-AUTHENTICATED-BLOCKS-V2"
        assert volume.read_blocks(0, 2) == bytes(2 * LOGICAL_BLOCK_SIZE)
        volume.write_blocks(3, b"A" * LOGICAL_BLOCK_SIZE)
        volume.write_blocks(8, b"B" * (2 * LOGICAL_BLOCK_SIZE))
        assert volume.read_blocks(3, 1) == b"A" * LOGICAL_BLOCK_SIZE
        assert volume.read_blocks(8, 2) == b"B" * (2 * LOGICAL_BLOCK_SIZE)

    assert progress[-1][0] == progress[-1][1]
    with EncryptedBlockVolume.open(path, key) as reopened:
        assert reopened.read_blocks(3, 1) == b"A" * LOGICAL_BLOCK_SIZE
        assert reopened.read_blocks(4, 1) == bytes(LOGICAL_BLOCK_SIZE)


def test_portable_password_slot_opens_disk_with_another_profile_key(
    tmp_path: Path,
) -> None:
    original_profile_key = master_key()
    unrelated_profile_key = master_key()
    password = "correct portable disk password"
    path = tmp_path / "portable.cpgv"
    payload = b"portable".ljust(LOGICAL_BLOCK_SIZE, b"!")

    with EncryptedBlockVolume.create(
        path,
        original_profile_key,
        logical_capacity=1024 * 1024,
        password=password,
    ) as volume:
        volume.write_blocks(7, payload)

    with pytest.raises(InvalidBlockVolumeError):
        EncryptedBlockVolume.open(path, unrelated_profile_key)

    access_key = EncryptedBlockVolume.password_access_key(path, password)
    with EncryptedBlockVolume.open(path, access_key) as portable:
        assert portable.read_blocks(7, 1) == payload

    with pytest.raises(InvalidBlockVolumeError, match="Неверный пароль"):
        EncryptedBlockVolume.password_access_key(
            path,
            "wrong portable disk password",
        )


def test_portable_password_can_be_changed_without_reencrypting_data(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "password-change.cpgv"
    old_password = "old correct portable password"
    new_password = "new correct portable password"
    payload = b"unchanged data".ljust(LOGICAL_BLOCK_SIZE, b".")
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
        password=old_password,
    ) as volume:
        volume.write_blocks(9, payload)

    EncryptedBlockVolume.change_password(path, old_password, new_password)

    with pytest.raises(InvalidBlockVolumeError, match="Неверный пароль"):
        EncryptedBlockVolume.password_access_key(path, old_password)
    with EncryptedBlockVolume.open_with_password(path, new_password) as reopened:
        assert reopened.read_blocks(9, 1) == payload
    with EncryptedBlockVolume.open(path, key) as local_profile:
        assert local_profile.read_blocks(9, 1) == payload


@pytest.mark.skipif(
    not disk_cipher_available(AES256_GCM),
    reason="AES-256-GCM is not available on this processor",
)
def test_aes_disk_round_trip_and_detects_tampering(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "aes.cpgv"
    payload = b"AES disk".ljust(LOGICAL_BLOCK_SIZE, b".")
    volume = EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
        algorithm=AES256_GCM,
    )
    volume.write_blocks(3, payload)
    volume.close()

    reopened = EncryptedBlockVolume.open(path, key)
    assert reopened.algorithm == AES256_GCM
    assert reopened.read_blocks(3, 1) == payload
    reopened.resize(2 * 1024 * 1024)
    assert reopened.logical_capacity == 2 * 1024 * 1024
    assert reopened.read_blocks(3, 1) == payload
    reopened.close()

    offset = HEADER_PREFIX.size + HEADER_AREA_SIZE + 3 * PHYSICAL_SLOT_SIZE
    with path.open("r+b") as stream:
        stream.seek(offset + NONCE_SIZE + 7)
        original = stream.read(1)
        stream.seek(-1, 1)
        stream.write(bytes([original[0] ^ 1]))

    damaged = EncryptedBlockVolume.open(path, key)
    with pytest.raises(BlockIntegrityError):
        damaged.read_blocks(3, 1)
    damaged.close()


def test_mapped_winspd_io_persists_concurrent_authenticated_ranges(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "mapped.cpgv"
    ranges = [
        (index * 16, bytes([65 + index]) * (16 * LOGICAL_BLOCK_SIZE))
        for index in range(4)
    ]
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
    ) as volume:
        assert volume.enable_mapped_io()
        assert volume.enable_mapped_io()
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(lambda item: volume.write_blocks(*item), ranges))
        volume.flush()
        with ThreadPoolExecutor(max_workers=4) as executor:
            restored = list(
                executor.map(
                    lambda item: volume.read_blocks(
                        item[0],
                        len(item[1]) // LOGICAL_BLOCK_SIZE,
                    ),
                    ranges,
                )
            )
        assert restored == [payload for _address, payload in ranges]

    with EncryptedBlockVolume.open(path, key) as reopened:
        for address, payload in ranges:
            assert reopened.read_blocks(
                address,
                len(payload) // LOGICAL_BLOCK_SIZE,
            ) == payload


def test_contiguous_block_read_uses_one_backing_file_operation(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "coalesced-read.cpgv"
    volume = EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
    )

    class CountingStream:
        def __init__(self, delegate: object) -> None:
            self.delegate = delegate
            self.read_calls = 0

        def read(self, size: int = -1) -> bytes:
            self.read_calls += 1
            return self.delegate.read(size)  # type: ignore[attr-defined]

        def __getattr__(self, name: str) -> object:
            return getattr(self.delegate, name)

    tracked = CountingStream(volume._stream)
    volume._stream = tracked
    try:
        assert volume.read_blocks(0, 64) == bytes(64 * LOGICAL_BLOCK_SIZE)
        assert tracked.read_calls == 1
    finally:
        volume.close()


def test_mapped_io_failure_keeps_regular_ciphertext_stream(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "mapped-fallback.cpgv"
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
    ) as volume:
        with patch.object(MappedFileStream, "__init__", side_effect=OSError("map")):
            assert not volume.enable_mapped_io()
        payload = b"fallback".ljust(LOGICAL_BLOCK_SIZE, b"!")
        volume.write_blocks(9, payload)
        assert volume.read_blocks(9, 1) == payload


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


def test_block_volume_can_grow_without_changing_existing_data(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "grow.cpgv"
    old_capacity = 1024 * 1024
    new_capacity = 2 * old_capacity
    marker = b"existing-data".ljust(LOGICAL_BLOCK_SIZE, b"!")
    progress: list[tuple[int, int]] = []

    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=old_capacity,
    ) as volume:
        old_volume_id = volume.volume_id
        volume.write_blocks(volume.block_count - 1, marker)
        volume.flush()
        volume.resize(
            new_capacity,
            progress=lambda completed, total: progress.append((completed, total)),
        )

        assert volume.logical_capacity == new_capacity
        assert volume.volume_id == old_volume_id
        assert volume.read_blocks(old_capacity // LOGICAL_BLOCK_SIZE - 1, 1) == marker
        assert volume.read_blocks(old_capacity // LOGICAL_BLOCK_SIZE, 1) == bytes(
            LOGICAL_BLOCK_SIZE
        )
        volume.write_blocks(volume.block_count - 1, b"new".ljust(LOGICAL_BLOCK_SIZE, b"?"))

    assert progress[-1][0] == progress[-1][1]
    assert path.stat().st_size == EncryptedBlockVolume.physical_size(
        new_capacity // LOGICAL_BLOCK_SIZE
    )
    with EncryptedBlockVolume.open(path, key) as reopened:
        assert reopened.logical_capacity == new_capacity
        assert reopened.volume_id == old_volume_id
        assert reopened.read_blocks(old_capacity // LOGICAL_BLOCK_SIZE - 1, 1) == marker
        assert reopened.read_blocks(reopened.block_count - 1, 1).startswith(b"new")


def test_resize_refuses_shrink_unaligned_size_and_insufficient_space(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "resize-validation.cpgv"
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=2 * 1024 * 1024,
    ) as volume:
        with pytest.raises(ValidationError, match="Уменьшение"):
            volume.resize(1024 * 1024)
        with pytest.raises(ValidationError, match="кратен"):
            volume.resize(3 * 1024 * 1024 + 1)
        with patch(
            "biopgp.core.block_volume.shutil.disk_usage",
            return_value=SimpleNamespace(free=0),
        ):
            with pytest.raises(ValidationError, match="Недостаточно свободного места"):
                volume.resize(3 * 1024 * 1024)

        assert volume.logical_capacity == 2 * 1024 * 1024


def test_interrupted_resize_falls_back_to_last_committed_capacity(
    monkeypatch,
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "interrupted-grow.cpgv"
    old_capacity = 1024 * 1024
    marker = b"preserved".ljust(LOGICAL_BLOCK_SIZE, b".")
    volume = EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=old_capacity,
    )
    volume.write_blocks(2, marker)
    volume.flush()
    old_physical_size = path.stat().st_size
    original_descriptor = EncryptedBlockVolume.__dict__["_encrypt_block"]
    original_encrypt = EncryptedBlockVolume._encrypt_block
    first_new_block = volume.block_count

    def interrupted_encrypt(
        cls: type[EncryptedBlockVolume],
        plaintext: bytes,
        block_index: int,
        volume_id: bytes,
        volume_key: bytes,
        context: bytes = b"",
    ) -> bytes:
        del cls
        if block_index >= first_new_block + 256:
            raise OSError("simulated interruption")
        return original_encrypt(
            plaintext,
            block_index,
            volume_id,
            volume_key,
            context,
        )

    monkeypatch.setattr(
        EncryptedBlockVolume,
        "_encrypt_block",
        classmethod(interrupted_encrypt),
    )
    with pytest.raises(OSError, match="simulated interruption"):
        volume.resize(3 * 1024 * 1024)
    volume.close()

    assert path.stat().st_size > old_physical_size
    with EncryptedBlockVolume.open(path, key) as recovered:
        assert recovered.logical_capacity == old_capacity
        assert recovered.read_blocks(2, 1) == marker
        monkeypatch.setattr(
            EncryptedBlockVolume,
            "_encrypt_block",
            original_descriptor,
        )
        recovered.resize(2 * 1024 * 1024)
        assert recovered.logical_capacity == 2 * 1024 * 1024

    with EncryptedBlockVolume.open(path, key) as reopened:
        assert reopened.logical_capacity == 2 * 1024 * 1024
        assert reopened.read_blocks(2, 1) == marker


def test_unauthenticated_trailing_data_is_rejected(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "trailing-data.cpgv"
    volume = EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
    )
    volume.close()
    with path.open("ab") as stream:
        stream.write(b"unauthenticated-tail")

    with pytest.raises(InvalidBlockVolumeError, match="неаутентифицированные"):
        EncryptedBlockVolume.open(path, key)


def test_invalid_header_closes_the_underlying_file(tmp_path: Path) -> None:
    key = master_key()
    path = tmp_path / "invalid-header.cpgv"
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
    ):
        pass
    with path.open("r+b") as stream:
        stream.write(b"BROKEN!!")

    original_open = Path.open
    opened_streams: list[object] = []

    def tracked_open(candidate: Path, *args: object, **kwargs: object) -> object:
        stream = original_open(candidate, *args, **kwargs)
        opened_streams.append(stream)
        return stream

    with patch.object(Path, "open", tracked_open):
        with pytest.raises(InvalidBlockVolumeError, match="поддерживаемой версии"):
            EncryptedBlockVolume.open(path, key)

    assert opened_streams
    assert opened_streams[-1].closed


def test_completed_resize_cannot_be_rolled_back_by_truncating_file(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "resize-rollback.cpgv"
    old_capacity = 1024 * 1024
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=old_capacity,
    ) as volume:
        volume.resize(2 * old_capacity)

    with path.open("r+b") as stream:
        stream.truncate(
            EncryptedBlockVolume.physical_size(
                old_capacity // LOGICAL_BLOCK_SIZE
            )
        )

    with pytest.raises(InvalidBlockVolumeError, match="подтверждённому заголовку"):
        EncryptedBlockVolume.open(path, key)


@pytest.mark.skipif(
    not disk_cipher_available(AES256_GCM),
    reason="AES-256-GCM is not available on this processor",
)
def test_algorithm_conversion_is_atomic_and_preserves_plaintext(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "algorithm-conversion.cpgv"
    storage_format = "TEST-WINDOWS-BLOCKS"
    first = b"first-block".ljust(LOGICAL_BLOCK_SIZE, b"!")
    last = b"last-block".ljust(LOGICAL_BLOCK_SIZE, b"?")
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=2 * 1024 * 1024,
        label="Algorithm conversion",
        storage_format=storage_format,
        algorithm=XCHACHA20_POLY1305,
    ) as source:
        original_volume_id = source.volume_id
        source.write_blocks(0, first)
        source.write_blocks(source.block_count - 1, last)
        source.flush()
    before = path.read_bytes()
    progress: list[tuple[int, int]] = []

    result = EncryptedBlockVolume.convert_algorithm_atomic(
        path,
        key,
        AES256_GCM,
        required_storage_format=storage_format,
        progress=lambda completed, total: progress.append((completed, total)),
    )

    assert result == path.resolve()
    assert path.read_bytes() != before
    assert not tuple(tmp_path.glob(".algorithm-conversion.cpgv.algorithm-*.tmp"))
    assert progress[0][0] == 0
    assert progress[-1][0] == progress[-1][1]
    with EncryptedBlockVolume.open(path, key) as converted:
        assert converted.algorithm == AES256_GCM
        assert converted.storage_format == storage_format
        assert converted.label == "Algorithm conversion"
        assert converted.volume_id != original_volume_id
        assert converted.read_blocks(0, 1) == first
        assert converted.read_blocks(converted.block_count - 1, 1) == last


@pytest.mark.skipif(
    not disk_cipher_available(AES256_GCM),
    reason="AES-256-GCM is not available on this processor",
)
def test_interrupted_algorithm_conversion_keeps_original_image(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "interrupted-algorithm.cpgv"
    storage_format = "TEST-WINDOWS-BLOCKS"
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=2 * 1024 * 1024,
        storage_format=storage_format,
    ) as source:
        source.write_blocks(17, b"preserved".ljust(LOGICAL_BLOCK_SIZE, b"."))
        source.flush()
    before = path.read_bytes()

    def interrupt(completed: int, _total: int) -> None:
        if completed:
            raise OSError("simulated conversion interruption")

    with pytest.raises(OSError, match="simulated conversion interruption"):
        EncryptedBlockVolume.convert_algorithm_atomic(
            path,
            key,
            AES256_GCM,
            required_storage_format=storage_format,
            progress=interrupt,
        )

    assert path.read_bytes() == before
    assert not tuple(tmp_path.glob(".interrupted-algorithm.cpgv.algorithm-*.tmp"))
    with EncryptedBlockVolume.open(path, key) as reopened:
        assert reopened.algorithm == XCHACHA20_POLY1305
        assert reopened.read_blocks(17, 1).startswith(b"preserved")


@pytest.mark.skipif(
    not disk_cipher_available(AES256_GCM),
    reason="AES-256-GCM is not available on this processor",
)
def test_algorithm_conversion_verifies_every_written_block_before_replace(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "verify-algorithm.cpgv"
    storage_format = "TEST-WINDOWS-BLOCKS"
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
        storage_format=storage_format,
    ):
        pass
    before = path.read_bytes()
    original_open = EncryptedBlockVolume.open

    def corrupt_replacement(
        candidate: Path,
        selected_key: bytes,
    ) -> EncryptedBlockVolume:
        selected = Path(candidate)
        if ".algorithm-" in selected.name:
            with selected.open("r+b") as stream:
                stream.seek(HEADER_PREFIX.size + HEADER_AREA_SIZE + NONCE_SIZE)
                value = stream.read(1)
                stream.seek(-1, 1)
                stream.write(bytes([value[0] ^ 1]))
        return original_open(selected, selected_key)

    with patch.object(
        EncryptedBlockVolume,
        "open",
        side_effect=corrupt_replacement,
    ):
        with pytest.raises(BlockIntegrityError):
            EncryptedBlockVolume.convert_algorithm_atomic(
                path,
                key,
                AES256_GCM,
                required_storage_format=storage_format,
            )

    assert path.read_bytes() == before
    assert not tuple(tmp_path.glob(".verify-algorithm.cpgv.algorithm-*.tmp"))


def test_algorithm_conversion_refuses_wrong_format_and_insufficient_space(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "algorithm-validation.cpgv"
    storage_format = "TEST-WINDOWS-BLOCKS"
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
        storage_format=storage_format,
    ):
        pass
    before = path.read_bytes()

    with pytest.raises(ValidationError, match="типа"):
        EncryptedBlockVolume.convert_algorithm_atomic(
            path,
            key,
            AES256_GCM,
            required_storage_format="ANOTHER-FORMAT",
        )
    with patch(
        "biopgp.core.block_volume.shutil.disk_usage",
        return_value=SimpleNamespace(free=0),
    ):
        with pytest.raises(ValidationError, match="свободного места"):
            EncryptedBlockVolume.convert_algorithm_atomic(
                path,
                key,
                AES256_GCM,
                required_storage_format=storage_format,
            )

    assert path.read_bytes() == before
    assert not tuple(tmp_path.glob(".*.algorithm-*.tmp"))


def test_algorithm_conversion_noop_does_not_rewrite_container(
    tmp_path: Path,
) -> None:
    key = master_key()
    path = tmp_path / "same-algorithm.cpgv"
    storage_format = "TEST-WINDOWS-BLOCKS"
    with EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
        storage_format=storage_format,
    ):
        pass
    before = path.read_bytes()
    progress: list[tuple[int, int]] = []

    EncryptedBlockVolume.convert_algorithm_atomic(
        path,
        key,
        XCHACHA20_POLY1305,
        required_storage_format=storage_format,
        progress=lambda completed, total: progress.append((completed, total)),
    )

    assert path.read_bytes() == before
    assert progress == [(1, 1)]
