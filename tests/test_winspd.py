from __future__ import annotations

import ctypes
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from nacl import pwhash, secret, utils

from cleverpgp.core.block_volume import LOGICAL_BLOCK_SIZE, EncryptedBlockVolume
from cleverpgp.core.errors import OutputExistsError
from cleverpgp.core.opaque_block_volume import OpaqueBlockVolume
from cleverpgp.core.opaque_volume_header import (
    HeaderKdfParameters,
    OpaqueVolumeHeaderStore,
)
from cleverpgp.core.winspd import (
    DEFAULT_DISPATCHER_THREADS,
    DEFAULT_MAX_TRANSFER_LENGTH,
    SCSISTAT_GOOD,
    Partition,
    StorageUnitInterface,
    StorageUnitParams,
    StorageUnitStatus,
    UnmapDescriptor,
    WinSpdBlockDevice,
    WinSpdError,
    WinSpdLibrary,
    WINDOWS_BLOCK_STORAGE_FORMAT,
    convert_windows_block_volume_algorithm,
    create_hidden_windows_block_volume,
    initialize_windows_partition,
    open_windows_block_volume,
    resize_windows_block_volume,
)
from cleverpgp.core.disk_crypto import AES256_GCM, disk_cipher_available


class UnusedLibrary:
    pass


class PartitionLibrary:
    def __init__(self) -> None:
        self.partitions: list[Partition] = []

    def define_partition_table(self, partitions: list[Partition]) -> bytes:
        self.partitions = partitions
        mbr = bytearray(512)
        mbr[510:512] = b"\x55\xaa"
        return bytes(mbr)


class MemoryVolume:
    logical_capacity = 32 * 1024 * 1024
    block_count = logical_capacity // LOGICAL_BLOCK_SIZE

    def __init__(self) -> None:
        self.first_block = bytes(LOGICAL_BLOCK_SIZE)
        self.flushed = False

    def read_blocks(self, block_address: int, block_count: int) -> bytes:
        assert (block_address, block_count) == (0, 1)
        return self.first_block

    def write_blocks(self, block_address: int, payload: bytes) -> None:
        assert block_address == 0
        self.first_block = payload

    def flush(self) -> None:
        self.flushed = True


def make_device(tmp_path: Path) -> tuple[EncryptedBlockVolume, WinSpdBlockDevice]:
    volume = EncryptedBlockVolume.create(
        tmp_path / "winspd.cpgv",
        utils.random(secret.SecretBox.KEY_SIZE),
        logical_capacity=1024 * 1024,
    )
    return volume, WinSpdBlockDevice(
        volume,
        library=UnusedLibrary(),  # type: ignore[arg-type]
        pipe_name=r"\\.\pipe\cleverpgp-test",
    )


def test_winspd_structures_match_official_abi() -> None:
    assert ctypes.sizeof(StorageUnitParams) == 128
    assert ctypes.sizeof(StorageUnitStatus) == 32
    assert ctypes.sizeof(UnmapDescriptor) == 16
    assert ctypes.sizeof(Partition) == 24
    assert ctypes.sizeof(StorageUnitInterface) == ctypes.sizeof(ctypes.c_void_p) * 16


def test_winspd_dispatcher_uses_bounded_threads_for_python_provider() -> None:
    start_dispatcher = Mock(return_value=0)
    library = WinSpdLibrary.__new__(WinSpdLibrary)
    library._dll = SimpleNamespace(
        SpdStorageUnitStartDispatcher=start_dispatcher,
    )
    storage_unit = ctypes.c_void_p(123)

    library.start(storage_unit)

    start_dispatcher.assert_called_once_with(
        storage_unit,
        DEFAULT_DISPATCHER_THREADS,
    )


def test_winspd_uses_bounded_transfer_buffers_for_python_provider(
    tmp_path: Path,
) -> None:
    volume, device = make_device(tmp_path)
    try:
        assert DEFAULT_MAX_TRANSFER_LENGTH == 64 * 1024
        assert device._params.MaxTransferLength == DEFAULT_MAX_TRANSFER_LENGTH
    finally:
        volume.close()


def test_windows_partition_is_initialized_inside_encrypted_blocks() -> None:
    volume = MemoryVolume()
    library = PartitionLibrary()

    initialize_windows_partition(  # type: ignore[arg-type]
        volume,
        library,  # type: ignore[arg-type]
    )

    partition = library.partitions[0]
    assert partition.Type == 7
    assert partition.BlockAddress * LOGICAL_BLOCK_SIZE == 1024 * 1024
    assert partition.BlockCount == volume.block_count - partition.BlockAddress
    assert volume.first_block[510:512] == b"\x55\xaa"
    assert volume.flushed


def test_callbacks_read_write_flush_and_unmap(tmp_path: Path) -> None:
    volume, device = make_device(tmp_path)
    try:
        assert bytes(device._params.Guid) == uuid.UUID(bytes=volume.volume_id).bytes_le
        status = StorageUnitStatus()
        payload = b"sector-data".ljust(LOGICAL_BLOCK_SIZE, b"!")
        source = ctypes.create_string_buffer(payload)
        assert device._write(0, ctypes.addressof(source), 4, 1, 1, ctypes.pointer(status))
        assert status.ScsiStatus == SCSISTAT_GOOD

        target = ctypes.create_string_buffer(LOGICAL_BLOCK_SIZE)
        assert device._read(0, ctypes.addressof(target), 4, 1, 0, ctypes.pointer(status))
        assert status.ScsiStatus == SCSISTAT_GOOD
        assert target.raw == payload

        descriptors = (UnmapDescriptor * 1)(UnmapDescriptor(4, 1, 0))
        assert device._unmap(0, descriptors, 1, ctypes.pointer(status))
        assert status.ScsiStatus == SCSISTAT_GOOD
        assert volume.read_blocks(4, 1) == bytes(LOGICAL_BLOCK_SIZE)
    finally:
        volume.close()


def test_winspd_callbacks_accept_v4_opaque_block_session(tmp_path: Path) -> None:
    header_store = OpaqueVolumeHeaderStore(
        HeaderKdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        )
    )
    volume = OpaqueBlockVolume.create_outer(
        tmp_path / "winspd-v4.cpgv",
        "outer correct horse battery staple",
        logical_capacity=1024 * 1024,
        storage_format=WINDOWS_BLOCK_STORAGE_FORMAT,
        header_store=header_store,
    )
    device = WinSpdBlockDevice(
        volume,
        library=UnusedLibrary(),  # type: ignore[arg-type]
        pipe_name=r"\\.\pipe\cleverpgp-v4-test",
    )
    try:
        status = StorageUnitStatus()
        payload = b"opaque-v4".ljust(LOGICAL_BLOCK_SIZE, b"!")
        source = ctypes.create_string_buffer(payload)
        assert device._write(
            0,
            ctypes.addressof(source),
            5,
            1,
            1,
            ctypes.pointer(status),
        )
        assert status.ScsiStatus == SCSISTAT_GOOD

        target = ctypes.create_string_buffer(LOGICAL_BLOCK_SIZE)
        assert device._read(
            0,
            ctypes.addressof(target),
            5,
            1,
            0,
            ctypes.pointer(status),
        )
        assert status.ScsiStatus == SCSISTAT_GOOD
        assert target.raw == payload
    finally:
        volume.close()


def test_callback_reports_out_of_range_instead_of_escaping(tmp_path: Path) -> None:
    volume, device = make_device(tmp_path)
    try:
        status = StorageUnitStatus()
        target = ctypes.create_string_buffer(LOGICAL_BLOCK_SIZE)
        assert device._read(
            0,
            ctypes.addressof(target),
            volume.block_count,
            1,
            0,
            ctypes.pointer(status),
        )
        assert status.ScsiStatus != SCSISTAT_GOOD
        assert device.last_error is not None
    finally:
        volume.close()


def test_windows_backend_rejects_a_generic_block_volume(tmp_path: Path) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    path = tmp_path / "generic.cpgv"
    volume = EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
    )
    volume.close()

    with pytest.raises(WinSpdError):
        open_windows_block_volume(path, key)


def test_windows_backend_opens_its_explicit_storage_format(tmp_path: Path) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    path = tmp_path / "windows.cpgv"
    volume = EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=1024 * 1024,
        storage_format=WINDOWS_BLOCK_STORAGE_FORMAT,
    )
    volume.close()

    with open_windows_block_volume(path, key) as reopened:
        assert reopened.storage_format == WINDOWS_BLOCK_STORAGE_FORMAT


def test_windows_backend_can_grow_closed_container(tmp_path: Path) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    path = tmp_path / "grow-windows.cpgv"
    original_capacity = 32 * 1024 * 1024
    volume = EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=original_capacity,
        storage_format=WINDOWS_BLOCK_STORAGE_FORMAT,
    )
    marker = b"partition-data".ljust(LOGICAL_BLOCK_SIZE, b"!")
    volume.write_blocks(0, marker)
    volume.close()
    progress: list[tuple[int, int]] = []

    result = resize_windows_block_volume(
        path,
        key,
        logical_capacity=40 * 1024 * 1024,
        progress=lambda completed, total: progress.append((completed, total)),
    )

    assert result == 40 * 1024 * 1024
    assert progress[-1][0] == progress[-1][1]
    with open_windows_block_volume(path, key) as reopened:
        assert reopened.logical_capacity == 40 * 1024 * 1024
        assert reopened.read_blocks(0, 1) == marker


@pytest.mark.skipif(
    not disk_cipher_available(AES256_GCM),
    reason="AES-256-GCM is not available on this processor",
)
def test_windows_backend_can_atomically_change_algorithm(tmp_path: Path) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    path = tmp_path / "convert-windows.cpgv"
    marker = b"partition-and-files".ljust(LOGICAL_BLOCK_SIZE, b"!")
    volume = EncryptedBlockVolume.create(
        path,
        key,
        logical_capacity=32 * 1024 * 1024,
        storage_format=WINDOWS_BLOCK_STORAGE_FORMAT,
    )
    volume.write_blocks(9, marker)
    volume.close()

    result = convert_windows_block_volume_algorithm(
        path,
        key,
        algorithm=AES256_GCM,
    )

    assert result == path.resolve()
    with open_windows_block_volume(path, key) as reopened:
        assert reopened.algorithm == AES256_GCM
        assert reopened.read_blocks(9, 1) == marker


def test_hidden_windows_image_prepares_both_partition_views(
    tmp_path: Path,
) -> None:
    path = tmp_path / "hidden-windows.cpgv"
    store = OpaqueVolumeHeaderStore(
        HeaderKdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        )
    )
    library = PartitionLibrary()
    progress: list[tuple[int, int]] = []

    headers = create_hidden_windows_block_volume(
        path,
        "outer correct horse battery staple",
        "hidden correct horse battery staple",
        outer_capacity=66 * 1024 * 1024,
        hidden_capacity=32 * 1024 * 1024,
        library=library,  # type: ignore[arg-type]
        header_store=store,
        progress=lambda completed, total: progress.append((completed, total)),
    )

    assert headers.outer.role == "outer"
    assert headers.hidden.role == "hidden"
    assert progress[-1] == (100, 100)
    with OpaqueBlockVolume.open_with_header(
        path,
        headers.outer,
        protected_hidden_descriptor=headers.hidden.hidden_descriptor,
    ) as outer:
        assert outer.read_blocks(0, 1)[510:512] == b"\x55\xaa"
        assert not outer.damage_prevented
    with OpaqueBlockVolume.open_with_header(path, headers.hidden) as hidden:
        assert hidden.read_blocks(0, 1)[510:512] == b"\x55\xaa"


def test_hidden_windows_image_is_removed_when_partition_creation_fails(
    tmp_path: Path,
) -> None:
    path = tmp_path / "failed-hidden-windows.cpgv"
    store = OpaqueVolumeHeaderStore(
        HeaderKdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        )
    )

    class FailingPartitionLibrary(PartitionLibrary):
        def define_partition_table(self, partitions: list[Partition]) -> bytes:
            del partitions
            raise RuntimeError("partition failure")

    with pytest.raises(RuntimeError, match="partition failure"):
        create_hidden_windows_block_volume(
            path,
            "outer correct horse battery staple",
            "hidden correct horse battery staple",
            outer_capacity=66 * 1024 * 1024,
            hidden_capacity=32 * 1024 * 1024,
            library=FailingPartitionLibrary(),  # type: ignore[arg-type]
            header_store=store,
        )

    assert not path.exists()


def test_hidden_windows_creation_never_deletes_existing_container(
    tmp_path: Path,
) -> None:
    path = tmp_path / "existing-hidden-windows.cpgv"
    original = b"existing user container"
    path.write_bytes(original)
    store = OpaqueVolumeHeaderStore(
        HeaderKdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        )
    )

    with pytest.raises(OutputExistsError):
        create_hidden_windows_block_volume(
            path,
            "outer correct horse battery staple",
            "hidden correct horse battery staple",
            outer_capacity=66 * 1024 * 1024,
            hidden_capacity=32 * 1024 * 1024,
            library=PartitionLibrary(),  # type: ignore[arg-type]
            header_store=store,
        )

    assert path.read_bytes() == original
