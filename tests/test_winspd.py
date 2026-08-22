from __future__ import annotations

import ctypes
from pathlib import Path

from nacl import secret, utils

from biopgp.core.block_volume import LOGICAL_BLOCK_SIZE, EncryptedBlockVolume
from biopgp.core.winspd import (
    SCSISTAT_GOOD,
    Partition,
    StorageUnitInterface,
    StorageUnitParams,
    StorageUnitStatus,
    UnmapDescriptor,
    WinSpdBlockDevice,
    initialize_windows_partition,
)


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
