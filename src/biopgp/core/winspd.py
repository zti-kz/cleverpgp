from __future__ import annotations

import ctypes
import os
import struct
import sys
import threading
import uuid
from collections.abc import Iterable
from pathlib import Path

from biopgp.core.block_volume import LOGICAL_BLOCK_SIZE, EncryptedBlockVolume
from biopgp.core.errors import ValidationError

ERROR_SUCCESS = 0
SCSISTAT_GOOD = 0
SCSISTAT_CHECK_CONDITION = 2
SCSI_SENSE_MEDIUM_ERROR = 3
SCSI_SENSE_HARDWARE_ERROR = 4
SCSI_SENSE_ILLEGAL_REQUEST = 5
SCSI_ADSENSE_WRITE_ERROR = 0x0C
SCSI_ADSENSE_UNRECOVERED_ERROR = 0x11
SCSI_ADSENSE_ILLEGAL_BLOCK = 0x21
SCSI_ADSENSE_INTERNAL_TARGET_FAILURE = 0x44

FLAG_CACHE_SUPPORTED = 0x00000002
FLAG_UNMAP_SUPPORTED = 0x00000004
DEFAULT_MAX_TRANSFER_LENGTH = 1024 * 1024
MIN_WINDOWS_DISK_CAPACITY = 32 * 1024 * 1024


class WinSpdError(RuntimeError):
    """WinSpd could not expose or service the encrypted block device."""


class StorageUnitParams(ctypes.Structure):
    _fields_ = [
        ("Guid", ctypes.c_ubyte * 16),
        ("BlockCount", ctypes.c_uint64),
        ("BlockLength", ctypes.c_uint32),
        ("ProductId", ctypes.c_ubyte * 16),
        ("ProductRevisionLevel", ctypes.c_ubyte * 4),
        ("DeviceType", ctypes.c_ubyte),
        ("Flags", ctypes.c_uint32),
        ("MaxTransferLength", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint64 * 8),
    ]


class StorageUnitStatus(ctypes.Structure):
    _fields_ = [
        ("ScsiStatus", ctypes.c_ubyte),
        ("SenseKey", ctypes.c_ubyte),
        ("ASC", ctypes.c_ubyte),
        ("ASCQ", ctypes.c_ubyte),
        ("Information", ctypes.c_uint64),
        ("ReservedCSI", ctypes.c_uint64),
        ("ReservedSKS", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
    ]


class UnmapDescriptor(ctypes.Structure):
    _fields_ = [
        ("BlockAddress", ctypes.c_uint64),
        ("BlockCount", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class Partition(ctypes.Structure):
    _fields_ = [
        ("Type", ctypes.c_ubyte),
        ("Active", ctypes.c_ubyte),
        ("BlockAddress", ctypes.c_uint64),
        ("BlockCount", ctypes.c_uint64),
    ]


READ_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_ubyte,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.c_uint32,
    ctypes.c_ubyte,
    ctypes.POINTER(StorageUnitStatus),
)
WRITE_CALLBACK = READ_CALLBACK
FLUSH_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_ubyte,
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.c_uint32,
    ctypes.POINTER(StorageUnitStatus),
)
UNMAP_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_ubyte,
    ctypes.c_void_p,
    ctypes.POINTER(UnmapDescriptor),
    ctypes.c_uint32,
    ctypes.POINTER(StorageUnitStatus),
)


class StorageUnitInterface(ctypes.Structure):
    _fields_ = [
        ("Read", READ_CALLBACK),
        ("Write", WRITE_CALLBACK),
        ("Flush", FLUSH_CALLBACK),
        ("Unmap", UNMAP_CALLBACK),
        ("Reserved", ctypes.c_void_p * 12),
    ]


def _set_fixed_bytes(target: object, value: bytes) -> None:
    if len(value) > len(target):
        raise ValueError("WinSpd text field is too long.")
    for index in range(len(target)):
        target[index] = value[index] if index < len(value) else 0


def _candidate_dll_paths() -> Iterable[Path]:
    override = os.environ.get("CLEVERPGP_WINSPD_DLL")
    if override:
        yield Path(override).expanduser()

    executable_dir = Path(sys.executable).resolve().parent
    architecture = "x64" if struct.calcsize("P") == 8 else "x86"
    yield executable_dir / f"winspd-{architecture}.dll"

    for environment_name in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(environment_name)
        if root:
            yield Path(root) / "WinSpd" / "bin" / f"winspd-{architecture}.dll"
            yield Path(root) / "WinSpd" / "sys" / f"winspd-{architecture}.dll"


def _default_dll_name() -> str:
    architecture = "x64" if struct.calcsize("P") == 8 else "x86"
    return f"winspd-{architecture}.dll"


class WinSpdLibrary:
    """Small, typed binding to the official WinSpd user-mode library."""

    def __init__(self, dll_path: Path | None = None) -> None:
        selected = Path(dll_path).expanduser().resolve() if dll_path else None
        if selected is None:
            selected = next(
                (path.resolve() for path in _candidate_dll_paths() if path.is_file()),
                None,
            )
        try:
            self._dll = ctypes.CDLL(str(selected) if selected else _default_dll_name())
        except OSError as error:
            raise WinSpdError(
                "Компонент системного диска WinSpd не установлен."
            ) from error
        self.path = selected
        self._configure_api()

    def _configure_api(self) -> None:
        self._dll.SpdStorageUnitCreate.argtypes = [
            ctypes.c_wchar_p,
            ctypes.POINTER(StorageUnitParams),
            ctypes.POINTER(StorageUnitInterface),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._dll.SpdStorageUnitCreate.restype = ctypes.c_uint32
        self._dll.SpdStorageUnitDelete.argtypes = [ctypes.c_void_p]
        self._dll.SpdStorageUnitDelete.restype = None
        self._dll.SpdStorageUnitShutdown.argtypes = [ctypes.c_void_p]
        self._dll.SpdStorageUnitShutdown.restype = None
        self._dll.SpdStorageUnitStartDispatcher.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self._dll.SpdStorageUnitStartDispatcher.restype = ctypes.c_uint32
        self._dll.SpdStorageUnitWaitDispatcher.argtypes = [ctypes.c_void_p]
        self._dll.SpdStorageUnitWaitDispatcher.restype = None
        self._dll.SpdDefinePartitionTable.argtypes = [
            ctypes.POINTER(Partition),
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        self._dll.SpdDefinePartitionTable.restype = ctypes.c_uint32

    def create(
        self,
        device_name: str | None,
        params: StorageUnitParams,
        interface: StorageUnitInterface,
    ) -> ctypes.c_void_p:
        storage_unit = ctypes.c_void_p()
        error = self._dll.SpdStorageUnitCreate(
            device_name,
            ctypes.byref(params),
            ctypes.byref(interface),
            ctypes.byref(storage_unit),
        )
        if error != ERROR_SUCCESS:
            raise WinSpdError(f"WinSpd не создал системный диск (код {error}).")
        return storage_unit

    def start(self, storage_unit: ctypes.c_void_p) -> None:
        error = self._dll.SpdStorageUnitStartDispatcher(storage_unit, 0)
        if error != ERROR_SUCCESS:
            raise WinSpdError(f"WinSpd не запустил системный диск (код {error}).")

    def shutdown(self, storage_unit: ctypes.c_void_p) -> None:
        self._dll.SpdStorageUnitShutdown(storage_unit)

    def wait(self, storage_unit: ctypes.c_void_p) -> None:
        self._dll.SpdStorageUnitWaitDispatcher(storage_unit)

    def delete(self, storage_unit: ctypes.c_void_p) -> None:
        self._dll.SpdStorageUnitDelete(storage_unit)

    def define_partition_table(self, partitions: list[Partition]) -> bytes:
        if not 1 <= len(partitions) <= 4:
            raise ValueError("An MBR must contain between one and four partitions.")
        partition_array = (Partition * len(partitions))(*partitions)
        buffer = (ctypes.c_ubyte * 512)()
        error = self._dll.SpdDefinePartitionTable(
            partition_array,
            len(partitions),
            ctypes.cast(buffer, ctypes.c_void_p),
        )
        if error != ERROR_SUCCESS:
            raise WinSpdError(
                f"WinSpd не подготовил таблицу разделов (код {error})."
            )
        return bytes(buffer)


def initialize_windows_partition(
    volume: EncryptedBlockVolume,
    library: WinSpdLibrary,
) -> None:
    """Initialize a new encrypted block array with one Windows data partition."""

    if volume.logical_capacity < MIN_WINDOWS_DISK_CAPACITY:
        raise ValidationError("Системный зашифрованный диск должен быть не меньше 32 МБ.")
    first_block = volume.read_blocks(0, 1)
    if first_block != bytes(LOGICAL_BLOCK_SIZE):
        raise ValidationError("Таблица разделов диска уже создана.")
    partition_start = max(1, (1024 * 1024) // LOGICAL_BLOCK_SIZE)
    mbr = library.define_partition_table(
        [
            Partition(
                Type=7,
                Active=0,
                BlockAddress=partition_start,
                BlockCount=volume.block_count - partition_start,
            )
        ]
    )
    volume.write_blocks(0, mbr.ljust(LOGICAL_BLOCK_SIZE, b"\0"))
    volume.flush()


class WinSpdBlockDevice:
    """Expose EncryptedBlockVolume through WinSpd SCSI block operations.

    Passing a named pipe is intended for the official ``stgtest`` utility and
    does not attach a disk to Windows. Passing ``None`` asks the installed
    driver to attach a real disk and therefore requires its service context.
    """

    def __init__(
        self,
        volume: EncryptedBlockVolume,
        *,
        library: WinSpdLibrary,
        pipe_name: str | None,
        product_revision: str = "0.5",
        max_transfer_length: int = DEFAULT_MAX_TRANSFER_LENGTH,
        close_volume: bool = False,
    ) -> None:
        if max_transfer_length <= 0 or max_transfer_length % LOGICAL_BLOCK_SIZE:
            raise ValueError("Max transfer length must be a positive block multiple.")
        self.volume = volume
        self.library = library
        self.pipe_name = pipe_name
        self.close_volume = close_volume
        self.last_error: Exception | None = None
        self._state_lock = threading.RLock()
        self._storage_unit: ctypes.c_void_p | None = None

        self._read_callback = READ_CALLBACK(self._read)
        self._write_callback = WRITE_CALLBACK(self._write)
        self._flush_callback = FLUSH_CALLBACK(self._flush)
        self._unmap_callback = UNMAP_CALLBACK(self._unmap)
        self._interface = StorageUnitInterface(
            self._read_callback,
            self._write_callback,
            self._flush_callback,
            self._unmap_callback,
            (ctypes.c_void_p * 12)(),
        )
        self._params = StorageUnitParams()
        self._params.Guid[:] = uuid.uuid4().bytes_le
        self._params.BlockCount = volume.block_count
        self._params.BlockLength = LOGICAL_BLOCK_SIZE
        _set_fixed_bytes(self._params.ProductId, b"CleverPGP")
        _set_fixed_bytes(
            self._params.ProductRevisionLevel,
            product_revision.encode("ascii", errors="strict"),
        )
        self._params.DeviceType = 0
        self._params.Flags = FLAG_CACHE_SUPPORTED | FLAG_UNMAP_SUPPORTED
        self._params.MaxTransferLength = max_transfer_length

    @property
    def running(self) -> bool:
        return self._storage_unit is not None

    def start(self) -> None:
        with self._state_lock:
            if self.running:
                return
            storage_unit = self.library.create(
                self.pipe_name,
                self._params,
                self._interface,
            )
            try:
                self.library.start(storage_unit)
            except Exception:
                self.library.delete(storage_unit)
                raise
            self._storage_unit = storage_unit

    def stop(self) -> None:
        with self._state_lock:
            storage_unit = self._storage_unit
            if storage_unit is None:
                return
            self._storage_unit = None
        try:
            self.library.shutdown(storage_unit)
            self.library.wait(storage_unit)
        finally:
            self.library.delete(storage_unit)
            if self.close_volume:
                self.volume.close()

    def wait(self) -> None:
        with self._state_lock:
            storage_unit = self._storage_unit
        if storage_unit is not None:
            self.library.wait(storage_unit)

    def __enter__(self) -> WinSpdBlockDevice:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.stop()

    @staticmethod
    def _clear_status(status: ctypes.POINTER(StorageUnitStatus)) -> None:
        ctypes.memset(status, 0, ctypes.sizeof(StorageUnitStatus))

    @staticmethod
    def _set_sense(
        status: ctypes.POINTER(StorageUnitStatus),
        sense_key: int,
        asc: int,
        information: int | None = None,
    ) -> None:
        value = status.contents
        value.ScsiStatus = SCSISTAT_CHECK_CONDITION
        value.SenseKey = sense_key
        value.ASC = asc
        if information is not None:
            value.Information = information
            value.Flags = 0x10

    def _record_error(
        self,
        error: Exception,
        status: ctypes.POINTER(StorageUnitStatus),
        *,
        write: bool = False,
        block_address: int | None = None,
    ) -> None:
        self.last_error = error
        sense_key = SCSI_SENSE_MEDIUM_ERROR
        asc = SCSI_ADSENSE_WRITE_ERROR if write else SCSI_ADSENSE_UNRECOVERED_ERROR
        if isinstance(error, (ValidationError, ValueError, OverflowError)):
            sense_key = SCSI_SENSE_ILLEGAL_REQUEST
            asc = SCSI_ADSENSE_ILLEGAL_BLOCK
        elif not isinstance(error, OSError):
            sense_key = SCSI_SENSE_HARDWARE_ERROR
            asc = SCSI_ADSENSE_INTERNAL_TARGET_FAILURE
        self._set_sense(status, sense_key, asc, block_address)

    def _read(
        self,
        _storage_unit: int,
        buffer: int,
        block_address: int,
        block_count: int,
        flush: int,
        status: ctypes.POINTER(StorageUnitStatus),
    ) -> int:
        self._clear_status(status)
        try:
            if flush:
                self.volume.flush()
            payload = self.volume.read_blocks(block_address, block_count)
            ctypes.memmove(buffer, payload, len(payload))
        except Exception as error:
            self._record_error(error, status, block_address=block_address)
        return 1

    def _write(
        self,
        _storage_unit: int,
        buffer: int,
        block_address: int,
        block_count: int,
        flush: int,
        status: ctypes.POINTER(StorageUnitStatus),
    ) -> int:
        self._clear_status(status)
        try:
            length = block_count * LOGICAL_BLOCK_SIZE
            payload = ctypes.string_at(buffer, length)
            self.volume.write_blocks(block_address, payload)
            if flush:
                self.volume.flush()
        except Exception as error:
            self._record_error(
                error,
                status,
                write=True,
                block_address=block_address,
            )
        return 1

    def _flush(
        self,
        _storage_unit: int,
        _block_address: int,
        _block_count: int,
        status: ctypes.POINTER(StorageUnitStatus),
    ) -> int:
        self._clear_status(status)
        try:
            self.volume.flush()
        except Exception as error:
            self._record_error(error, status, write=True)
        return 1

    def _unmap(
        self,
        _storage_unit: int,
        descriptors: ctypes.POINTER(UnmapDescriptor),
        count: int,
        status: ctypes.POINTER(StorageUnitStatus),
    ) -> int:
        self._clear_status(status)
        try:
            blocks_per_chunk = DEFAULT_MAX_TRANSFER_LENGTH // LOGICAL_BLOCK_SIZE
            for descriptor_index in range(count):
                descriptor = descriptors[descriptor_index]
                address = int(descriptor.BlockAddress)
                remaining = int(descriptor.BlockCount)
                while remaining:
                    chunk = min(remaining, blocks_per_chunk)
                    self.volume.write_blocks(
                        address,
                        bytes(chunk * LOGICAL_BLOCK_SIZE),
                    )
                    address += chunk
                    remaining -= chunk
        except Exception as error:
            self._record_error(error, status, write=True)
        return 1
