from __future__ import annotations

import math
import struct
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from nacl import bindings, exceptions, secret, utils

from biopgp.core.block_volume import (
    LOGICAL_BLOCK_SIZE,
    MIN_LOGICAL_CAPACITY,
    NONCE_SIZE,
    TAG_SIZE,
    BlockIntegrityError,
    BlockVolumeError,
    InvalidBlockVolumeError,
)
from biopgp.core.errors import ValidationError

HIDDEN_MAGIC = b"CPGPHID1"
HIDDEN_FORMAT_VERSION = 1
HIDDEN_SLOT_SIZE = NONCE_SIZE + LOGICAL_BLOCK_SIZE + TAG_SIZE
INITIALIZATION_BATCH_BLOCKS = 256


class BlockVolume(Protocol):
    path: Path

    @property
    def block_count(self) -> int: ...

    @property
    def logical_capacity(self) -> int: ...

    @property
    def label(self) -> str: ...

    @property
    def volume_id(self) -> bytes: ...

    @property
    def storage_format(self) -> str | None: ...

    def read_blocks(
        self,
        block_address: int,
        block_count: int,
        *,
        context: bytes = b"",
    ) -> bytes: ...

    def write_blocks(
        self,
        block_address: int,
        data: bytes,
        *,
        context: bytes = b"",
    ) -> None: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class HiddenVolumeDescriptor:
    volume_id: bytes
    region_start_block: int
    region_block_count: int
    hidden_block_count: int
    label: str
    storage_format: str
    format_version: int = HIDDEN_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != HIDDEN_FORMAT_VERSION:
            raise ValidationError("Неподдерживаемая версия скрытого тома.")
        if not isinstance(self.volume_id, bytes) or len(self.volume_id) != 16:
            raise ValidationError("Некорректный идентификатор скрытого тома.")
        if self.region_start_block < 0 or self.region_block_count <= 0:
            raise ValidationError("Некорректная область скрытого тома.")
        if self.hidden_block_count <= 0:
            raise ValidationError("Некорректный размер скрытого тома.")
        if not self.label.strip() or len(self.label) > 31:
            raise ValidationError("Некорректное название скрытого тома.")
        if not self.storage_format or len(self.storage_format) > 63:
            raise ValidationError("Некорректное назначение скрытого тома.")
        required = HiddenBlockVolume.required_region_blocks(
            self.hidden_block_count * LOGICAL_BLOCK_SIZE
        )
        if required != self.region_block_count:
            raise ValidationError("Размер области скрытого тома не согласован.")


class HiddenBlockVolume:
    """Authenticated block view nested in the cover volume plaintext.

    The cover layer remains independently authenticated. Hidden slots are
    stored as an opaque stream inside a caller-verified free tail region of the
    outer filesystem. A future encrypted hidden header will store the
    descriptor and both keys; this class deliberately contains no password
    handling or discoverable on-disk marker.
    """

    def __init__(
        self,
        cover: BlockVolume,
        hidden_key: bytes,
        descriptor: HiddenVolumeDescriptor,
        *,
        owns_cover: bool = False,
    ) -> None:
        self._validate_hidden_key(hidden_key)
        self._validate_region(cover, descriptor)
        self._cover = cover
        self._hidden_key = bytearray(hidden_key)
        self._descriptor = descriptor
        self._owns_cover = owns_cover
        self._lock = threading.RLock()
        self._closed = False

    @classmethod
    def create(
        cls,
        cover: BlockVolume,
        hidden_key: bytes,
        *,
        logical_capacity: int,
        label: str = "Clever PGP Hidden",
        storage_format: str,
        region_start_block: int | None = None,
        owns_cover: bool = False,
        progress: Callable[[int, int], None] | None = None,
    ) -> HiddenBlockVolume:
        cls._validate_hidden_key(hidden_key)
        hidden_block_count = cls._hidden_block_count(logical_capacity)
        region_block_count = cls.required_region_blocks(logical_capacity)
        if region_start_block is None:
            region_start_block = cover.block_count - region_block_count
        descriptor = HiddenVolumeDescriptor(
            volume_id=uuid.uuid4().bytes,
            region_start_block=region_start_block,
            region_block_count=region_block_count,
            hidden_block_count=hidden_block_count,
            label=label.strip(),
            storage_format=storage_format,
        )
        volume = cls(
            cover,
            hidden_key,
            descriptor,
            owns_cover=owns_cover,
        )
        try:
            volume._initialize(progress=progress)
            return volume
        except Exception:
            volume.close()
            raise

    @classmethod
    def open(
        cls,
        cover: BlockVolume,
        hidden_key: bytes,
        descriptor: HiddenVolumeDescriptor,
        *,
        owns_cover: bool = False,
    ) -> HiddenBlockVolume:
        return cls(cover, hidden_key, descriptor, owns_cover=owns_cover)

    @staticmethod
    def required_region_blocks(logical_capacity: int) -> int:
        hidden_blocks = HiddenBlockVolume._hidden_block_count(logical_capacity)
        return math.ceil(hidden_blocks * HIDDEN_SLOT_SIZE / LOGICAL_BLOCK_SIZE)

    @staticmethod
    def maximum_logical_capacity(region_block_count: int) -> int:
        """Return the largest block-aligned hidden disk fitting a region."""

        if not isinstance(region_block_count, int) or region_block_count <= 0:
            raise ValidationError("Некорректный размер области скрытого тома.")
        hidden_blocks = (
            region_block_count * LOGICAL_BLOCK_SIZE // HIDDEN_SLOT_SIZE
        )
        return hidden_blocks * LOGICAL_BLOCK_SIZE

    @property
    def path(self) -> Path:
        return self._cover.path

    @property
    def block_count(self) -> int:
        return self._descriptor.hidden_block_count

    @property
    def logical_capacity(self) -> int:
        return self.block_count * LOGICAL_BLOCK_SIZE

    @property
    def label(self) -> str:
        return self._descriptor.label

    @property
    def volume_id(self) -> bytes:
        return self._descriptor.volume_id

    @property
    def storage_format(self) -> str:
        return self._descriptor.storage_format

    @property
    def descriptor(self) -> HiddenVolumeDescriptor:
        return self._descriptor

    @property
    def region_start_block(self) -> int:
        return self._descriptor.region_start_block

    @property
    def region_block_count(self) -> int:
        return self._descriptor.region_block_count

    def read_blocks(
        self,
        block_address: int,
        block_count: int,
        *,
        context: bytes = b"",
    ) -> bytes:
        self._validate_range(block_address, block_count)
        authenticated_context = self._validate_context(context)
        with self._lock:
            self._ensure_open()
            raw, relative_start = self._read_inner_range(block_address, block_count)
            result = bytearray()
            for offset in range(block_count):
                slot_start = relative_start + offset * HIDDEN_SLOT_SIZE
                slot = raw[slot_start : slot_start + HIDDEN_SLOT_SIZE]
                hidden_index = block_address + offset
                try:
                    result.extend(
                        bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                            slot[NONCE_SIZE:],
                            self._block_aad(
                                self.volume_id,
                                hidden_index,
                                authenticated_context,
                            ),
                            slot[:NONCE_SIZE],
                            bytes(self._hidden_key),
                        )
                    )
                except exceptions.CryptoError as error:
                    raise BlockIntegrityError(
                        f"Нарушена целостность скрытого блока {hidden_index}."
                    ) from error
            return bytes(result)

    def write_blocks(
        self,
        block_address: int,
        data: bytes,
        *,
        context: bytes = b"",
    ) -> None:
        payload = bytes(data)
        if not payload or len(payload) % LOGICAL_BLOCK_SIZE:
            raise ValidationError(
                "Запись должна содержать целое число логических блоков."
            )
        block_count = len(payload) // LOGICAL_BLOCK_SIZE
        self._validate_range(block_address, block_count)
        authenticated_context = self._validate_context(context)
        with self._lock:
            self._ensure_open()
            raw, relative_start, cover_address = self._read_mutable_inner_range(
                block_address,
                block_count,
            )
            for offset in range(block_count):
                plaintext_start = offset * LOGICAL_BLOCK_SIZE
                hidden_index = block_address + offset
                encrypted = self._encrypt_block(
                    payload[
                        plaintext_start : plaintext_start + LOGICAL_BLOCK_SIZE
                    ],
                    hidden_index,
                    authenticated_context,
                )
                slot_start = relative_start + offset * HIDDEN_SLOT_SIZE
                raw[slot_start : slot_start + HIDDEN_SLOT_SIZE] = encrypted
            self._cover.write_blocks(cover_address, bytes(raw))

    def flush(self) -> None:
        with self._lock:
            self._ensure_open()
            self._cover.flush()

    def resize(self, logical_capacity: int, **_: object) -> None:
        del logical_capacity
        raise ValidationError(
            "Изменение размера скрытого тома требует безопасного переноса его области."
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._cover.flush()
            finally:
                for index in range(len(self._hidden_key)):
                    self._hidden_key[index] = 0
                if self._owns_cover:
                    self._cover.close()
                self._closed = True

    def __enter__(self) -> HiddenBlockVolume:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _initialize(
        self,
        *,
        progress: Callable[[int, int], None] | None,
    ) -> None:
        pending = bytearray()
        cover_cursor = self.region_start_block
        zero_block = bytes(LOGICAL_BLOCK_SIZE)
        for hidden_index in range(self.block_count):
            pending.extend(self._encrypt_block(zero_block, hidden_index, b""))
            complete_cover_blocks = len(pending) // LOGICAL_BLOCK_SIZE
            if (
                complete_cover_blocks >= INITIALIZATION_BATCH_BLOCKS
                or hidden_index + 1 == self.block_count
            ):
                if hidden_index + 1 == self.block_count:
                    region_bytes = self.region_block_count * LOGICAL_BLOCK_SIZE
                    remaining = region_bytes - (
                        cover_cursor - self.region_start_block
                    ) * LOGICAL_BLOCK_SIZE - len(pending)
                    if remaining < 0:
                        raise InvalidBlockVolumeError(
                            "Скрытый том не помещается в выделенную область."
                        )
                    pending.extend(utils.random(remaining))
                    complete_cover_blocks = len(pending) // LOGICAL_BLOCK_SIZE
                write_size = complete_cover_blocks * LOGICAL_BLOCK_SIZE
                if write_size:
                    self._cover.write_blocks(
                        cover_cursor,
                        bytes(pending[:write_size]),
                    )
                    del pending[:write_size]
                    cover_cursor += complete_cover_blocks
            if progress is not None:
                progress(hidden_index + 1, self.block_count)
        if pending or cover_cursor != self.region_start_block + self.region_block_count:
            raise InvalidBlockVolumeError(
                "Скрытый том и его выделенная область не согласованы."
            )
        self._cover.flush()

    def _read_inner_range(
        self,
        block_address: int,
        block_count: int,
    ) -> tuple[bytes, int]:
        start_byte = block_address * HIDDEN_SLOT_SIZE
        end_byte = (block_address + block_count) * HIDDEN_SLOT_SIZE
        first_cover_block = start_byte // LOGICAL_BLOCK_SIZE
        end_cover_block = math.ceil(end_byte / LOGICAL_BLOCK_SIZE)
        cover_count = end_cover_block - first_cover_block
        cover_address = self.region_start_block + first_cover_block
        raw = self._cover.read_blocks(cover_address, cover_count)
        return raw, start_byte - first_cover_block * LOGICAL_BLOCK_SIZE

    def _read_mutable_inner_range(
        self,
        block_address: int,
        block_count: int,
    ) -> tuple[bytearray, int, int]:
        raw, relative_start = self._read_inner_range(block_address, block_count)
        start_byte = block_address * HIDDEN_SLOT_SIZE
        first_cover_block = start_byte // LOGICAL_BLOCK_SIZE
        return (
            bytearray(raw),
            relative_start,
            self.region_start_block + first_cover_block,
        )

    def _encrypt_block(
        self,
        plaintext: bytes,
        block_index: int,
        context: bytes,
    ) -> bytes:
        nonce = utils.random(NONCE_SIZE)
        ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext,
            self._block_aad(self.volume_id, block_index, context),
            nonce,
            bytes(self._hidden_key),
        )
        return nonce + ciphertext

    @staticmethod
    def _block_aad(volume_id: bytes, block_index: int, context: bytes) -> bytes:
        return (
            HIDDEN_MAGIC
            + bytes([HIDDEN_FORMAT_VERSION])
            + volume_id
            + struct.pack(">Q", block_index)
            + context
        )

    @staticmethod
    def _hidden_block_count(logical_capacity: int) -> int:
        if (
            not isinstance(logical_capacity, int)
            or logical_capacity < MIN_LOGICAL_CAPACITY
            or logical_capacity % LOGICAL_BLOCK_SIZE
        ):
            raise ValidationError(
                "Размер скрытого тома должен быть не меньше 1 МБ "
                "и кратен размеру блока."
            )
        return logical_capacity // LOGICAL_BLOCK_SIZE

    @staticmethod
    def _validate_hidden_key(hidden_key: bytes) -> None:
        if (
            not isinstance(hidden_key, bytes)
            or len(hidden_key) != secret.SecretBox.KEY_SIZE
        ):
            raise ValidationError("Некорректный ключ скрытого тома.")

    @staticmethod
    def _validate_region(
        cover: BlockVolume,
        descriptor: HiddenVolumeDescriptor,
    ) -> None:
        if (
            descriptor.region_start_block < 0
            or descriptor.region_start_block + descriptor.region_block_count
            > cover.block_count
        ):
            raise ValidationError(
                "Область скрытого тома выходит за границы внешнего диска."
            )

    def _validate_range(self, block_address: int, block_count: int) -> None:
        if (
            not isinstance(block_address, int)
            or not isinstance(block_count, int)
            or block_address < 0
            or block_count <= 0
            or block_address + block_count > self.block_count
        ):
            raise ValidationError(
                "Запрошенный диапазон выходит за границы скрытого тома."
            )

    @staticmethod
    def _validate_context(context: bytes) -> bytes:
        if not isinstance(context, bytes) or len(context) > 64:
            raise ValidationError("Некорректный контекст скрытого блока.")
        return context

    def _ensure_open(self) -> None:
        if self._closed:
            raise InvalidBlockVolumeError("Скрытый том уже закрыт.")


class HiddenRegionProtectedVolume:
    """Outer view that rejects writes capable of damaging a hidden region.

    After the first overlapping write all subsequent writes are rejected until
    close, matching VeraCrypt's damage-prevention state transition.
    """

    def __init__(
        self,
        cover: BlockVolume,
        descriptor: HiddenVolumeDescriptor,
        *,
        owns_cover: bool = False,
    ) -> None:
        HiddenBlockVolume._validate_region(cover, descriptor)
        self._cover = cover
        self._descriptor = descriptor
        self._owns_cover = owns_cover
        self._damage_prevented = False
        self._closed = False
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self._cover.path

    @property
    def block_count(self) -> int:
        return self._cover.block_count

    @property
    def logical_capacity(self) -> int:
        return self._cover.logical_capacity

    @property
    def label(self) -> str:
        return self._cover.label

    @property
    def volume_id(self) -> bytes:
        return self._cover.volume_id

    @property
    def storage_format(self) -> str | None:
        return self._cover.storage_format

    @property
    def hidden_region_protected(self) -> bool:
        return True

    @property
    def damage_prevented(self) -> bool:
        return self._damage_prevented

    def read_blocks(
        self,
        block_address: int,
        block_count: int,
        *,
        context: bytes = b"",
    ) -> bytes:
        with self._lock:
            self._ensure_open()
            return self._cover.read_blocks(
                block_address,
                block_count,
                context=context,
            )

    def write_blocks(
        self,
        block_address: int,
        data: bytes,
        *,
        context: bytes = b"",
    ) -> None:
        payload = bytes(data)
        if not payload or len(payload) % LOGICAL_BLOCK_SIZE:
            raise ValidationError(
                "Запись должна содержать целое число логических блоков."
            )
        block_count = len(payload) // LOGICAL_BLOCK_SIZE
        with self._lock:
            self._ensure_open()
            if (
                not isinstance(block_address, int)
                or block_address < 0
                or block_address + block_count > self.block_count
            ):
                raise ValidationError(
                    "Запрошенный диапазон выходит за границы внешнего диска."
                )
            protected_start = self._descriptor.region_start_block
            protected_end = protected_start + self._descriptor.region_block_count
            requested_end = block_address + block_count
            overlaps = block_address < protected_end and requested_end > protected_start
            if overlaps:
                self._damage_prevented = True
            if self._damage_prevented:
                raise BlockVolumeError(
                    "Запись остановлена для защиты скрытого тома. "
                    "Внешний диск доступен только для чтения до отключения."
                )
            self._cover.write_blocks(
                block_address,
                payload,
                context=context,
            )

    def flush(self) -> None:
        with self._lock:
            self._ensure_open()
            self._cover.flush()

    def resize(self, logical_capacity: int, **_: object) -> None:
        del logical_capacity
        raise ValidationError(
            "Нельзя изменять размер внешнего диска при защите скрытого тома."
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._owns_cover:
                self._cover.close()
            self._closed = True

    def __enter__(self) -> HiddenRegionProtectedVolume:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise InvalidBlockVolumeError("Внешний диск уже закрыт.")


__all__ = [
    "HIDDEN_FORMAT_VERSION",
    "HIDDEN_SLOT_SIZE",
    "HiddenBlockVolume",
    "HiddenRegionProtectedVolume",
    "HiddenVolumeDescriptor",
]
