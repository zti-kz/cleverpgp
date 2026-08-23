from __future__ import annotations

import os
import shutil
import struct
import tempfile
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from nacl import bindings, exceptions, secret, utils

from biopgp.core.block_volume import (
    INITIALIZATION_BATCH_BLOCKS,
    LOGICAL_BLOCK_SIZE,
    MIN_LOGICAL_CAPACITY,
    NONCE_SIZE,
    PHYSICAL_SLOT_SIZE,
    BlockIntegrityError,
    InvalidBlockVolumeError,
)
from biopgp.core.errors import OutputExistsError, ValidationError
from biopgp.core.hidden_volume import (
    BlockVolume,
    HiddenBlockVolume,
    HiddenRegionProtectedVolume,
    HiddenVolumeDescriptor,
)
from biopgp.core.opaque_volume_header import (
    BANK_COUNT,
    OPAQUE_HEADER_RESERVED_SIZE,
    OpaqueVolumeHeader,
    OpaqueVolumeHeaderStore,
    VolumeRole,
)

OPAQUE_BLOCK_AAD = b"CPGPBLK4"
ProgressCallback = Callable[[int, int], None]


class OpaqueCoverBlockVolume:
    """Authenticated outer block array whose metadata lives in a v4 header."""

    def __init__(
        self,
        path: Path,
        stream: object,
        header: OpaqueVolumeHeader,
    ) -> None:
        self.path = Path(path)
        self._stream = stream
        self._volume_key = bytearray(header.cover_key)
        self._volume_id = bytes(header.cover_volume_id)
        self._block_count = header.cover_block_count
        self._label = header.label
        self._storage_format = header.storage_format
        self._lock = threading.RLock()
        self._closed = False

    @property
    def block_count(self) -> int:
        return self._block_count

    @property
    def logical_capacity(self) -> int:
        return self.block_count * LOGICAL_BLOCK_SIZE

    @property
    def label(self) -> str:
        return self._label

    @property
    def volume_id(self) -> bytes:
        return self._volume_id

    @property
    def storage_format(self) -> str:
        return self._storage_format

    def read_blocks(
        self,
        block_address: int,
        block_count: int,
        *,
        context: bytes = b"",
    ) -> bytes:
        self._validate_range(block_address, block_count)
        authenticated_context = self._validate_context(context)
        result = bytearray()
        with self._lock:
            self._ensure_open()
            self._stream.seek(self._slot_offset(block_address))
            for offset in range(block_count):
                slot = self._read_exact(self._stream, PHYSICAL_SLOT_SIZE)
                block_index = block_address + offset
                try:
                    result.extend(
                        bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                            slot[NONCE_SIZE:],
                            self._block_aad(
                                self.volume_id,
                                block_index,
                                authenticated_context,
                            ),
                            slot[:NONCE_SIZE],
                            bytes(self._volume_key),
                        )
                    )
                except exceptions.CryptoError as error:
                    raise BlockIntegrityError(
                        f"Нарушена целостность блока {block_index}."
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
        encrypted = bytearray()
        for offset in range(block_count):
            start = offset * LOGICAL_BLOCK_SIZE
            block_index = block_address + offset
            encrypted.extend(
                self._encrypt_block(
                    payload[start : start + LOGICAL_BLOCK_SIZE],
                    block_index,
                    self.volume_id,
                    bytes(self._volume_key),
                    authenticated_context,
                )
            )
        with self._lock:
            self._ensure_open()
            self._stream.seek(self._slot_offset(block_address))
            self._stream.write(encrypted)

    def flush(self) -> None:
        with self._lock:
            self._ensure_open()
            self._stream.flush()
            os.fsync(self._stream.fileno())

    def resize(self, logical_capacity: int, **_: object) -> None:
        del logical_capacity
        raise ValidationError(
            "Изменение размера формата v4 будет включено после защиты "
            "границ скрытого диска."
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self.flush()
            finally:
                self._stream.close()
                for index in range(len(self._volume_key)):
                    self._volume_key[index] = 0
                self._closed = True

    def __enter__(self) -> OpaqueCoverBlockVolume:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @staticmethod
    def physical_size(block_count: int) -> int:
        if not isinstance(block_count, int) or block_count <= 0:
            raise ValidationError("Некорректное число блоков диска.")
        return OPAQUE_HEADER_RESERVED_SIZE + block_count * PHYSICAL_SLOT_SIZE

    def _slot_offset(self, block_address: int) -> int:
        return OPAQUE_HEADER_RESERVED_SIZE + block_address * PHYSICAL_SLOT_SIZE

    @staticmethod
    def _block_aad(
        volume_id: bytes,
        block_index: int,
        context: bytes = b"",
    ) -> bytes:
        return OPAQUE_BLOCK_AAD + volume_id + struct.pack(">Q", block_index) + context

    @classmethod
    def _encrypt_block(
        cls,
        plaintext: bytes,
        block_index: int,
        volume_id: bytes,
        volume_key: bytes,
        context: bytes = b"",
    ) -> bytes:
        nonce = utils.random(NONCE_SIZE)
        ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext,
            cls._block_aad(volume_id, block_index, context),
            nonce,
            volume_key,
        )
        return nonce + ciphertext

    def _validate_range(self, block_address: int, block_count: int) -> None:
        if (
            not isinstance(block_address, int)
            or not isinstance(block_count, int)
            or block_address < 0
            or block_count <= 0
            or block_address + block_count > self.block_count
        ):
            raise ValidationError(
                "Запрошенный диапазон блоков выходит за границы диска."
            )

    @staticmethod
    def _validate_context(context: bytes) -> bytes:
        if not isinstance(context, bytes) or len(context) > 64:
            raise ValidationError("Некорректный контекст логического блока.")
        return context

    def _ensure_open(self) -> None:
        if self._closed:
            raise InvalidBlockVolumeError("Зашифрованный диск уже закрыт.")

    @staticmethod
    def _read_exact(stream: object, size: int) -> bytes:
        data = stream.read(size)
        if len(data) != size:
            raise InvalidBlockVolumeError("Файл зашифрованного диска оборван.")
        return data


class OpaqueVolumeSession:
    """Owns the cover stream and delegates I/O to the selected projection."""

    def __init__(
        self,
        role: VolumeRole,
        cover: OpaqueCoverBlockVolume,
        selected: BlockVolume,
    ) -> None:
        self.role = role
        self._cover = cover
        self._selected = selected
        self._closed = False

    @property
    def path(self) -> Path:
        return self._selected.path

    @property
    def block_count(self) -> int:
        return self._selected.block_count

    @property
    def logical_capacity(self) -> int:
        return self._selected.logical_capacity

    @property
    def label(self) -> str:
        return self._selected.label

    @property
    def volume_id(self) -> bytes:
        return self._selected.volume_id

    @property
    def storage_format(self) -> str | None:
        return self._selected.storage_format

    @property
    def damage_prevented(self) -> bool:
        return bool(getattr(self._selected, "damage_prevented", False))

    def read_blocks(
        self,
        block_address: int,
        block_count: int,
        *,
        context: bytes = b"",
    ) -> bytes:
        self._ensure_open()
        return self._selected.read_blocks(
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
        self._ensure_open()
        self._selected.write_blocks(block_address, data, context=context)

    def flush(self) -> None:
        self._ensure_open()
        self._selected.flush()

    def resize(self, logical_capacity: int, **kwargs: object) -> None:
        self._ensure_open()
        resize = getattr(self._selected, "resize", None)
        if not callable(resize):
            raise ValidationError("Этот диск нельзя увеличить.")
        resize(logical_capacity, **kwargs)

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self._selected is not self._cover:
                self._selected.close()
        finally:
            self._cover.close()
            self._closed = True

    def __enter__(self) -> OpaqueVolumeSession:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise InvalidBlockVolumeError("Зашифрованный диск уже закрыт.")


class OpaqueBlockVolume:
    """Creates and opens v4 cover/hidden projections by their passwords."""

    @classmethod
    def create_outer(
        cls,
        path: Path,
        outer_password: str,
        *,
        logical_capacity: int,
        label: str = "Clever PGP",
        storage_format: str,
        overwrite: bool = False,
        header_store: OpaqueVolumeHeaderStore | None = None,
        progress: ProgressCallback | None = None,
    ) -> OpaqueVolumeSession:
        target = Path(path).expanduser().resolve()
        block_count = cls._block_count_for_capacity(logical_capacity)
        clean_label = label.strip() or "Clever PGP"
        if len(clean_label) > 31:
            raise ValidationError("Название диска должно быть не длиннее 31 символа.")
        if not storage_format or len(storage_format) > 63:
            raise ValidationError("Некорректное назначение блочного хранилища.")
        if target.exists() and not overwrite:
            raise OutputExistsError(f"Контейнер уже существует: {target}")
        if not target.parent.is_dir():
            raise ValidationError("Папка для контейнера не существует.")

        required_size = OpaqueCoverBlockVolume.physical_size(block_count)
        if required_size > int(shutil.disk_usage(target.parent).free):
            raise ValidationError(
                "Недостаточно свободного места на выбранном накопителе."
            )

        store = header_store or OpaqueVolumeHeaderStore()
        cover_key = utils.random(secret.SecretBox.KEY_SIZE)
        header = OpaqueVolumeHeader(
            role="outer",
            generation=1,
            cover_volume_id=uuid.uuid4().bytes,
            cover_key=cover_key,
            cover_block_count=block_count,
            label=clean_label,
            storage_format=storage_format,
            created_at=datetime.now(UTC).isoformat(),
        )
        temporary_path: Path | None = None
        try:
            temporary = tempfile.NamedTemporaryFile(
                mode="w+b",
                prefix=f".{target.name}.",
                suffix=".tmp",
                dir=target.parent,
                delete=False,
            )
            temporary_path = Path(temporary.name)
            with temporary as stream:
                store.initialize(
                    stream,
                    outer_password,
                    header,
                    progress=(
                        (lambda completed, _total: progress(
                            completed,
                            BANK_COUNT + block_count,
                        ))
                        if progress is not None
                        else None
                    ),
                )
                zero_block = bytes(LOGICAL_BLOCK_SIZE)
                completed = 0
                stream.seek(OPAQUE_HEADER_RESERVED_SIZE)
                while completed < block_count:
                    batch_count = min(
                        INITIALIZATION_BATCH_BLOCKS,
                        block_count - completed,
                    )
                    batch = bytearray()
                    for offset in range(batch_count):
                        block_index = completed + offset
                        batch.extend(
                            OpaqueCoverBlockVolume._encrypt_block(
                                zero_block,
                                block_index,
                                header.cover_volume_id,
                                cover_key,
                            )
                        )
                    stream.write(batch)
                    completed += batch_count
                    if progress is not None:
                        progress(BANK_COUNT + completed, BANK_COUNT + block_count)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, target)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

        stream = target.open("r+b")
        cover = OpaqueCoverBlockVolume(target, stream, header)
        return OpaqueVolumeSession("outer", cover, cover)

    @classmethod
    def open(
        cls,
        path: Path,
        password: str,
        *,
        header_store: OpaqueVolumeHeaderStore | None = None,
        progress: ProgressCallback | None = None,
    ) -> OpaqueVolumeSession:
        source = Path(path).expanduser().resolve()
        if not source.is_file():
            raise InvalidBlockVolumeError("Файл зашифрованного диска не найден.")
        store = header_store or OpaqueVolumeHeaderStore()
        with source.open("rb") as header_stream:
            header = store.unlock(header_stream, password, progress=progress)
        return cls.open_with_header(source, header)

    @classmethod
    def open_with_header(
        cls,
        path: Path,
        header: OpaqueVolumeHeader,
        *,
        protected_hidden_descriptor: HiddenVolumeDescriptor | None = None,
    ) -> OpaqueVolumeSession:
        """Open already-authenticated material without retaining its password."""

        source = Path(path).expanduser().resolve()
        if not source.is_file():
            raise InvalidBlockVolumeError("Файл зашифрованного диска не найден.")
        stream = source.open("r+b")
        cover: OpaqueCoverBlockVolume | None = None
        try:
            cls._validate_physical_size(source, header.cover_block_count)
            cover = OpaqueCoverBlockVolume(source, stream, header)
            if header.role == "outer":
                selected: BlockVolume = cover
                if protected_hidden_descriptor is not None:
                    selected = HiddenRegionProtectedVolume(
                        cover,
                        protected_hidden_descriptor,
                    )
                return OpaqueVolumeSession("outer", cover, selected)
            if protected_hidden_descriptor is not None:
                raise ValidationError(
                    "Защита скрытой области применяется только к внешнему диску."
                )
            if header.hidden_key is None or header.hidden_descriptor is None:
                raise InvalidBlockVolumeError("Скрытый заголовок диска повреждён.")
            hidden = HiddenBlockVolume.open(
                cover,
                header.hidden_key,
                header.hidden_descriptor,
            )
            return OpaqueVolumeSession("hidden", cover, hidden)
        except Exception:
            if cover is not None:
                cover.close()
            else:
                stream.close()
            raise

    @classmethod
    def add_hidden_in_verified_free_region(
        cls,
        path: Path,
        outer_password: str,
        hidden_password: str,
        *,
        logical_capacity: int,
        region_start_block: int,
        label: str = "Clever PGP Hidden",
        storage_format: str,
        header_store: OpaqueVolumeHeaderStore | None = None,
        progress: ProgressCallback | None = None,
    ) -> None:
        """Create hidden blocks only in a region verified free by the caller.

        This deliberately is not exposed by the UI until the filesystem layer
        can prove that the whole requested tail contains no allocated clusters.
        """

        store = header_store or OpaqueVolumeHeaderStore()
        session = cls.open(
            path,
            outer_password,
            header_store=store,
        )
        if session.role != "outer":
            session.close()
            raise ValidationError("Требуется пароль внешнего диска.")
        hidden_key = utils.random(secret.SecretBox.KEY_SIZE)
        try:
            hidden = HiddenBlockVolume.create(
                session._cover,
                hidden_key,
                logical_capacity=logical_capacity,
                label=label,
                storage_format=storage_format,
                region_start_block=region_start_block,
                progress=progress,
            )
            descriptor = hidden.descriptor
            hidden.close()
            hidden_header = OpaqueVolumeHeader(
                role="hidden",
                generation=1,
                cover_volume_id=session._cover.volume_id,
                cover_key=bytes(session._cover._volume_key),
                cover_block_count=session._cover.block_count,
                label=descriptor.label,
                storage_format=descriptor.storage_format,
                created_at=datetime.now(UTC).isoformat(),
                hidden_key=hidden_key,
                hidden_descriptor=descriptor,
            )
            store.add_hidden(
                session._cover._stream,
                outer_password,
                hidden_password,
                hidden_header,
            )
        finally:
            session.close()

    @classmethod
    def open_outer_with_hidden_protection(
        cls,
        path: Path,
        outer_password: str,
        hidden_password: str,
        *,
        header_store: OpaqueVolumeHeaderStore | None = None,
    ) -> OpaqueVolumeSession:
        store = header_store or OpaqueVolumeHeaderStore()
        session = cls.open(path, outer_password, header_store=store)
        if session.role != "outer":
            session.close()
            raise ValidationError("Требуется пароль внешнего диска.")
        try:
            hidden_header = store.unlock(
                session._cover._stream,
                hidden_password,
            )
            if (
                hidden_header.role != "hidden"
                or hidden_header.hidden_descriptor is None
                or hidden_header.cover_volume_id != session._cover.volume_id
                or not bindings.sodium_memcmp(
                    hidden_header.cover_key,
                    bytes(session._cover._volume_key),
                )
            ):
                raise ValidationError(
                    "Скрытый пароль не относится к внешнему диску."
                )
            protected = HiddenRegionProtectedVolume(
                session._cover,
                hidden_header.hidden_descriptor,
            )
            session._selected = protected
            return session
        except Exception:
            session.close()
            raise

    @staticmethod
    def _block_count_for_capacity(capacity: int) -> int:
        if not isinstance(capacity, int) or capacity < MIN_LOGICAL_CAPACITY:
            raise ValidationError("Размер диска должен быть не меньше 1 МБ.")
        if capacity % LOGICAL_BLOCK_SIZE:
            raise ValidationError(
                "Размер диска должен быть кратен размеру логического блока."
            )
        return capacity // LOGICAL_BLOCK_SIZE

    @staticmethod
    def _validate_physical_size(path: Path, block_count: int) -> None:
        expected = OpaqueCoverBlockVolume.physical_size(block_count)
        actual = path.stat().st_size
        if actual != expected:
            raise InvalidBlockVolumeError(
                "Размер файла не соответствует защищённому заголовку диска."
            )


__all__ = [
    "OPAQUE_BLOCK_AAD",
    "OpaqueBlockVolume",
    "OpaqueCoverBlockVolume",
    "OpaqueVolumeSession",
]
