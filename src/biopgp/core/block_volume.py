from __future__ import annotations

import base64
import binascii
import json
import os
import shutil
import struct
import tempfile
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from nacl import bindings, exceptions, hash, secret, utils
from nacl.encoding import RawEncoder

from biopgp.core.errors import ContainerError, OutputExistsError, ValidationError

MAGIC = b"CPGPBLK2"
FORMAT_VERSION = 2
HEADER_PREFIX = struct.Struct(">8sBI")
HEADER_AREA_SIZE = 64 * 1024
HEADER_JSON_LENGTH = struct.Struct(">I")
LOGICAL_BLOCK_SIZE = 4096
NONCE_SIZE = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
TAG_SIZE = bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES
PHYSICAL_SLOT_SIZE = NONCE_SIZE + LOGICAL_BLOCK_SIZE + TAG_SIZE
MIN_LOGICAL_CAPACITY = 1024 * 1024
INITIALIZATION_BATCH_BLOCKS = 256
ALGORITHM = "XCHACHA20-POLY1305-BLOCK-V1"
KEY_WRAP = "XSALSA20-POLY1305-SECRETBOX"
GENERIC_STORAGE_FORMAT = "CLEVERPGP-AUTHENTICATED-BLOCKS-V1"


class BlockVolumeError(ContainerError):
    """Base class for block volume errors safe to show to the user."""


class InvalidBlockVolumeError(BlockVolumeError):
    pass


class BlockIntegrityError(BlockVolumeError):
    pass


class EncryptedBlockVolume:
    """Random-access authenticated storage for the version 2 disk backend.

    Each logical 4096-byte block has an independent random nonce and
    authentication tag. Rewriting one block therefore never serializes or
    encrypts unrelated blocks. The class is independent of a Windows block
    driver and can be exercised before the WinSpd integration is enabled.
    """

    def __init__(
        self,
        path: Path,
        stream: object,
        volume_key: bytes,
        volume_id: bytes,
        block_count: int,
        metadata: dict[str, object],
    ) -> None:
        self.path = Path(path)
        self._stream = stream
        self._volume_key = bytearray(volume_key)
        self._volume_id = bytes(volume_id)
        self._block_count = block_count
        self._metadata = metadata
        self._lock = threading.RLock()
        self._closed = False

    @classmethod
    def create(
        cls,
        path: Path,
        master_key: bytes,
        *,
        logical_capacity: int,
        label: str = "Clever PGP",
        overwrite: bool = False,
        storage_format: str = GENERIC_STORAGE_FORMAT,
        progress: Callable[[int, int], None] | None = None,
    ) -> EncryptedBlockVolume:
        target = Path(path).expanduser().resolve()
        cls._validate_master_key(master_key)
        block_count = cls._block_count_for_capacity(logical_capacity)
        label = label.strip() or "Clever PGP"
        if len(label) > 31:
            raise ValidationError("Название диска должно быть не длиннее 31 символа.")
        if target.exists() and not overwrite:
            raise OutputExistsError(f"Контейнер уже существует: {target}")
        if not target.parent.is_dir():
            raise ValidationError("Папка для контейнера не существует.")
        if not storage_format or len(storage_format) > 63:
            raise ValidationError("Некорректное назначение блочного хранилища.")

        required_size = cls.physical_size(block_count)
        free_bytes = int(shutil.disk_usage(target.parent).free)
        if required_size > free_bytes:
            raise ValidationError(
                "Недостаточно свободного места на выбранном накопителе."
            )

        volume_key = utils.random(secret.SecretBox.KEY_SIZE)
        volume_id = uuid.uuid4().bytes
        wrapped_key = bytes(secret.SecretBox(master_key).encrypt(volume_key))
        metadata: dict[str, object] = {
            "algorithm": ALGORITHM,
            "block_count": block_count,
            "created_at": datetime.now(UTC).isoformat(),
            "key_wrap": KEY_WRAP,
            "label": label,
            "logical_block_size": LOGICAL_BLOCK_SIZE,
            "storage_format": storage_format,
            "volume_id": base64.b64encode(volume_id).decode("ascii"),
            "wrapped_volume_key": base64.b64encode(wrapped_key).decode("ascii"),
        }
        authenticated = cls._canonical_metadata(metadata)
        metadata["header_auth"] = base64.b64encode(
            hash.blake2b(
                authenticated,
                key=volume_key,
                digest_size=32,
                encoder=RawEncoder,
            )
        ).decode("ascii")
        raw_header = cls._encode_header(metadata)

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
                stream.write(raw_header)
                zero_block = bytes(LOGICAL_BLOCK_SIZE)
                completed = 0
                while completed < block_count:
                    batch_count = min(
                        INITIALIZATION_BATCH_BLOCKS, block_count - completed
                    )
                    batch = bytearray()
                    for offset in range(batch_count):
                        block_index = completed + offset
                        batch.extend(
                            cls._encrypt_block(
                                zero_block, block_index, volume_id, volume_key
                            )
                        )
                    stream.write(batch)
                    completed += batch_count
                    if progress is not None:
                        progress(completed, block_count)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, target)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

        return cls.open(target, master_key)

    @classmethod
    def open(cls, path: Path, master_key: bytes) -> EncryptedBlockVolume:
        source = Path(path).expanduser().resolve()
        cls._validate_master_key(master_key)
        if not source.is_file():
            raise InvalidBlockVolumeError("Файл зашифрованного диска не найден.")

        stream = source.open("r+b")
        try:
            raw_prefix = cls._read_exact(stream, HEADER_PREFIX.size)
            magic, version, header_size = HEADER_PREFIX.unpack(raw_prefix)
            if magic != MAGIC or version != FORMAT_VERSION:
                raise InvalidBlockVolumeError(
                    "Это не блочный диск Clever PGP поддерживаемой версии."
                )
            if header_size != HEADER_AREA_SIZE:
                raise InvalidBlockVolumeError("Некорректный размер заголовка диска.")
            header_area = cls._read_exact(stream, header_size)
            metadata = cls._decode_header(header_area)
            cls._validate_metadata(metadata)

            wrapped_key = base64.b64decode(
                str(metadata["wrapped_volume_key"]), validate=True
            )
            volume_key = secret.SecretBox(master_key).decrypt(wrapped_key)
            volume_id = base64.b64decode(
                str(metadata["volume_id"]), validate=True
            )
            expected_auth = base64.b64decode(
                str(metadata["header_auth"]), validate=True
            )
            authenticated_metadata = dict(metadata)
            del authenticated_metadata["header_auth"]
            actual_auth = hash.blake2b(
                cls._canonical_metadata(authenticated_metadata),
                key=volume_key,
                digest_size=32,
                encoder=RawEncoder,
            )
            if not bindings.sodium_memcmp(expected_auth, actual_auth):
                raise InvalidBlockVolumeError(
                    "Заголовок зашифрованного диска повреждён."
                )

            block_count = int(metadata["block_count"])
            if len(volume_id) != 16:
                raise InvalidBlockVolumeError("Некорректный идентификатор диска.")
            if source.stat().st_size != cls.physical_size(block_count):
                raise InvalidBlockVolumeError(
                    "Размер файла не соответствует заголовку диска."
                )
        except (
            OSError,
            struct.error,
            KeyError,
            TypeError,
            ValueError,
            binascii.Error,
            exceptions.CryptoError,
        ) as error:
            stream.close()
            if isinstance(error, InvalidBlockVolumeError):
                raise
            raise InvalidBlockVolumeError(
                "Диск повреждён или создан другим профилем."
            ) from error

        return cls(source, stream, volume_key, volume_id, block_count, metadata)

    @property
    def block_count(self) -> int:
        return self._block_count

    @property
    def logical_capacity(self) -> int:
        return self._block_count * LOGICAL_BLOCK_SIZE

    @property
    def label(self) -> str:
        return str(self._metadata["label"])

    @property
    def volume_id(self) -> bytes:
        return self._volume_id

    @property
    def storage_format(self) -> str | None:
        value = self._metadata.get("storage_format")
        return str(value) if isinstance(value, str) and value else None

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
                                self._volume_id,
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
                    self._volume_id,
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

    def __enter__(self) -> EncryptedBlockVolume:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @staticmethod
    def physical_size(block_count: int) -> int:
        if not isinstance(block_count, int) or block_count <= 0:
            raise ValidationError("Некорректное число блоков диска.")
        return HEADER_PREFIX.size + HEADER_AREA_SIZE + block_count * PHYSICAL_SLOT_SIZE

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
    def _validate_master_key(master_key: bytes) -> None:
        if not isinstance(master_key, bytes) or len(master_key) != secret.SecretBox.KEY_SIZE:
            raise ValidationError("Некорректный мастер-ключ профиля.")

    def _validate_range(self, block_address: int, block_count: int) -> None:
        if (
            not isinstance(block_address, int)
            or not isinstance(block_count, int)
            or block_address < 0
            or block_count <= 0
            or block_address + block_count > self._block_count
        ):
            raise ValidationError("Запрошенный диапазон блоков выходит за границы диска.")

    def _ensure_open(self) -> None:
        if self._closed:
            raise InvalidBlockVolumeError("Зашифрованный диск уже закрыт.")

    @staticmethod
    def _slot_offset(block_address: int) -> int:
        return HEADER_PREFIX.size + HEADER_AREA_SIZE + block_address * PHYSICAL_SLOT_SIZE

    @staticmethod
    def _block_aad(
        volume_id: bytes, block_index: int, context: bytes = b""
    ) -> bytes:
        return MAGIC + volume_id + struct.pack(">Q", block_index) + context

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

    @staticmethod
    def _validate_context(context: bytes) -> bytes:
        if not isinstance(context, bytes) or len(context) > 64:
            raise ValidationError("Некорректный контекст логического блока.")
        return context

    @staticmethod
    def _canonical_metadata(metadata: dict[str, object]) -> bytes:
        return json.dumps(
            metadata,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def _encode_header(cls, metadata: dict[str, object]) -> bytes:
        encoded = cls._canonical_metadata(metadata)
        if len(encoded) + HEADER_JSON_LENGTH.size > HEADER_AREA_SIZE:
            raise ValidationError("Заголовок диска слишком большой.")
        padding_size = HEADER_AREA_SIZE - HEADER_JSON_LENGTH.size - len(encoded)
        header_area = HEADER_JSON_LENGTH.pack(len(encoded)) + encoded + utils.random(
            padding_size
        )
        return HEADER_PREFIX.pack(MAGIC, FORMAT_VERSION, HEADER_AREA_SIZE) + header_area

    @staticmethod
    def _decode_header(header_area: bytes) -> dict[str, object]:
        if len(header_area) != HEADER_AREA_SIZE:
            raise InvalidBlockVolumeError("Заголовок диска оборван.")
        (json_size,) = HEADER_JSON_LENGTH.unpack(
            header_area[: HEADER_JSON_LENGTH.size]
        )
        if not 1 <= json_size <= HEADER_AREA_SIZE - HEADER_JSON_LENGTH.size:
            raise InvalidBlockVolumeError("Некорректная длина заголовка диска.")
        decoded = json.loads(
            header_area[
                HEADER_JSON_LENGTH.size : HEADER_JSON_LENGTH.size + json_size
            ].decode("utf-8")
        )
        if not isinstance(decoded, dict):
            raise InvalidBlockVolumeError("Некорректный заголовок диска.")
        return decoded

    @classmethod
    def _validate_metadata(cls, metadata: dict[str, object]) -> None:
        if metadata.get("algorithm") != ALGORITHM or metadata.get("key_wrap") != KEY_WRAP:
            raise InvalidBlockVolumeError("Неподдерживаемый метод защиты диска.")
        if int(metadata.get("logical_block_size", 0)) != LOGICAL_BLOCK_SIZE:
            raise InvalidBlockVolumeError("Неподдерживаемый размер блока диска.")
        block_count = int(metadata.get("block_count", 0))
        if block_count <= 0:
            raise InvalidBlockVolumeError("Некорректное число блоков диска.")
        if not str(metadata.get("label", "")):
            raise InvalidBlockVolumeError("В заголовке отсутствует название диска.")
        storage_format = metadata.get("storage_format")
        if storage_format is not None and (
            not isinstance(storage_format, str) or not storage_format
        ):
            raise InvalidBlockVolumeError("Некорректное назначение блочного хранилища.")
        for name in ("volume_id", "wrapped_volume_key", "header_auth"):
            if not isinstance(metadata.get(name), str):
                raise InvalidBlockVolumeError("Заголовок диска содержит неверные поля.")

    @staticmethod
    def _read_exact(stream: object, size: int) -> bytes:
        data = stream.read(size)
        if len(data) != size:
            raise InvalidBlockVolumeError("Файл зашифрованного диска оборван.")
        return data
