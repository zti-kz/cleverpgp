from __future__ import annotations

import base64
import binascii
import hashlib
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

from nacl import bindings, exceptions, hash, pwhash, secret, utils
from nacl.encoding import RawEncoder

from cleverpgp.core.disk_crypto import (
    DEFAULT_DISK_ALGORITHM,
    DISK_NONCE_FIELD_SIZE,
    DISK_TAG_SIZE,
    random_nonce_fields,
    require_disk_cipher,
)
from cleverpgp.core.errors import ContainerError, OutputExistsError, ValidationError
from cleverpgp.core.mapped_stream import MappedFileStream

MAGIC = b"CPGPBLK5"
FORMAT_VERSION = 5
HEADER_PREFIX = struct.Struct(">8sBI")
HEADER_AREA_SIZE = 64 * 1024
HEADER_JSON_LENGTH = struct.Struct(">I")
BLOCK_INDEX = struct.Struct(">Q")
HEADER_SLOT_COUNT = 3
HEADER_SLOT_SIZE = HEADER_AREA_SIZE // HEADER_SLOT_COUNT
HEADER_UNUSED_SIZE = HEADER_AREA_SIZE - HEADER_SLOT_COUNT * HEADER_SLOT_SIZE
LOGICAL_BLOCK_SIZE = 4096
NONCE_SIZE = DISK_NONCE_FIELD_SIZE
TAG_SIZE = DISK_TAG_SIZE
PHYSICAL_SLOT_SIZE = NONCE_SIZE + LOGICAL_BLOCK_SIZE + TAG_SIZE
MIN_LOGICAL_CAPACITY = 1024 * 1024
INITIALIZATION_BATCH_BLOCKS = 256
ALGORITHM_CONVERSION_BATCH_BLOCKS = 256
ALGORITHM = DEFAULT_DISK_ALGORITHM
KEY_WRAP = "XSALSA20-POLY1305-SECRETBOX"
GENERIC_STORAGE_FORMAT = "CLEVERPGP-AUTHENTICATED-BLOCKS-V2"
HEADER_STATE_COMMITTED = "committed"
HEADER_STATE_PREPARING = "preparing"
PASSWORD_KDF = "ARGON2ID13"
PASSWORD_WRAP_FIELD = "password_wrapped_volume_key"
PASSWORD_SALT_FIELD = "password_kdf_salt"
PASSWORD_OPSLIMIT_FIELD = "password_kdf_opslimit"
PASSWORD_MEMLIMIT_FIELD = "password_kdf_memlimit"
PROFILE_WRAP_LIST_FIELD = "profile_wrapped_volume_keys"
MAXIMUM_ADDITIONAL_PROFILE_SLOTS = 8
MINIMUM_PASSWORD_LENGTH = 12
MAXIMUM_PASSWORD_BYTES = 1024
MAXIMUM_KDF_MEMORY = pwhash.argon2id.MEMLIMIT_SENSITIVE
MAXIMUM_KDF_OPERATIONS = pwhash.argon2id.OPSLIMIT_SENSITIVE


class BlockVolumeError(ContainerError):
    """Base class for block volume errors safe to show to the user."""


class InvalidBlockVolumeError(BlockVolumeError):
    pass


class BlockIntegrityError(BlockVolumeError):
    pass


class EncryptedBlockVolume:
    """Random-access authenticated storage for the version 5 disk backend.

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
        *,
        active_header_slot: int,
        pending_resize: bool = False,
    ) -> None:
        self.path = Path(path)
        self._stream = stream
        self._volume_key = bytearray(volume_key)
        self._volume_id = bytes(volume_id)
        self._block_count = block_count
        self._metadata = metadata
        self._cipher = require_disk_cipher(str(metadata["algorithm"]))
        self._active_header_slot = active_header_slot
        self._header_generation = int(metadata["header_generation"])
        self._pending_resize = pending_resize
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
        algorithm: str = ALGORITHM,
        password: str | None = None,
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
        cipher = require_disk_cipher(algorithm)

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
            "algorithm": cipher.identifier,
            "block_count": block_count,
            "created_at": datetime.now(UTC).isoformat(),
            "header_generation": 1,
            "key_wrap": KEY_WRAP,
            "label": label,
            "logical_block_size": LOGICAL_BLOCK_SIZE,
            "storage_format": storage_format,
            "resize_state": HEADER_STATE_COMMITTED,
            "volume_id": base64.b64encode(volume_id).decode("ascii"),
            "wrapped_volume_key": base64.b64encode(wrapped_key).decode("ascii"),
        }
        if password is not None:
            password_bytes = cls._validate_password(password)
            password_salt = utils.random(pwhash.argon2id.SALTBYTES)
            password_access_key = cls._derive_password_key(
                password_bytes,
                password_salt,
                pwhash.argon2id.OPSLIMIT_MODERATE,
                pwhash.argon2id.MEMLIMIT_MODERATE,
            )
            try:
                metadata.update(
                    {
                        "password_kdf": PASSWORD_KDF,
                        PASSWORD_SALT_FIELD: base64.b64encode(
                            password_salt
                        ).decode("ascii"),
                        PASSWORD_OPSLIMIT_FIELD: pwhash.argon2id.OPSLIMIT_MODERATE,
                        PASSWORD_MEMLIMIT_FIELD: pwhash.argon2id.MEMLIMIT_MODERATE,
                        PASSWORD_WRAP_FIELD: base64.b64encode(
                            bytes(
                                secret.SecretBox(password_access_key).encrypt(
                                    volume_key
                                )
                            )
                        ).decode("ascii"),
                    }
                )
            finally:
                del password_access_key
        metadata = cls._authenticated_metadata(metadata, volume_key)
        raw_header = cls._encode_initial_header(metadata)

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
                                zero_block,
                                block_index,
                                volume_id,
                                volume_key,
                                algorithm=cipher.identifier,
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
            candidates = cls._authenticated_header_candidates(
                header_area,
                master_key,
            )
            metadata, volume_key, volume_id, active_slot, pending_resize = (
                cls._select_header_candidate(
                    candidates,
                    physical_file_size=source.stat().st_size,
                )
            )
            block_count = int(metadata["block_count"])
        except InvalidBlockVolumeError:
            stream.close()
            raise
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
            raise InvalidBlockVolumeError(
                "Диск повреждён или создан другим профилем."
            ) from error

        return cls(
            source,
            stream,
            volume_key,
            volume_id,
            block_count,
            metadata,
            active_header_slot=active_slot,
            pending_resize=pending_resize,
        )

    @classmethod
    def password_access_key(cls, path: Path, password: str) -> bytes:
        """Authenticate a portable password slot and return its access key.

        The returned key is equivalent only to a wrapping credential for this
        disk. It is never used as the block-encryption key itself.
        """

        source = Path(path).expanduser().resolve()
        if not source.is_file():
            raise InvalidBlockVolumeError("Файл зашифрованного диска не найден.")
        password_bytes = cls._validate_password(password)
        with source.open("rb") as stream:
            raw_prefix = cls._read_exact(stream, HEADER_PREFIX.size)
            magic, version, header_size = HEADER_PREFIX.unpack(raw_prefix)
            if magic != MAGIC or version != FORMAT_VERSION:
                raise InvalidBlockVolumeError(
                    "Это не переносимый зашифрованный диск Clever PGP."
                )
            if header_size != HEADER_AREA_SIZE:
                raise InvalidBlockVolumeError("Некорректный размер заголовка диска.")
            header_area = cls._read_exact(stream, header_size)

        candidates: set[tuple[bytes, int, int]] = set()
        for slot in range(HEADER_SLOT_COUNT):
            start = slot * HEADER_SLOT_SIZE
            try:
                metadata = cls._decode_header_slot(
                    header_area[start : start + HEADER_SLOT_SIZE]
                )
                cls._validate_metadata(metadata)
                if PASSWORD_WRAP_FIELD not in metadata:
                    continue
                salt = base64.b64decode(
                    str(metadata[PASSWORD_SALT_FIELD]), validate=True
                )
                operations = int(metadata[PASSWORD_OPSLIMIT_FIELD])
                memory = int(metadata[PASSWORD_MEMLIMIT_FIELD])
                cls._validate_password_kdf(operations, memory)
                if len(salt) != pwhash.argon2id.SALTBYTES:
                    raise ValueError("password salt")
                candidates.add((salt, operations, memory))
            except (
                InvalidBlockVolumeError,
                KeyError,
                TypeError,
                ValueError,
                binascii.Error,
            ):
                continue

        for salt, operations, memory in candidates:
            access_key = cls._derive_password_key(
                password_bytes,
                salt,
                operations,
                memory,
            )
            try:
                authenticated = cls._authenticated_header_candidates(
                    header_area,
                    access_key,
                )
                cls._select_header_candidate(
                    authenticated,
                    physical_file_size=source.stat().st_size,
                )
            except InvalidBlockVolumeError:
                del access_key
                continue
            return access_key
        raise InvalidBlockVolumeError("Неверный пароль зашифрованного диска.")

    @classmethod
    def open_with_password(
        cls,
        path: Path,
        password: str,
    ) -> EncryptedBlockVolume:
        access_key = cls.password_access_key(path, password)
        try:
            return cls.open(path, access_key)
        finally:
            del access_key

    @classmethod
    def change_password(
        cls,
        path: Path,
        current_password: str,
        new_password: str,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> Path:
        """Replace only the portable wrapping slot, never the data key."""

        if current_password == new_password:
            raise ValidationError(
                "Новый пароль диска должен отличаться от текущего."
            )
        cls._validate_password(new_password)
        target = Path(path).expanduser().resolve()
        if progress is not None:
            progress(1, 5)
        current_access_key = cls.password_access_key(target, current_password)
        try:
            volume = cls.open(target, current_access_key)
        finally:
            del current_access_key
        try:
            if progress is not None:
                progress(2, 5)
            salt = utils.random(pwhash.argon2id.SALTBYTES)
            new_access_key = cls._derive_password_key(
                new_password.encode("utf-8"),
                salt,
                pwhash.argon2id.OPSLIMIT_MODERATE,
                pwhash.argon2id.MEMLIMIT_MODERATE,
            )
            try:
                metadata = dict(volume._metadata)
                metadata.pop("header_auth", None)
                metadata.update(
                    {
                        "header_generation": volume._header_generation + 1,
                        "password_kdf": PASSWORD_KDF,
                        PASSWORD_SALT_FIELD: base64.b64encode(salt).decode("ascii"),
                        PASSWORD_OPSLIMIT_FIELD: pwhash.argon2id.OPSLIMIT_MODERATE,
                        PASSWORD_MEMLIMIT_FIELD: pwhash.argon2id.MEMLIMIT_MODERATE,
                        PASSWORD_WRAP_FIELD: base64.b64encode(
                            bytes(
                                secret.SecretBox(new_access_key).encrypt(
                                    bytes(volume._volume_key)
                                )
                            )
                        ).decode("ascii"),
                    }
                )
            finally:
                del new_access_key
            authenticated = cls._authenticated_metadata(
                metadata,
                bytes(volume._volume_key),
            )
            new_slot = (volume._active_header_slot + 1) % HEADER_SLOT_COUNT
            volume._write_verified_header_slot(new_slot, authenticated)
            if progress is not None:
                progress(4, 5)
            for slot in range(HEADER_SLOT_COUNT):
                if slot != new_slot:
                    volume._invalidate_header_slot(slot)
            volume._metadata = authenticated
            volume._active_header_slot = new_slot
            volume._header_generation = int(authenticated["header_generation"])
            if progress is not None:
                progress(5, 5)
        finally:
            volume.close()
        return target

    @classmethod
    def add_profile_access(
        cls,
        path: Path,
        password: str,
        profile_master_key: bytes,
    ) -> Path:
        """Add a local profile slot after the portable password succeeds."""

        cls._validate_master_key(profile_master_key)
        target = Path(path).expanduser().resolve()
        try:
            already_linked = cls.open(target, profile_master_key)
        except InvalidBlockVolumeError:
            pass
        else:
            already_linked.close()
            return target

        portable_key = cls.password_access_key(target, password)
        try:
            volume = cls.open(target, portable_key)
        finally:
            del portable_key
        try:
            profile_slots = list(
                volume._metadata.get(PROFILE_WRAP_LIST_FIELD, [])
            )
            if len(profile_slots) >= MAXIMUM_ADDITIONAL_PROFILE_SLOTS:
                raise ValidationError(
                    "Достигнут предел локальных профилей для этого диска."
                )
            profile_slots.append(
                base64.b64encode(
                    bytes(
                        secret.SecretBox(profile_master_key).encrypt(
                            bytes(volume._volume_key)
                        )
                    )
                ).decode("ascii")
            )
            metadata = dict(volume._metadata)
            metadata.pop("header_auth", None)
            metadata.update(
                {
                    "header_generation": volume._header_generation + 1,
                    PROFILE_WRAP_LIST_FIELD: profile_slots,
                }
            )
            authenticated = cls._authenticated_metadata(
                metadata,
                bytes(volume._volume_key),
            )
            new_slot = (volume._active_header_slot + 1) % HEADER_SLOT_COUNT
            volume._write_verified_header_slot(new_slot, authenticated)
            for slot in range(HEADER_SLOT_COUNT):
                if slot != new_slot:
                    volume._invalidate_header_slot(slot)
            volume._metadata = authenticated
            volume._active_header_slot = new_slot
            volume._header_generation = int(authenticated["header_generation"])
        finally:
            volume.close()
        return target

    @classmethod
    def convert_algorithm_atomic(
        cls,
        path: Path,
        master_key: bytes,
        algorithm: str,
        *,
        required_storage_format: str,
        progress: Callable[[int, int], None] | None = None,
    ) -> Path:
        """Re-encrypt a closed block image without risking the original file.

        The source is authenticated block by block and a complete replacement
        image is written beside it with a fresh volume key and volume id.  The
        original path is replaced only after the new header and exact physical
        size have been reopened and verified.  This method intentionally
        requires an exact storage format because callers must know that its
        blocks use the empty authenticated context.
        """

        target = Path(path).expanduser().resolve()
        cls._validate_master_key(master_key)
        if (
            not isinstance(required_storage_format, str)
            or not required_storage_format
        ):
            raise ValidationError("Некорректное назначение блочного хранилища.")
        target_cipher = require_disk_cipher(algorithm)
        temporary_path: Path | None = None
        replacement_key = bytearray(utils.random(secret.SecretBox.KEY_SIZE))
        try:
            with cls.open(target, master_key) as source:
                if source.storage_format != required_storage_format:
                    raise ValidationError(
                        "Изменение метода недоступно для этого типа зашифрованного диска."
                    )
                if source._pending_resize:
                    raise ValidationError(
                        "Сначала завершите или повторите увеличение зашифрованного диска."
                    )
                if PASSWORD_WRAP_FIELD in source._metadata:
                    raise ValidationError(
                        "Для переносимого диска изменение метода требует пароль "
                        "самого диска. Эта операция будет добавлена отдельно."
                    )
                if source.algorithm == target_cipher.identifier:
                    if progress is not None:
                        progress(1, 1)
                    return target

                source_state = target.stat()
                block_count = source.block_count
                required_size = cls.physical_size(block_count)
                if int(shutil.disk_usage(target.parent).free) < required_size:
                    raise ValidationError(
                        "Для безопасной смены метода недостаточно свободного места "
                        "на накопителе контейнера."
                    )

                replacement_volume_id = uuid.uuid4().bytes
                replacement_key_bytes = bytes(replacement_key)
                wrapped_key = bytes(
                    secret.SecretBox(master_key).encrypt(replacement_key_bytes)
                )
                metadata: dict[str, object] = {
                    "algorithm": target_cipher.identifier,
                    "block_count": block_count,
                    "created_at": str(source._metadata["created_at"]),
                    "converted_at": datetime.now(UTC).isoformat(),
                    "header_generation": source._header_generation + 1,
                    "key_wrap": KEY_WRAP,
                    "label": source.label,
                    "logical_block_size": LOGICAL_BLOCK_SIZE,
                    "storage_format": required_storage_format,
                    "resize_state": HEADER_STATE_COMMITTED,
                    "volume_id": base64.b64encode(replacement_volume_id).decode(
                        "ascii"
                    ),
                    "wrapped_volume_key": base64.b64encode(wrapped_key).decode(
                        "ascii"
                    ),
                }
                metadata = cls._authenticated_metadata(
                    metadata,
                    replacement_key_bytes,
                )

                temporary = tempfile.NamedTemporaryFile(
                    mode="w+b",
                    prefix=f".{target.name}.algorithm-",
                    suffix=".tmp",
                    dir=target.parent,
                    delete=False,
                )
                temporary_path = Path(temporary.name)
                with temporary as output:
                    output.write(cls._encode_initial_header(metadata))
                    completed = 0
                    total_work = block_count * 2
                    source_digest = hashlib.blake2b(
                        digest_size=32,
                        person=b"CPGP-CONVERT-V1",
                    )
                    if progress is not None:
                        progress(0, total_work)
                    while completed < block_count:
                        batch_count = min(
                            ALGORITHM_CONVERSION_BATCH_BLOCKS,
                            block_count - completed,
                        )
                        plaintext = source.read_blocks(completed, batch_count)
                        source_digest.update(plaintext)
                        nonce_fields = random_nonce_fields(batch_count)
                        encrypted = bytearray()
                        for offset in range(batch_count):
                            plaintext_start = offset * LOGICAL_BLOCK_SIZE
                            nonce_start = offset * NONCE_SIZE
                            nonce = nonce_fields[
                                nonce_start : nonce_start + NONCE_SIZE
                            ]
                            block_index = completed + offset
                            encrypted.extend(nonce)
                            encrypted.extend(
                                target_cipher.encrypt(
                                    plaintext[
                                        plaintext_start : plaintext_start
                                        + LOGICAL_BLOCK_SIZE
                                    ],
                                    cls._block_aad(
                                        replacement_volume_id,
                                        block_index,
                                    ),
                                    nonce,
                                    replacement_key_bytes,
                                )
                            )
                        output.write(encrypted)
                        completed += batch_count
                        if progress is not None:
                            progress(completed, total_work)
                    output.flush()
                    os.fsync(output.fileno())

            current_state = target.stat()
            if (
                current_state.st_size != source_state.st_size
                or current_state.st_mtime_ns != source_state.st_mtime_ns
            ):
                raise ValidationError(
                    "Зашифрованный диск изменился во время преобразования. "
                    "Исходный контейнер сохранён."
                )
            assert temporary_path is not None
            with cls.open(temporary_path, master_key) as verified:
                if (
                    verified.algorithm != target_cipher.identifier
                    or verified.block_count != block_count
                    or verified.storage_format != required_storage_format
                ):
                    raise BlockVolumeError(
                        "Не удалось проверить преобразованный зашифрованный диск."
                    )
                verified_digest = hashlib.blake2b(
                    digest_size=32,
                    person=b"CPGP-CONVERT-V1",
                )
                verified_blocks = 0
                while verified_blocks < block_count:
                    batch_count = min(
                        ALGORITHM_CONVERSION_BATCH_BLOCKS,
                        block_count - verified_blocks,
                    )
                    verified_digest.update(
                        verified.read_blocks(verified_blocks, batch_count)
                    )
                    verified_blocks += batch_count
                    if progress is not None:
                        progress(block_count + verified_blocks, total_work)
                if not bindings.sodium_memcmp(
                    source_digest.digest(),
                    verified_digest.digest(),
                ):
                    raise BlockVolumeError(
                        "Содержимое преобразованного диска не совпадает с исходным."
                    )
            os.replace(temporary_path, target)
            temporary_path = None
            return target
        finally:
            for index in range(len(replacement_key)):
                replacement_key[index] = 0
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

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

    @property
    def algorithm(self) -> str:
        return self._cipher.identifier

    @property
    def has_portable_password(self) -> bool:
        return PASSWORD_WRAP_FIELD in self._metadata

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
            self._stream.seek(self._slot_offset(block_address))
            slots = self._read_exact(
                self._stream,
                block_count * PHYSICAL_SLOT_SIZE,
            )
            volume_key = bytes(self._volume_key)
            volume_id = self._volume_id

        # The backing file is needed only for the contiguous read above. Crypto
        # can run outside the stream lock so independent WinSpd requests are not
        # needlessly serialized by Python while every block is authenticated.
        result = bytearray()
        append_plaintext = result.extend
        decrypt_block = self._cipher.decrypt
        encode_block_index = BLOCK_INDEX.pack
        aad_prefix = MAGIC + volume_id
        for offset in range(block_count):
            slot_start = offset * PHYSICAL_SLOT_SIZE
            nonce_end = slot_start + NONCE_SIZE
            slot_end = slot_start + PHYSICAL_SLOT_SIZE
            block_index = block_address + offset
            try:
                append_plaintext(
                    decrypt_block(
                        slots[nonce_end:slot_end],
                        aad_prefix
                        + encode_block_index(block_index)
                        + authenticated_context,
                        slots[slot_start:nonce_end],
                        volume_key,
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
        with self._lock:
            self._ensure_open()
            volume_key = bytes(self._volume_key)
            volume_id = self._volume_id

        encrypted = bytearray()
        append_encrypted = encrypted.extend
        encrypt_block = self._cipher.encrypt
        encode_block_index = BLOCK_INDEX.pack
        aad_prefix = MAGIC + volume_id
        nonces = random_nonce_fields(block_count)
        for offset in range(block_count):
            start = offset * LOGICAL_BLOCK_SIZE
            block_index = block_address + offset
            nonce_start = offset * NONCE_SIZE
            nonce = nonces[nonce_start : nonce_start + NONCE_SIZE]
            append_encrypted(nonce)
            append_encrypted(
                encrypt_block(
                    payload[start : start + LOGICAL_BLOCK_SIZE],
                    aad_prefix
                    + encode_block_index(block_index)
                    + authenticated_context,
                    nonce,
                    volume_key,
                )
            )
        with self._lock:
            self._ensure_open()
            self._stream.seek(self._slot_offset(block_address))
            self._stream.write(encrypted)

    def resize(
        self,
        logical_capacity: int,
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> None:
        """Increase the logical capacity with a crash-recoverable header update."""

        new_block_count = self._block_count_for_capacity(logical_capacity)
        with self._lock:
            self._ensure_open()
            if new_block_count < self._block_count:
                raise ValidationError(
                    "Уменьшение зашифрованного диска пока не поддерживается безопасно."
                )
            if new_block_count == self._block_count:
                if progress is not None:
                    progress(1, 1)
                return

            self._discard_incomplete_resize()
            added_blocks = new_block_count - self._block_count
            required_growth = added_blocks * PHYSICAL_SLOT_SIZE
            free_bytes = int(shutil.disk_usage(self.path.parent).free)
            if required_growth > free_bytes:
                raise ValidationError(
                    "Недостаточно свободного места на выбранном накопителе."
                )

            generation = self._header_generation + 1
            resized_at = datetime.now(UTC).isoformat()
            preparing_slot = (self._active_header_slot + 1) % HEADER_SLOT_COUNT
            committed_slot = (self._active_header_slot + 2) % HEADER_SLOT_COUNT
            base_metadata = dict(self._metadata)
            base_metadata.pop("header_auth", None)
            base_metadata.update(
                {
                    "block_count": new_block_count,
                    "header_generation": generation,
                    "resized_at": resized_at,
                }
            )
            preparing_metadata = dict(base_metadata)
            preparing_metadata["resize_state"] = HEADER_STATE_PREPARING
            preparing_metadata = self._authenticated_metadata(
                preparing_metadata,
                bytes(self._volume_key),
            )
            self._write_verified_header_slot(preparing_slot, preparing_metadata)
            self.flush()
            self._pending_resize = True

            zero_block = bytes(LOGICAL_BLOCK_SIZE)
            completed = 0
            self._stream.seek(self.physical_size(self._block_count))
            while completed < added_blocks:
                batch_count = min(
                    INITIALIZATION_BATCH_BLOCKS,
                    added_blocks - completed,
                )
                batch = bytearray()
                for offset in range(batch_count):
                    block_index = self._block_count + completed + offset
                    arguments = (
                        zero_block,
                        block_index,
                        self._volume_id,
                        bytes(self._volume_key),
                    )
                    if self.algorithm == ALGORITHM:
                        # Preserve the established extension/testing surface
                        # for the original on-disk method.
                        encrypted_block = self._encrypt_block(*arguments)
                    else:
                        encrypted_block = self._encrypt_block(
                            *arguments,
                            algorithm=self.algorithm,
                        )
                    batch.extend(encrypted_block)
                self._stream.write(batch)
                completed += batch_count
                if progress is not None:
                    progress(completed, added_blocks)
            self.flush()

            committed_metadata = dict(base_metadata)
            committed_metadata["resize_state"] = HEADER_STATE_COMMITTED
            committed_metadata = self._authenticated_metadata(
                committed_metadata,
                bytes(self._volume_key),
            )
            self._write_verified_header_slot(committed_slot, committed_metadata)
            self.flush()
            previous_active_slot = self._active_header_slot
            self._metadata = committed_metadata
            self._block_count = new_block_count
            self._active_header_slot = committed_slot
            self._header_generation = generation
            self._pending_resize = False
            try:
                self._invalidate_header_slot(previous_active_slot)
            except OSError:
                # The new committed header is already durable. Keeping the old
                # authenticated slot is safe, although less strict against a
                # later whole-file rollback.
                pass

    def flush(self) -> None:
        with self._lock:
            self._ensure_open()
            self._stream.flush()
            os.fsync(self._stream.fileno())

    def enable_mapped_io(self) -> bool:
        """Use mapped ciphertext I/O for a live WinSpd session when available."""

        with self._lock:
            self._ensure_open()
            if isinstance(self._stream, MappedFileStream):
                return True
            try:
                mapped = MappedFileStream(self.path)
            except (OSError, ValueError, OverflowError):
                return False
            try:
                self._stream.flush()
                os.fsync(self._stream.fileno())
                self._stream.close()
            except Exception:
                mapped.close()
                raise
            self._stream = mapped
            return True

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
        return MAGIC + volume_id + BLOCK_INDEX.pack(block_index) + context

    @classmethod
    def _encrypt_block(
        cls,
        plaintext: bytes,
        block_index: int,
        volume_id: bytes,
        volume_key: bytes,
        context: bytes = b"",
        *,
        algorithm: str = ALGORITHM,
    ) -> bytes:
        nonce = utils.random(NONCE_SIZE)
        ciphertext = require_disk_cipher(algorithm).encrypt(
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
    def _encode_initial_header(cls, metadata: dict[str, object]) -> bytes:
        first_slot = cls._encode_header_slot(metadata)
        remaining_slots = utils.random(HEADER_SLOT_SIZE * (HEADER_SLOT_COUNT - 1))
        unused = utils.random(HEADER_UNUSED_SIZE)
        return (
            HEADER_PREFIX.pack(MAGIC, FORMAT_VERSION, HEADER_AREA_SIZE)
            + first_slot
            + remaining_slots
            + unused
        )

    @classmethod
    def _encode_header_slot(cls, metadata: dict[str, object]) -> bytes:
        encoded = cls._canonical_metadata(metadata)
        if len(encoded) + HEADER_JSON_LENGTH.size > HEADER_SLOT_SIZE:
            raise ValidationError("Заголовок диска слишком большой.")
        padding_size = HEADER_SLOT_SIZE - HEADER_JSON_LENGTH.size - len(encoded)
        return HEADER_JSON_LENGTH.pack(len(encoded)) + encoded + utils.random(
            padding_size
        )

    @staticmethod
    def _decode_header_slot(header_area: bytes) -> dict[str, object]:
        if len(header_area) != HEADER_SLOT_SIZE:
            raise InvalidBlockVolumeError("Слот заголовка диска оборван.")
        (json_size,) = HEADER_JSON_LENGTH.unpack(
            header_area[: HEADER_JSON_LENGTH.size]
        )
        if not 1 <= json_size <= HEADER_SLOT_SIZE - HEADER_JSON_LENGTH.size:
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
    def _authenticated_header_candidates(
        cls,
        header_area: bytes,
        master_key: bytes,
    ) -> list[tuple[dict[str, object], bytes, bytes, int]]:
        if len(header_area) != HEADER_AREA_SIZE:
            raise InvalidBlockVolumeError("Заголовок диска оборван.")
        candidates: list[tuple[dict[str, object], bytes, bytes, int]] = []
        for slot in range(HEADER_SLOT_COUNT):
            start = slot * HEADER_SLOT_SIZE
            try:
                metadata = cls._decode_header_slot(
                    header_area[start : start + HEADER_SLOT_SIZE]
                )
                cls._validate_metadata(metadata)
                volume_key: bytes | None = None
                wrapped_values = [str(metadata["wrapped_volume_key"])]
                wrapped_values.extend(
                    str(value)
                    for value in metadata.get(PROFILE_WRAP_LIST_FIELD, [])
                )
                if PASSWORD_WRAP_FIELD in metadata:
                    wrapped_values.append(str(metadata[PASSWORD_WRAP_FIELD]))
                for encoded_wrapped_key in wrapped_values:
                    try:
                        wrapped_key = base64.b64decode(
                            encoded_wrapped_key,
                            validate=True,
                        )
                        volume_key = secret.SecretBox(master_key).decrypt(
                            wrapped_key
                        )
                        break
                    except (binascii.Error, exceptions.CryptoError, ValueError):
                        continue
                if volume_key is None:
                    raise exceptions.CryptoError("key slot")
                volume_id = base64.b64decode(
                    str(metadata["volume_id"]),
                    validate=True,
                )
                if len(volume_id) != 16:
                    raise ValueError("volume id")
                expected_auth = base64.b64decode(
                    str(metadata["header_auth"]),
                    validate=True,
                )
                actual_auth = cls._metadata_auth(metadata, volume_key)
                if not bindings.sodium_memcmp(expected_auth, actual_auth):
                    raise ValueError("header authentication")
            except (
                InvalidBlockVolumeError,
                KeyError,
                TypeError,
                ValueError,
                binascii.Error,
                exceptions.CryptoError,
            ):
                continue
            candidates.append((metadata, volume_key, volume_id, slot))
        if not candidates:
            raise InvalidBlockVolumeError(
                "Диск повреждён или создан другим профилем."
            )
        identities = {
            (candidate[1], candidate[2], candidate[0]["algorithm"])
            for candidate in candidates
        }
        if len(identities) != 1:
            raise InvalidBlockVolumeError(
                "Заголовки диска относятся к разным криптографическим томам."
            )
        return candidates

    @classmethod
    def _select_header_candidate(
        cls,
        candidates: list[tuple[dict[str, object], bytes, bytes, int]],
        *,
        physical_file_size: int,
    ) -> tuple[dict[str, object], bytes, bytes, int, bool]:
        committed = [
            candidate
            for candidate in candidates
            if candidate[0]["resize_state"] == HEADER_STATE_COMMITTED
        ]
        exact = [
            candidate
            for candidate in committed
            if cls.physical_size(int(candidate[0]["block_count"]))
            == physical_file_size
        ]
        if exact:
            selected = max(
                exact,
                key=lambda candidate: int(candidate[0]["header_generation"]),
            )
            return (*selected, False)

        older = [
            candidate
            for candidate in committed
            if cls.physical_size(int(candidate[0]["block_count"]))
            < physical_file_size
        ]
        if not older:
            raise InvalidBlockVolumeError(
                "Размер файла не соответствует подтверждённому заголовку диска."
            )
        selected = max(
            older,
            key=lambda candidate: int(candidate[0]["header_generation"]),
        )
        selected_generation = int(selected[0]["header_generation"])
        pending = any(
            candidate[0]["resize_state"] == HEADER_STATE_PREPARING
            and int(candidate[0]["header_generation"]) > selected_generation
            and cls.physical_size(int(candidate[0]["block_count"]))
            >= physical_file_size
            for candidate in candidates
        )
        if not pending:
            raise InvalidBlockVolumeError(
                "Обнаружены неаутентифицированные данные после конца диска."
            )
        return (*selected, True)

    @classmethod
    def _validate_metadata(cls, metadata: dict[str, object]) -> None:
        try:
            require_disk_cipher(str(metadata.get("algorithm", "")))
        except ValidationError as error:
            raise InvalidBlockVolumeError(str(error)) from error
        if metadata.get("key_wrap") != KEY_WRAP:
            raise InvalidBlockVolumeError("Неподдерживаемый метод защиты диска.")
        if int(metadata.get("logical_block_size", 0)) != LOGICAL_BLOCK_SIZE:
            raise InvalidBlockVolumeError("Неподдерживаемый размер блока диска.")
        block_count = int(metadata.get("block_count", 0))
        if block_count <= 0:
            raise InvalidBlockVolumeError("Некорректное число блоков диска.")
        if not str(metadata.get("label", "")):
            raise InvalidBlockVolumeError("В заголовке отсутствует название диска.")
        generation = int(metadata.get("header_generation", 0))
        if generation <= 0:
            raise InvalidBlockVolumeError("Некорректное поколение заголовка диска.")
        if metadata.get("resize_state") not in (
            HEADER_STATE_COMMITTED,
            HEADER_STATE_PREPARING,
        ):
            raise InvalidBlockVolumeError("Некорректное состояние размера диска.")
        storage_format = metadata.get("storage_format")
        if storage_format is not None and (
            not isinstance(storage_format, str) or not storage_format
        ):
            raise InvalidBlockVolumeError("Некорректное назначение блочного хранилища.")
        for name in ("volume_id", "wrapped_volume_key", "header_auth"):
            if not isinstance(metadata.get(name), str):
                raise InvalidBlockVolumeError("Заголовок диска содержит неверные поля.")
        password_fields = (
            "password_kdf",
            PASSWORD_SALT_FIELD,
            PASSWORD_OPSLIMIT_FIELD,
            PASSWORD_MEMLIMIT_FIELD,
            PASSWORD_WRAP_FIELD,
        )
        present_password_fields = [name in metadata for name in password_fields]
        if any(present_password_fields):
            if not all(present_password_fields):
                raise InvalidBlockVolumeError(
                    "Парольный слот диска содержит неполные данные."
                )
            if metadata.get("password_kdf") != PASSWORD_KDF:
                raise InvalidBlockVolumeError(
                    "Парольный слот диска использует неподдерживаемый метод."
                )
            try:
                salt = base64.b64decode(
                    str(metadata[PASSWORD_SALT_FIELD]), validate=True
                )
                base64.b64decode(str(metadata[PASSWORD_WRAP_FIELD]), validate=True)
                operations = int(metadata[PASSWORD_OPSLIMIT_FIELD])
                memory = int(metadata[PASSWORD_MEMLIMIT_FIELD])
                cls._validate_password_kdf(operations, memory)
            except (TypeError, ValueError, binascii.Error) as error:
                raise InvalidBlockVolumeError(
                    "Парольный слот диска повреждён."
                ) from error
            if len(salt) != pwhash.argon2id.SALTBYTES:
                raise InvalidBlockVolumeError(
                    "Парольный слот диска содержит неверную соль."
                )
        additional_profiles = metadata.get(PROFILE_WRAP_LIST_FIELD, [])
        if (
            not isinstance(additional_profiles, list)
            or len(additional_profiles) > MAXIMUM_ADDITIONAL_PROFILE_SLOTS
        ):
            raise InvalidBlockVolumeError(
                "Некорректный список локальных профилей диска."
            )
        try:
            for value in additional_profiles:
                if not isinstance(value, str):
                    raise ValueError("profile slot type")
                base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as error:
            raise InvalidBlockVolumeError(
                "Локальный слот профиля диска повреждён."
            ) from error

    @staticmethod
    def _validate_password(password: str) -> bytes:
        if not isinstance(password, str) or len(password) < MINIMUM_PASSWORD_LENGTH:
            raise ValidationError(
                f"Пароль диска должен содержать не менее {MINIMUM_PASSWORD_LENGTH} символов."
            )
        encoded = password.encode("utf-8")
        if len(encoded) > MAXIMUM_PASSWORD_BYTES:
            raise ValidationError("Пароль диска слишком длинный.")
        return encoded

    @staticmethod
    def _validate_password_kdf(opslimit: int, memlimit: int) -> None:
        if not pwhash.argon2id.OPSLIMIT_MIN <= opslimit <= MAXIMUM_KDF_OPERATIONS:
            raise ValueError("password operations")
        if not pwhash.argon2id.MEMLIMIT_MIN <= memlimit <= MAXIMUM_KDF_MEMORY:
            raise ValueError("password memory")

    @classmethod
    def _derive_password_key(
        cls,
        password: bytes,
        salt: bytes,
        opslimit: int,
        memlimit: int,
    ) -> bytes:
        cls._validate_password_kdf(opslimit, memlimit)
        return pwhash.argon2id.kdf(
            secret.SecretBox.KEY_SIZE,
            password,
            salt,
            opslimit=opslimit,
            memlimit=memlimit,
        )

    @classmethod
    def _authenticated_metadata(
        cls,
        metadata: dict[str, object],
        volume_key: bytes,
    ) -> dict[str, object]:
        authenticated = dict(metadata)
        authenticated.pop("header_auth", None)
        authenticated["header_auth"] = base64.b64encode(
            hash.blake2b(
                cls._canonical_metadata(authenticated),
                key=volume_key,
                digest_size=32,
                encoder=RawEncoder,
            )
        ).decode("ascii")
        return authenticated

    @classmethod
    def _metadata_auth(
        cls,
        metadata: dict[str, object],
        volume_key: bytes,
    ) -> bytes:
        authenticated = dict(metadata)
        del authenticated["header_auth"]
        return hash.blake2b(
            cls._canonical_metadata(authenticated),
            key=volume_key,
            digest_size=32,
            encoder=RawEncoder,
        )

    def _write_verified_header_slot(
        self,
        slot: int,
        metadata: dict[str, object],
    ) -> None:
        if not 0 <= slot < HEADER_SLOT_COUNT:
            raise ValueError("Header slot is out of range.")
        encoded = self._encode_header_slot(metadata)
        offset = HEADER_PREFIX.size + slot * HEADER_SLOT_SIZE
        self._stream.seek(offset)
        self._stream.write(encoded)
        self._stream.flush()
        os.fsync(self._stream.fileno())
        self._stream.seek(offset)
        stored = self._read_exact(self._stream, HEADER_SLOT_SIZE)
        if not bindings.sodium_memcmp(stored, encoded):
            raise BlockVolumeError("Не удалось проверить запись заголовка диска.")

    def _discard_incomplete_resize(self) -> None:
        expected_size = self.physical_size(self._block_count)
        actual_size = self.path.stat().st_size
        if actual_size < expected_size:
            raise InvalidBlockVolumeError("Файл зашифрованного диска оборван.")
        if actual_size > expected_size:
            if not self._pending_resize:
                raise InvalidBlockVolumeError(
                    "Обнаружены данные после подтверждённого конца диска."
                )
            self._stream.truncate(expected_size)
            self.flush()
        self._pending_resize = False

    def _invalidate_header_slot(self, slot: int) -> None:
        if not 0 <= slot < HEADER_SLOT_COUNT:
            raise ValueError("Header slot is out of range.")
        offset = HEADER_PREFIX.size + slot * HEADER_SLOT_SIZE
        self._stream.seek(offset)
        self._stream.write(utils.random(HEADER_SLOT_SIZE))
        self._stream.flush()
        os.fsync(self._stream.fileno())

    @staticmethod
    def _read_exact(stream: object, size: int) -> bytes:
        data = stream.read(size)
        if len(data) != size:
            raise InvalidBlockVolumeError("Файл зашифрованного диска оборван.")
        return data
