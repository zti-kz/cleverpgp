from __future__ import annotations

import base64
import binascii
import hmac
import io
import json
import os
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO, Literal

from nacl import bindings, exceptions, pwhash, secret, utils

from biopgp.core.block_volume import LOGICAL_BLOCK_SIZE
from biopgp.core.errors import AuthenticationError, ValidationError
from biopgp.core.hidden_volume import HiddenVolumeDescriptor

OPAQUE_FORMAT_VERSION = 4
OPAQUE_HEADER_MAGIC = b"CPGPHDR4"
OPAQUE_HEADER_RESERVED_SIZE = 128 * 1024
ROLE_AREA_SIZE = OPAQUE_HEADER_RESERVED_SIZE // 2
BANK_COUNT = 2
BANK_SIZE = ROLE_AREA_SIZE // BANK_COUNT
SALT_SIZE = pwhash.argon2id.SALTBYTES
NONCE_SIZE = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
TAG_SIZE = bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES
BANK_PLAINTEXT_SIZE = BANK_SIZE - SALT_SIZE - NONCE_SIZE - TAG_SIZE
PROTECTED_TRANSFER_SIZE = 1 + BANK_PLAINTEXT_SIZE
PAYLOAD_PREFIX = struct.Struct(">8sBQI")
MAXIMUM_PASSWORD_BYTES = 1024
MINIMUM_PASSWORD_LENGTH = 12
MAXIMUM_KDF_MEMORY = pwhash.argon2id.MEMLIMIT_SENSITIVE
MAXIMUM_KDF_OPERATIONS = pwhash.argon2id.OPSLIMIT_SENSITIVE

VolumeRole = Literal["outer", "hidden"]
ProgressCallback = Callable[[int, int], None]


@dataclass(frozen=True, slots=True)
class HeaderKdfParameters:
    opslimit: int = pwhash.argon2id.OPSLIMIT_MODERATE
    memlimit: int = pwhash.argon2id.MEMLIMIT_MODERATE


@dataclass(frozen=True, slots=True)
class OpaqueVolumeHeader:
    """Authenticated key material revealed only after a password succeeds."""

    role: VolumeRole
    generation: int
    cover_volume_id: bytes
    cover_key: bytes
    cover_block_count: int
    label: str
    storage_format: str
    created_at: str
    hidden_key: bytes | None = None
    hidden_descriptor: HiddenVolumeDescriptor | None = None

    def __post_init__(self) -> None:
        if self.role not in ("outer", "hidden"):
            raise ValidationError("Некорректная роль заголовка диска.")
        if not isinstance(self.generation, int) or self.generation <= 0:
            raise ValidationError("Некорректное поколение заголовка диска.")
        if (
            not isinstance(self.cover_volume_id, bytes)
            or len(self.cover_volume_id) != 16
        ):
            raise ValidationError("Некорректный идентификатор внешнего диска.")
        if (
            not isinstance(self.cover_key, bytes)
            or len(self.cover_key) != secret.SecretBox.KEY_SIZE
        ):
            raise ValidationError("Некорректный ключ внешнего диска.")
        if not isinstance(self.cover_block_count, int) or self.cover_block_count <= 0:
            raise ValidationError("Некорректное число блоков внешнего диска.")
        if not isinstance(self.label, str) or not self.label.strip():
            raise ValidationError("В заголовке отсутствует название диска.")
        if len(self.label) > 31:
            raise ValidationError("Название диска должно быть не длиннее 31 символа.")
        if (
            not isinstance(self.storage_format, str)
            or not self.storage_format
            or len(self.storage_format) > 63
        ):
            raise ValidationError("Некорректное назначение блочного хранилища.")
        if (
            not isinstance(self.created_at, str)
            or not self.created_at
            or len(self.created_at) > 64
        ):
            raise ValidationError("Некорректная дата создания диска.")

        has_hidden_material = (
            self.hidden_key is not None or self.hidden_descriptor is not None
        )
        if self.role == "outer" and has_hidden_material:
            raise ValidationError(
                "Внешний заголовок не должен раскрывать скрытый диск."
            )
        if self.role == "hidden":
            if (
                not isinstance(self.hidden_key, bytes)
                or len(self.hidden_key) != secret.SecretBox.KEY_SIZE
                or not isinstance(self.hidden_descriptor, HiddenVolumeDescriptor)
            ):
                raise ValidationError(
                    "Скрытый заголовок не содержит ключевой материал."
                )
            hidden_end = (
                self.hidden_descriptor.region_start_block
                + self.hidden_descriptor.region_block_count
            )
            if hidden_end > self.cover_block_count:
                raise ValidationError(
                    "Скрытая область выходит за границы внешнего диска."
                )


class OpaqueVolumeHeaderStore:
    """Two fixed random-looking header areas selected only by a password.

    Each role has two independent password-derived banks. The outer area is
    always attempted first. If it cannot be authenticated, the same password is
    attempted against the hidden area. An unused hidden area remains random and
    has the same length and public structure as an encrypted one.
    """

    def __init__(self, kdf_parameters: HeaderKdfParameters | None = None) -> None:
        self.kdf_parameters = kdf_parameters or HeaderKdfParameters()
        self._validate_kdf_parameters(self.kdf_parameters)

    def initialize(
        self,
        stream: BinaryIO,
        outer_password: str,
        outer_header: OpaqueVolumeHeader,
        *,
        progress: ProgressCallback | None = None,
    ) -> None:
        if outer_header.role != "outer":
            raise ValidationError("Для создания требуется внешний заголовок.")
        password = self._validate_password(outer_password)
        stream.seek(0)
        stream.write(utils.random(OPAQUE_HEADER_RESERVED_SIZE))
        self._write_role_banks(
            stream,
            "outer",
            password,
            outer_header,
            progress=progress,
            completed_before=0,
            total=BANK_COUNT,
        )
        self._sync(stream)

    def add_hidden(
        self,
        stream: BinaryIO,
        outer_password: str,
        hidden_password: str,
        hidden_header: OpaqueVolumeHeader,
        *,
        progress: ProgressCallback | None = None,
    ) -> None:
        if hidden_header.role != "hidden":
            raise ValidationError("Для скрытой области требуется скрытый заголовок.")
        outer_password_bytes = self._validate_password(outer_password)
        hidden_password_bytes = self._validate_password(hidden_password)
        if hmac.compare_digest(outer_password_bytes, hidden_password_bytes):
            raise ValidationError(
                "Пароли внешнего и скрытого дисков должны различаться."
            )

        outer = self._unlock_role(
            stream,
            outer_password_bytes,
            "outer",
            progress=progress,
            completed_before=0,
            total=BANK_COUNT * 2,
        )
        if (
            outer.cover_volume_id != hidden_header.cover_volume_id
            or not hmac.compare_digest(outer.cover_key, hidden_header.cover_key)
            or outer.cover_block_count != hidden_header.cover_block_count
        ):
            raise ValidationError(
                "Скрытый заголовок не относится к выбранному внешнему диску."
            )

        self._write_role_banks(
            stream,
            "hidden",
            hidden_password_bytes,
            hidden_header,
            progress=progress,
            completed_before=BANK_COUNT,
            total=BANK_COUNT * 2,
        )
        self._sync(stream)

    def unlock(
        self,
        stream: BinaryIO,
        password: str,
        *,
        progress: ProgressCallback | None = None,
    ) -> OpaqueVolumeHeader:
        password_bytes = self._validate_password(password)
        total = BANK_COUNT * 2
        try:
            result = self._unlock_role(
                stream,
                password_bytes,
                "outer",
                progress=progress,
                completed_before=0,
                total=total,
            )
        except AuthenticationError:
            result = self._unlock_role(
                stream,
                password_bytes,
                "hidden",
                progress=progress,
                completed_before=BANK_COUNT,
                total=total,
            )
        if progress is not None:
            progress(total, total)
        return result

    @classmethod
    def serialize_for_protected_transfer(
        cls,
        header: OpaqueVolumeHeader,
    ) -> bytes:
        """Serialize unlocked material only for an authenticated OS wrapper."""

        role_index = 0 if header.role == "outer" else 1
        return bytes([role_index]) + cls._encode_payload(header)

    @classmethod
    def deserialize_protected_transfer(
        cls,
        payload: bytes,
    ) -> OpaqueVolumeHeader:
        if len(payload) != PROTECTED_TRANSFER_SIZE or payload[0] not in (0, 1):
            raise ValidationError("Некорректный материал запуска диска.")
        role: VolumeRole = "outer" if payload[0] == 0 else "hidden"
        return cls._decode_payload(payload[1:], expected_role=role)

    def _unlock_role(
        self,
        stream: BinaryIO,
        password: bytes,
        role: VolumeRole,
        *,
        progress: ProgressCallback | None,
        completed_before: int,
        total: int,
    ) -> OpaqueVolumeHeader:
        candidates: list[OpaqueVolumeHeader] = []
        for bank_index in range(BANK_COUNT):
            raw_bank = self._read_bank(stream, role, bank_index)
            try:
                candidate = self._decrypt_bank(
                    raw_bank,
                    password,
                    role,
                    bank_index,
                )
            except (
                AuthenticationError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                KeyError,
                TypeError,
                ValueError,
                binascii.Error,
                ValidationError,
            ):
                candidate = None
            if candidate is not None:
                candidates.append(candidate)
            if progress is not None:
                progress(completed_before + bank_index + 1, total)
        if not candidates:
            raise AuthenticationError(
                "Неверный пароль или повреждён заголовок диска."
            )
        identities = {
            (candidate.cover_volume_id, candidate.cover_key)
            for candidate in candidates
        }
        if len(identities) != 1:
            raise AuthenticationError(
                "Неверный пароль или повреждён заголовок диска."
            )
        return max(candidates, key=lambda candidate: candidate.generation)

    def _write_role_banks(
        self,
        stream: BinaryIO,
        role: VolumeRole,
        password: bytes,
        header: OpaqueVolumeHeader,
        *,
        progress: ProgressCallback | None,
        completed_before: int,
        total: int,
    ) -> None:
        for bank_index in range(BANK_COUNT):
            encoded = self._encrypt_bank(header, password, role, bank_index)
            stream.seek(self._bank_offset(role, bank_index))
            stream.write(encoded)
            self._sync(stream)
            if progress is not None:
                progress(completed_before + bank_index + 1, total)

    def _encrypt_bank(
        self,
        header: OpaqueVolumeHeader,
        password: bytes,
        role: VolumeRole,
        bank_index: int,
    ) -> bytes:
        if header.role != role:
            raise ValidationError("Роль заголовка не соответствует его области.")
        salt = utils.random(SALT_SIZE)
        key = self._derive_key(password, salt)
        nonce = utils.random(NONCE_SIZE)
        try:
            ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                self._encode_payload(header),
                self._bank_aad(role, bank_index),
                nonce,
                key,
            )
        finally:
            del key
        encoded = salt + nonce + ciphertext
        if len(encoded) != BANK_SIZE:
            raise ValidationError("Внутренняя ошибка размера заголовка диска.")
        return encoded

    def _decrypt_bank(
        self,
        raw_bank: bytes,
        password: bytes,
        role: VolumeRole,
        bank_index: int,
    ) -> OpaqueVolumeHeader:
        if len(raw_bank) != BANK_SIZE:
            raise AuthenticationError(
                "Неверный пароль или повреждён заголовок диска."
            )
        salt = raw_bank[:SALT_SIZE]
        nonce = raw_bank[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        ciphertext = raw_bank[SALT_SIZE + NONCE_SIZE :]
        key = self._derive_key(password, salt)
        try:
            plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext,
                self._bank_aad(role, bank_index),
                nonce,
                key,
            )
        except exceptions.CryptoError as error:
            raise AuthenticationError(
                "Неверный пароль или повреждён заголовок диска."
            ) from error
        finally:
            del key
        return self._decode_payload(plaintext, expected_role=role)

    @staticmethod
    def _encode_payload(header: OpaqueVolumeHeader) -> bytes:
        hidden: dict[str, object] | None = None
        if header.hidden_descriptor is not None and header.hidden_key is not None:
            descriptor = header.hidden_descriptor
            hidden = {
                "descriptor": {
                    "format_version": descriptor.format_version,
                    "hidden_block_count": descriptor.hidden_block_count,
                    "label": descriptor.label,
                    "region_block_count": descriptor.region_block_count,
                    "region_start_block": descriptor.region_start_block,
                    "storage_format": descriptor.storage_format,
                    "volume_id": base64.b64encode(descriptor.volume_id).decode(
                        "ascii"
                    ),
                },
                "key": base64.b64encode(header.hidden_key).decode("ascii"),
            }
        metadata: dict[str, object] = {
            "cover_block_count": header.cover_block_count,
            "cover_key": base64.b64encode(header.cover_key).decode("ascii"),
            "cover_volume_id": base64.b64encode(header.cover_volume_id).decode(
                "ascii"
            ),
            "created_at": header.created_at,
            "hidden": hidden,
            "label": header.label,
            "logical_block_size": LOGICAL_BLOCK_SIZE,
            "role": header.role,
            "storage_format": header.storage_format,
        }
        encoded = json.dumps(
            metadata,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        prefix = PAYLOAD_PREFIX.pack(
            OPAQUE_HEADER_MAGIC,
            OPAQUE_FORMAT_VERSION,
            header.generation,
            len(encoded),
        )
        if len(prefix) + len(encoded) > BANK_PLAINTEXT_SIZE:
            raise ValidationError("Заголовок диска слишком большой.")
        return prefix + encoded + utils.random(
            BANK_PLAINTEXT_SIZE - len(prefix) - len(encoded)
        )

    @staticmethod
    def _decode_payload(
        plaintext: bytes,
        *,
        expected_role: VolumeRole,
    ) -> OpaqueVolumeHeader:
        if len(plaintext) != BANK_PLAINTEXT_SIZE:
            raise ValidationError("Некорректный размер заголовка диска.")
        magic, version, generation, metadata_size = PAYLOAD_PREFIX.unpack(
            plaintext[: PAYLOAD_PREFIX.size]
        )
        if magic != OPAQUE_HEADER_MAGIC or version != OPAQUE_FORMAT_VERSION:
            raise ValidationError("Неподдерживаемый заголовок диска.")
        maximum = BANK_PLAINTEXT_SIZE - PAYLOAD_PREFIX.size
        if not 1 <= metadata_size <= maximum:
            raise ValidationError("Некорректная длина заголовка диска.")
        metadata = json.loads(
            plaintext[
                PAYLOAD_PREFIX.size : PAYLOAD_PREFIX.size + metadata_size
            ].decode("utf-8")
        )
        if not isinstance(metadata, dict) or metadata.get("role") != expected_role:
            raise ValidationError("Роль заголовка диска не подтверждена.")
        if int(metadata.get("logical_block_size", 0)) != LOGICAL_BLOCK_SIZE:
            raise ValidationError("Неподдерживаемый размер блока диска.")

        hidden_key: bytes | None = None
        descriptor: HiddenVolumeDescriptor | None = None
        hidden = metadata.get("hidden")
        if hidden is not None:
            if not isinstance(hidden, dict) or not isinstance(
                hidden.get("descriptor"), dict
            ):
                raise ValidationError("Некорректное описание скрытого диска.")
            raw_descriptor = hidden["descriptor"]
            hidden_key = base64.b64decode(str(hidden["key"]), validate=True)
            descriptor = HiddenVolumeDescriptor(
                volume_id=base64.b64decode(
                    str(raw_descriptor["volume_id"]),
                    validate=True,
                ),
                region_start_block=int(raw_descriptor["region_start_block"]),
                region_block_count=int(raw_descriptor["region_block_count"]),
                hidden_block_count=int(raw_descriptor["hidden_block_count"]),
                label=str(raw_descriptor["label"]),
                storage_format=str(raw_descriptor["storage_format"]),
                format_version=int(raw_descriptor["format_version"]),
            )

        return OpaqueVolumeHeader(
            role=expected_role,
            generation=generation,
            cover_volume_id=base64.b64decode(
                str(metadata["cover_volume_id"]),
                validate=True,
            ),
            cover_key=base64.b64decode(
                str(metadata["cover_key"]),
                validate=True,
            ),
            cover_block_count=int(metadata["cover_block_count"]),
            label=str(metadata["label"]),
            storage_format=str(metadata["storage_format"]),
            created_at=str(metadata["created_at"]),
            hidden_key=hidden_key,
            hidden_descriptor=descriptor,
        )

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        return pwhash.argon2id.kdf(
            secret.SecretBox.KEY_SIZE,
            password,
            salt,
            opslimit=self.kdf_parameters.opslimit,
            memlimit=self.kdf_parameters.memlimit,
        )

    @staticmethod
    def _bank_aad(role: VolumeRole, bank_index: int) -> bytes:
        role_index = 0 if role == "outer" else 1
        return OPAQUE_HEADER_MAGIC + bytes(
            [OPAQUE_FORMAT_VERSION, role_index, bank_index]
        )

    @staticmethod
    def _bank_offset(role: VolumeRole, bank_index: int) -> int:
        if role not in ("outer", "hidden") or not 0 <= bank_index < BANK_COUNT:
            raise ValueError("Header bank is out of range.")
        role_offset = 0 if role == "outer" else ROLE_AREA_SIZE
        return role_offset + bank_index * BANK_SIZE

    @classmethod
    def _read_bank(
        cls,
        stream: BinaryIO,
        role: VolumeRole,
        bank_index: int,
    ) -> bytes:
        stream.seek(cls._bank_offset(role, bank_index))
        raw = stream.read(BANK_SIZE)
        if len(raw) != BANK_SIZE:
            raise AuthenticationError(
                "Неверный пароль или повреждён заголовок диска."
            )
        return raw

    @staticmethod
    def _validate_password(password: str) -> bytes:
        if not isinstance(password, str) or len(password) < MINIMUM_PASSWORD_LENGTH:
            raise ValidationError(
                "Пароль диска должен содержать не менее "
                f"{MINIMUM_PASSWORD_LENGTH} символов."
            )
        encoded = password.encode("utf-8")
        if len(encoded) > MAXIMUM_PASSWORD_BYTES:
            raise ValidationError("Пароль диска слишком длинный.")
        return encoded

    @staticmethod
    def _validate_kdf_parameters(parameters: HeaderKdfParameters) -> None:
        if not (
            pwhash.argon2id.OPSLIMIT_MIN
            <= parameters.opslimit
            <= MAXIMUM_KDF_OPERATIONS
        ):
            raise ValidationError("Недопустимый параметр формирования ключа.")
        if not (
            pwhash.argon2id.MEMLIMIT_MIN
            <= parameters.memlimit
            <= MAXIMUM_KDF_MEMORY
        ):
            raise ValidationError("Недопустимый объём памяти формирования ключа.")

    @staticmethod
    def _sync(stream: BinaryIO) -> None:
        stream.flush()
        try:
            descriptor = stream.fileno()
        except (AttributeError, io.UnsupportedOperation):
            return
        os.fsync(descriptor)


__all__ = [
    "BANK_COUNT",
    "BANK_SIZE",
    "HeaderKdfParameters",
    "OPAQUE_FORMAT_VERSION",
    "OPAQUE_HEADER_RESERVED_SIZE",
    "PROTECTED_TRANSFER_SIZE",
    "OpaqueVolumeHeader",
    "OpaqueVolumeHeaderStore",
    "ROLE_AREA_SIZE",
]
