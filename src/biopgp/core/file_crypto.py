from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import struct
import tempfile
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from nacl import bindings, exceptions, public, secret

from biopgp.core.errors import (
    CryptographicIdentityError,
    InvalidEncryptedFileError,
    OutputExistsError,
    ValidationError,
)
from biopgp.core.identity import (
    IdentityService,
    identity_fingerprint,
    public_identity_from_contact,
)
from biopgp.core.models import Contact, PublicIdentity
from biopgp.core.storage import ProfileRepository

MAGIC = b"CPGPFILE"
FORMAT_VERSION = 2
PREFIX = struct.Struct(">8sBI")
RECORD_LENGTH = struct.Struct(">I")
CHUNK_SIZE = 1024 * 1024
MAX_HEADER_SIZE = 64 * 1024
MAX_RECIPIENTS = 64
ALGORITHM = "XCHACHA20-POLY1305-SECRETSTREAM"
KEY_WRAP = "X25519-SEALEDBOX"
SIGNATURE_ALGORITHM = "ED25519PH"
SIGNATURE_DOMAIN = b"Clever PGP signed encrypted file v2\0"

ProgressCallback = Callable[[int, str], None]


@dataclass(frozen=True, slots=True)
class DecryptedFileResult:
    path: Path
    sender: PublicIdentity
    sender_is_known: bool
    sender_is_self: bool


@dataclass(frozen=True, slots=True)
class _RecipientSlot:
    fingerprint: str
    sealed_file_key: bytes


class FileCryptoService:
    """Signed, multi-recipient streaming `.cpgp` encryption."""

    def __init__(self, repository: ProfileRepository | None = None) -> None:
        self.repository = repository

    def bind_repository(self, repository: ProfileRepository) -> None:
        if self.repository is not None and self.repository.path != repository.path:
            raise ValueError("File crypto service is already bound to another profile.")
        self.repository = repository

    def encrypt_file(
        self,
        source_path: Path,
        target_path: Path,
        master_key: bytes,
        *,
        recipients: Iterable[PublicIdentity | Contact] = (),
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
    ) -> Path:
        self._report_progress(progress, 2, "Проверка исходного файла")
        source, target = self._validate_paths(source_path, target_path, overwrite)
        self._validate_master_key(master_key)
        identity_service = self._identity_service()

        file_key = bindings.crypto_secretstream_xchacha20poly1305_keygen()
        signing_secret_key: bytes | None = None
        identity = identity_service.ensure_unlocked(master_key)
        try:
            sender = identity.public_identity
            selected_recipients = self._normalize_recipients(sender, recipients)
            slots = tuple(
                _RecipientSlot(
                    recipient.fingerprint,
                    public.SealedBox(
                        public.PublicKey(recipient.encryption_public_key)
                    ).encrypt(file_key),
                )
                for recipient in selected_recipients
            )
            state = bindings.crypto_secretstream_xchacha20poly1305_state()
            stream_header = bindings.crypto_secretstream_xchacha20poly1305_init_push(
                state,
                file_key,
            )
            header = self._encode_header(stream_header, slots, sender)
            prefix = PREFIX.pack(MAGIC, FORMAT_VERSION, len(header))
            associated_data = prefix + header
            source_size = source.stat().st_size
            signing_secret_key = identity.signing_secret_key_copy()
        finally:
            identity.lock()

        temporary_path: Path | None = None
        try:
            self._report_progress(progress, 5, "Подготовка шифрования")
            temporary_path, target_stream = self._temporary_output(target)
            with source.open("rb") as source_stream, target_stream:
                target_stream.write(associated_data)
                self._encrypt_records(
                    source_stream,
                    target_stream,
                    state,
                    associated_data,
                    signing_secret_key,
                    source_size=source_size,
                    progress=progress,
                )
                self._report_progress(progress, 97, "Сохранение результата")
                target_stream.flush()
                os.fsync(target_stream.fileno())
            os.replace(temporary_path, target)
            temporary_path = None
            self._report_progress(progress, 100, "Шифрование завершено")
            return target
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            del file_key
            del master_key
            if signing_secret_key is not None:
                del signing_secret_key

    def decrypt_file(
        self,
        source_path: Path,
        target_path: Path,
        master_key: bytes,
        *,
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
    ) -> Path:
        return self.decrypt_file_detailed(
            source_path,
            target_path,
            master_key,
            overwrite=overwrite,
            progress=progress,
        ).path

    def decrypt_file_detailed(
        self,
        source_path: Path,
        target_path: Path,
        master_key: bytes,
        *,
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
    ) -> DecryptedFileResult:
        self._report_progress(progress, 2, "Проверка зашифрованного файла")
        source, target = self._validate_paths(source_path, target_path, overwrite)
        self._validate_master_key(master_key)
        identity_service = self._identity_service()

        temporary_path: Path | None = None
        identity = identity_service.ensure_unlocked(master_key)
        try:
            encrypted_size = source.stat().st_size
            with source.open("rb") as source_stream:
                associated_data, stream_header, slots, sender = self._read_header(
                    source_stream
                )
                slot = next(
                    (
                        candidate
                        for candidate in slots
                        if hmac.compare_digest(
                            candidate.fingerprint,
                            identity.public_identity.fingerprint,
                        )
                    ),
                    None,
                )
                if slot is None:
                    raise InvalidEncryptedFileError(
                        "Файл не зашифрован для открытого ключа текущего профиля."
                    )
                encryption_private_key = identity.encryption_private_key_copy()
                try:
                    file_key = public.SealedBox(
                        public.PrivateKey(encryption_private_key)
                    ).decrypt(slot.sealed_file_key)
                except (exceptions.CryptoError, TypeError, ValueError) as error:
                    raise InvalidEncryptedFileError(
                        "Ключевой слот получателя повреждён."
                    ) from error
                finally:
                    del encryption_private_key
                if len(file_key) != bindings.crypto_secretstream_xchacha20poly1305_KEYBYTES:
                    raise InvalidEncryptedFileError(
                        "Ключевой слот содержит ключ неправильной длины."
                    )

                state = bindings.crypto_secretstream_xchacha20poly1305_state()
                try:
                    bindings.crypto_secretstream_xchacha20poly1305_init_pull(
                        state,
                        stream_header,
                        file_key,
                    )
                except (ValueError, RuntimeError) as error:
                    raise InvalidEncryptedFileError(
                        "Некорректный криптографический заголовок файла."
                    ) from error

                temporary_path, target_stream = self._temporary_output(target)
                self._report_progress(progress, 5, "Проверка ключа файла")
                with target_stream:
                    self._decrypt_records(
                        source_stream,
                        target_stream,
                        state,
                        associated_data,
                        sender,
                        encrypted_size=encrypted_size,
                        progress=progress,
                    )
                    self._report_progress(progress, 97, "Сохранение результата")
                    target_stream.flush()
                    os.fsync(target_stream.fileno())

            sender_is_self, sender_is_known = self._sender_trust(
                sender,
                identity.public_identity,
            )
            os.replace(temporary_path, target)
            temporary_path = None
            self._report_progress(progress, 100, "Расшифрование завершено")
            return DecryptedFileResult(
                path=target,
                sender=sender,
                sender_is_known=sender_is_known,
                sender_is_self=sender_is_self,
            )
        finally:
            identity.lock()
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            del master_key
            if "file_key" in locals():
                del file_key

    @staticmethod
    def default_encrypted_path(source_path: Path) -> Path:
        source = Path(source_path)
        return source.with_name(source.name + ".cpgp")

    @staticmethod
    def default_decrypted_path(source_path: Path) -> Path:
        source = Path(source_path)
        if source.suffix.lower() == ".cpgp":
            candidate = source.with_suffix("")
        else:
            candidate = source.with_name(source.name + ".decrypted")
        if not candidate.exists():
            return candidate
        return candidate.with_name(candidate.stem + ".decrypted" + candidate.suffix)

    def _identity_service(self) -> IdentityService:
        if self.repository is None:
            raise CryptographicIdentityError(
                "Хранилище профиля не подключено к файловому шифрованию."
            )
        return IdentityService(self.repository)

    def _sender_trust(
        self,
        sender: PublicIdentity,
        own_identity: PublicIdentity,
    ) -> tuple[bool, bool]:
        if hmac.compare_digest(sender.fingerprint, own_identity.fingerprint):
            if (
                hmac.compare_digest(
                    sender.encryption_public_key,
                    own_identity.encryption_public_key,
                )
                and hmac.compare_digest(
                    sender.signing_public_key,
                    own_identity.signing_public_key,
                )
            ):
                return True, True
            raise InvalidEncryptedFileError(
                "Отпечаток отправителя совпал, но его открытые ключи отличаются."
            )
        if self.repository is None:
            return False, False
        contact = self.repository.get_contact_by_fingerprint(sender.fingerprint)
        if contact is None:
            return False, False
        known = public_identity_from_contact(contact)
        if (
            not hmac.compare_digest(
                known.encryption_public_key,
                sender.encryption_public_key,
            )
            or not hmac.compare_digest(
                known.signing_public_key,
                sender.signing_public_key,
            )
        ):
            raise InvalidEncryptedFileError(
                "Открытые ключи отправителя не совпадают с сохранённым контактом."
            )
        return False, True

    @staticmethod
    def _normalize_recipients(
        sender: PublicIdentity,
        recipients: Iterable[PublicIdentity | Contact],
    ) -> tuple[PublicIdentity, ...]:
        result: list[PublicIdentity] = [sender]
        seen = {sender.fingerprint}
        for value in recipients:
            recipient = (
                public_identity_from_contact(value)
                if isinstance(value, Contact)
                else value
            )
            expected = identity_fingerprint(
                recipient.encryption_public_key,
                recipient.signing_public_key,
            )
            if not hmac.compare_digest(expected, recipient.fingerprint):
                raise ValidationError("Открытые ключи получателя повреждены.")
            if expected in seen:
                continue
            seen.add(expected)
            result.append(recipient)
            if len(result) > MAX_RECIPIENTS:
                raise ValidationError(
                    f"Для одного файла можно выбрать не более {MAX_RECIPIENTS} получателей."
                )
        return tuple(result)

    @staticmethod
    def _validate_paths(
        source_path: Path,
        target_path: Path,
        overwrite: bool,
    ) -> tuple[Path, Path]:
        source = Path(source_path).expanduser().resolve()
        target = Path(target_path).expanduser().resolve()
        if not source.is_file():
            raise ValidationError("Исходный файл не найден.")
        if source == target:
            raise ValidationError("Исходный и целевой путь должны отличаться.")
        if target.exists() and not overwrite:
            raise OutputExistsError("Целевой файл уже существует.")
        target.parent.mkdir(parents=True, exist_ok=True)
        return source, target

    @staticmethod
    def _validate_master_key(master_key: bytes) -> None:
        if len(master_key) != secret.SecretBox.KEY_SIZE:
            raise ValidationError("Некорректный мастер-ключ текущего сеанса.")

    @staticmethod
    def _encode_header(
        stream_header: bytes,
        recipient_slots: tuple[_RecipientSlot, ...],
        sender: PublicIdentity,
    ) -> bytes:
        payload = {
            "algorithm": ALGORITHM,
            "chunk_size": CHUNK_SIZE,
            "key_wrap": KEY_WRAP,
            "recipients": [
                {
                    "fingerprint": slot.fingerprint,
                    "sealed_file_key": base64.b64encode(
                        slot.sealed_file_key
                    ).decode("ascii"),
                }
                for slot in recipient_slots
            ],
            "sender": {
                "display_name": sender.display_name,
                "encryption_public_key": base64.b64encode(
                    sender.encryption_public_key
                ).decode("ascii"),
                "fingerprint": sender.fingerprint,
                "signing_public_key": base64.b64encode(
                    sender.signing_public_key
                ).decode("ascii"),
            },
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "stream_header": base64.b64encode(stream_header).decode("ascii"),
        }
        encoded = _canonical_json(payload)
        if len(encoded) > MAX_HEADER_SIZE:
            raise ValidationError("Заголовок файла слишком велик.")
        return encoded

    def _read_header(
        self,
        source_stream: BinaryIO,
    ) -> tuple[bytes, bytes, tuple[_RecipientSlot, ...], PublicIdentity]:
        raw_prefix = self._read_exact(source_stream, PREFIX.size)
        try:
            magic, version, header_size = PREFIX.unpack(raw_prefix)
        except struct.error as error:
            raise InvalidEncryptedFileError("Повреждён заголовок файла.") from error

        if magic != MAGIC:
            raise InvalidEncryptedFileError("Это не файл Clever PGP.")
        if version != FORMAT_VERSION:
            raise InvalidEncryptedFileError(
                f"Версия формата {version} не поддерживается."
            )
        if not 2 <= header_size <= MAX_HEADER_SIZE:
            raise InvalidEncryptedFileError("Недопустимый размер заголовка.")

        raw_header = self._read_exact(source_stream, header_size)
        try:
            payload = json.loads(raw_header.decode("utf-8"))
            if not isinstance(payload, dict):
                raise TypeError
            if payload.get("algorithm") != ALGORITHM:
                raise ValueError("algorithm")
            if payload.get("key_wrap") != KEY_WRAP:
                raise ValueError("key_wrap")
            if payload.get("signature_algorithm") != SIGNATURE_ALGORITHM:
                raise ValueError("signature_algorithm")
            if payload.get("chunk_size") != CHUNK_SIZE:
                raise ValueError("chunk_size")
            stream_header = base64.b64decode(
                payload["stream_header"],
                validate=True,
            )
            raw_slots = payload["recipients"]
            raw_sender = payload["sender"]
            if not isinstance(raw_slots, list) or not isinstance(raw_sender, dict):
                raise TypeError
            if not 1 <= len(raw_slots) <= MAX_RECIPIENTS:
                raise ValueError("recipients")
            slots = self._decode_recipient_slots(raw_slots)
            sender = self._decode_sender(raw_sender)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
            binascii.Error,
            ValidationError,
        ) as error:
            raise InvalidEncryptedFileError(
                "Некорректный заголовок Clever PGP."
            ) from error

        if len(stream_header) != bindings.crypto_secretstream_xchacha20poly1305_HEADERBYTES:
            raise InvalidEncryptedFileError("Некорректный заголовок secretstream.")
        return raw_prefix + raw_header, stream_header, slots, sender

    @staticmethod
    def _decode_recipient_slots(raw_slots: list[object]) -> tuple[_RecipientSlot, ...]:
        result: list[_RecipientSlot] = []
        seen: set[str] = set()
        expected_key_size = (
            bindings.crypto_secretstream_xchacha20poly1305_KEYBYTES
            + bindings.crypto_box_SEALBYTES
        )
        for raw_slot in raw_slots:
            if not isinstance(raw_slot, dict):
                raise TypeError("recipient")
            fingerprint = _normalize_fingerprint(str(raw_slot["fingerprint"]))
            sealed_key = base64.b64decode(
                raw_slot["sealed_file_key"],
                validate=True,
            )
            if len(sealed_key) != expected_key_size or fingerprint in seen:
                raise ValueError("recipient")
            seen.add(fingerprint)
            result.append(_RecipientSlot(fingerprint, sealed_key))
        return tuple(result)

    @staticmethod
    def _decode_sender(raw_sender: dict[str, object]) -> PublicIdentity:
        display_name = str(raw_sender["display_name"]).strip()
        if (
            not display_name
            or len(display_name) > 100
            or any(
                unicodedata.category(character).startswith("C")
                for character in display_name
            )
        ):
            raise ValueError("sender name")
        encryption_public_key = base64.b64decode(
            raw_sender["encryption_public_key"],
            validate=True,
        )
        signing_public_key = base64.b64decode(
            raw_sender["signing_public_key"],
            validate=True,
        )
        fingerprint = _normalize_fingerprint(str(raw_sender["fingerprint"]))
        expected = identity_fingerprint(
            encryption_public_key,
            signing_public_key,
        )
        if not hmac.compare_digest(expected, fingerprint):
            raise ValueError("sender fingerprint")
        return PublicIdentity(
            display_name=display_name,
            fingerprint=fingerprint,
            encryption_public_key=encryption_public_key,
            signing_public_key=signing_public_key,
        )

    @staticmethod
    def _encrypt_records(
        source_stream: BinaryIO,
        target_stream: BinaryIO,
        state: bindings.crypto_secretstream_xchacha20poly1305_state,
        associated_data: bytes,
        signing_secret_key: bytes,
        *,
        source_size: int,
        progress: ProgressCallback | None,
    ) -> None:
        signature_state = bindings.crypto_sign_ed25519ph_state()
        bindings.crypto_sign_ed25519ph_update(signature_state, SIGNATURE_DOMAIN)
        bindings.crypto_sign_ed25519ph_update(signature_state, associated_data)
        processed = 0
        while chunk := source_stream.read(CHUNK_SIZE):
            bindings.crypto_sign_ed25519ph_update(signature_state, chunk)
            encrypted = bindings.crypto_secretstream_xchacha20poly1305_push(
                state,
                chunk,
                associated_data,
                bindings.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
            )
            FileCryptoService._write_encrypted_record(target_stream, encrypted)
            processed += len(chunk)
            fraction = processed / max(1, source_size)
            FileCryptoService._report_progress(
                progress,
                5 + round(87 * min(1.0, fraction)),
                "Шифрование и подписание данных",
            )

        signature = bindings.crypto_sign_ed25519ph_final_create(
            signature_state,
            signing_secret_key,
        )
        final_payload = _canonical_json(
            {
                "content_size": processed,
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )
        FileCryptoService._write_encrypted_record(
            target_stream,
            bindings.crypto_secretstream_xchacha20poly1305_push(
                state,
                final_payload,
                associated_data,
                bindings.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
            ),
        )
        FileCryptoService._report_progress(
            progress,
            95,
            "Подпись файла сформирована",
        )

    @staticmethod
    def _write_encrypted_record(target_stream: BinaryIO, encrypted: bytes) -> None:
        target_stream.write(RECORD_LENGTH.pack(len(encrypted)))
        target_stream.write(encrypted)

    def _decrypt_records(
        self,
        source_stream: BinaryIO,
        target_stream: BinaryIO,
        state: bindings.crypto_secretstream_xchacha20poly1305_state,
        associated_data: bytes,
        sender: PublicIdentity,
        *,
        encrypted_size: int,
        progress: ProgressCallback | None,
    ) -> None:
        maximum_record_size = (
            CHUNK_SIZE + bindings.crypto_secretstream_xchacha20poly1305_ABYTES
        )
        signature_state = bindings.crypto_sign_ed25519ph_state()
        bindings.crypto_sign_ed25519ph_update(signature_state, SIGNATURE_DOMAIN)
        bindings.crypto_sign_ed25519ph_update(signature_state, associated_data)
        processed = 0
        while True:
            raw_length = source_stream.read(RECORD_LENGTH.size)
            if not raw_length:
                raise InvalidEncryptedFileError("В файле отсутствует завершающий блок.")
            if len(raw_length) != RECORD_LENGTH.size:
                raise InvalidEncryptedFileError("Оборвана длина блока шифротекста.")
            (record_size,) = RECORD_LENGTH.unpack(raw_length)
            if not (
                bindings.crypto_secretstream_xchacha20poly1305_ABYTES
                <= record_size
                <= maximum_record_size
            ):
                raise InvalidEncryptedFileError("Недопустимый размер блока шифротекста.")
            encrypted = self._read_exact(source_stream, record_size)
            try:
                plaintext, tag = bindings.crypto_secretstream_xchacha20poly1305_pull(
                    state,
                    encrypted,
                    associated_data,
                )
            except (exceptions.CryptoError, ValueError, RuntimeError) as error:
                raise InvalidEncryptedFileError(
                    "Нарушена целостность зашифрованного файла."
                ) from error

            if tag == bindings.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE:
                bindings.crypto_sign_ed25519ph_update(signature_state, plaintext)
                target_stream.write(plaintext)
                processed += len(plaintext)
                fraction = source_stream.tell() / max(1, encrypted_size)
                self._report_progress(
                    progress,
                    5 + round(87 * min(1.0, fraction)),
                    "Расшифрование и проверка данных",
                )
                continue
            if tag != bindings.crypto_secretstream_xchacha20poly1305_TAG_FINAL:
                raise InvalidEncryptedFileError("Недопустимый тег блока.")
            if source_stream.read(1):
                raise InvalidEncryptedFileError(
                    "После завершающего блока обнаружены лишние данные."
                )
            signature = self._decode_signature_payload(plaintext, processed)
            try:
                verified = bindings.crypto_sign_ed25519ph_final_verify(
                    signature_state,
                    signature,
                    sender.signing_public_key,
                )
            except (exceptions.BadSignatureError, TypeError, ValueError) as error:
                raise InvalidEncryptedFileError(
                    "Цифровая подпись файла недействительна."
                ) from error
            if not verified:
                raise InvalidEncryptedFileError(
                    "Цифровая подпись файла недействительна."
                )
            self._report_progress(progress, 95, "Цифровая подпись подтверждена")
            return

    @staticmethod
    def _decode_signature_payload(payload: bytes, processed: int) -> bytes:
        try:
            value = json.loads(payload.decode("ascii"))
            if not isinstance(value, dict):
                raise TypeError
            if set(value) != {"content_size", "signature"}:
                raise ValueError("fields")
            content_size = value["content_size"]
            if type(content_size) is not int or content_size != processed:
                raise ValueError("content_size")
            signature = base64.b64decode(value["signature"], validate=True)
            if len(signature) != bindings.crypto_sign_BYTES:
                raise ValueError("signature")
            return signature
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
            binascii.Error,
        ) as error:
            raise InvalidEncryptedFileError(
                "Повреждён завершающий блок цифровой подписи."
            ) from error

    @staticmethod
    def _report_progress(
        progress: ProgressCallback | None,
        value: int,
        message: str,
    ) -> None:
        if progress is not None:
            progress(max(0, min(100, int(value))), message)

    @staticmethod
    def _read_exact(source_stream: BinaryIO, size: int) -> bytes:
        data = source_stream.read(size)
        if len(data) != size:
            raise InvalidEncryptedFileError("Зашифрованный файл оборван.")
        return data

    @staticmethod
    def _temporary_output(target: Path) -> tuple[Path, BinaryIO]:
        temporary = tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        )
        return Path(temporary.name), temporary


def _normalize_fingerprint(fingerprint: str) -> str:
    normalized = str(fingerprint).replace(" ", "").upper()
    if len(normalized) != 64 or any(
        character not in "0123456789ABCDEF" for character in normalized
    ):
        raise ValidationError("Некорректный отпечаток открытого ключа.")
    return normalized


def _canonical_json(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


__all__ = [
    "ALGORITHM",
    "CHUNK_SIZE",
    "DecryptedFileResult",
    "FileCryptoService",
    "FORMAT_VERSION",
    "KEY_WRAP",
    "MAGIC",
    "SIGNATURE_ALGORITHM",
]
