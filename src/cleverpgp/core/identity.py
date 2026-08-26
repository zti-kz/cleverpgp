from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import tempfile
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

from nacl import bindings, exceptions, public, secret, signing

from cleverpgp.core.errors import (
    CryptographicIdentityError,
    OutputExistsError,
    ProfileNotFoundError,
    ValidationError,
)
from cleverpgp.core.key_validity import normalize_expiration
from cleverpgp.core.models import (
    Contact,
    CryptographicIdentity,
    PublicIdentity,
)
from cleverpgp.core.storage import ProfileRepository

PUBLIC_KEY_EXTENSION = ".cpgk"
PUBLIC_KEY_MAGIC = b"CPGP-PUBLIC-KEY-V1\n"
PUBLIC_KEY_FORMAT = "CLEVERPGP-PUBLIC-IDENTITY"
PUBLIC_KEY_VERSION = 1
PUBLIC_KEY_MAX_SIZE = 16 * 1024
FINGERPRINT_DOMAIN = b"Clever PGP public identity fingerprint v1\0"
PUBLIC_BUNDLE_SIGNATURE_DOMAIN = b"Clever PGP public identity bundle v1\0"
ENCRYPTION_ALGORITHM = "X25519-SEALEDBOX"
SIGNATURE_ALGORITHM = "ED25519"


class UnlockedCryptographicIdentity:
    """Best-effort in-memory owner of the profile's private identity keys."""

    def __init__(
        self,
        public_identity: PublicIdentity,
        encryption_private_key: bytes,
        signing_seed: bytes,
    ) -> None:
        if len(encryption_private_key) != bindings.crypto_box_SECRETKEYBYTES:
            raise ValueError("Unexpected encryption private-key length")
        if len(signing_seed) != bindings.crypto_sign_SEEDBYTES:
            raise ValueError("Unexpected signing seed length")
        self.public_identity = public_identity
        self._encryption_private_key: bytearray | None = bytearray(
            encryption_private_key
        )
        self._signing_seed: bytearray | None = bytearray(signing_seed)

    @property
    def is_unlocked(self) -> bool:
        return (
            self._encryption_private_key is not None
            and self._signing_seed is not None
        )

    def encryption_private_key_copy(self) -> bytes:
        if self._encryption_private_key is None:
            raise CryptographicIdentityError(
                "Криптографическая идентичность заблокирована."
            )
        return bytes(self._encryption_private_key)

    def signing_seed_copy(self) -> bytes:
        if self._signing_seed is None:
            raise CryptographicIdentityError(
                "Криптографическая идентичность заблокирована."
            )
        return bytes(self._signing_seed)

    def signing_secret_key_copy(self) -> bytes:
        _public_key, secret_key = bindings.crypto_sign_seed_keypair(
            self.signing_seed_copy()
        )
        return secret_key

    def lock(self) -> None:
        for value in (self._encryption_private_key, self._signing_seed):
            if value is not None:
                for index in range(len(value)):
                    value[index] = 0
        self._encryption_private_key = None
        self._signing_seed = None

    def __enter__(self) -> UnlockedCryptographicIdentity:
        return self

    def __exit__(self, *_: object) -> None:
        self.lock()

    def __del__(self) -> None:
        self.lock()


class IdentityService:
    def __init__(self, repository: ProfileRepository) -> None:
        self.repository = repository

    def ensure_unlocked(self, master_key: bytes) -> UnlockedCryptographicIdentity:
        _validate_master_key(master_key)
        record = self.repository.get_cryptographic_identity()
        if record is None:
            record = self._create_identity(master_key)
        return self._unlock_record(record, master_key)

    def public_identity(self, master_key: bytes) -> PublicIdentity:
        with self.ensure_unlocked(master_key) as identity:
            return identity.public_identity

    def export_public_identity(
        self,
        target_path: Path,
        master_key: bytes,
        *,
        overwrite: bool = False,
    ) -> Path:
        target = Path(target_path).expanduser().resolve()
        if target.exists() and not overwrite:
            raise OutputExistsError("Файл открытого ключа уже существует.")
        target.parent.mkdir(parents=True, exist_ok=True)
        with self.ensure_unlocked(master_key) as identity:
            payload = _public_bundle_payload(identity.public_identity)
            canonical = _canonical_json(payload)
            signing_key = signing.SigningKey(identity.signing_seed_copy())
            signature = signing_key.sign(
                PUBLIC_BUNDLE_SIGNATURE_DOMAIN + canonical
            ).signature
            encoded = PUBLIC_KEY_MAGIC + _canonical_json(
                {
                    **payload,
                    "self_signature": base64.b64encode(signature).decode("ascii"),
                }
            )
        temporary_path: Path | None = None
        try:
            temporary_path, stream = _temporary_output(target)
            with stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, target)
            temporary_path = None
            return target
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def import_contact(self, source_path: Path) -> Contact:
        return self.add_contact(read_public_identity(source_path))

    def add_contact(self, public_identity: PublicIdentity) -> Contact:
        display_name = _validate_display_name(public_identity.display_name)
        expected_fingerprint = identity_fingerprint(
            public_identity.encryption_public_key,
            public_identity.signing_public_key,
        )
        if not hmac.compare_digest(
            expected_fingerprint,
            _validate_fingerprint(public_identity.fingerprint),
        ):
            raise ValidationError("Отпечаток открытого ключа не совпадает.")
        own = self.repository.get_cryptographic_identity()
        if own is not None and hmac.compare_digest(
            expected_fingerprint,
            identity_fingerprint(
                own.encryption_public_key,
                own.signing_public_key,
            ),
        ):
            raise ValidationError(
                "Это открытый ключ текущего профиля, а не нового контакта."
            )
        if any(
            hmac.compare_digest(expected_fingerprint, key.fingerprint)
            for key in self.repository.list_user_keys()
        ):
            raise ValidationError(
                "Это ваш локальный ключ, а не ключ нового получателя."
            )
        contact = Contact(
            contact_id=str(uuid4()),
            display_name=display_name,
            fingerprint=expected_fingerprint,
            encryption_public_key=public_identity.encryption_public_key,
            signing_public_key=public_identity.signing_public_key,
            created_at=datetime.now(UTC).isoformat(),
            expires_at=public_identity.expires_at,
        )
        self.repository.save_contact(contact)
        return contact

    def _create_identity(self, master_key: bytes) -> CryptographicIdentity:
        profile = self.repository.get_profile()
        if profile is None:
            raise ProfileNotFoundError("Локальный профиль не найден.")

        encryption_private = public.PrivateKey.generate()
        signing_private = signing.SigningKey.generate()
        encryption_private_bytes = bytes(encryption_private)
        signing_seed = bytes(signing_private)
        wrapper = secret.SecretBox(master_key)
        record = CryptographicIdentity(
            profile_id=profile.profile_id,
            encryption_public_key=bytes(encryption_private.public_key),
            signing_public_key=bytes(signing_private.verify_key),
            encrypted_encryption_private_key=bytes(
                wrapper.encrypt(encryption_private_bytes)
            ),
            encrypted_signing_seed=bytes(wrapper.encrypt(signing_seed)),
            created_at=datetime.now(UTC).isoformat(),
        )
        try:
            inserted = self.repository.save_cryptographic_identity(record)
            if inserted:
                return record
            concurrent = self.repository.get_cryptographic_identity()
            if concurrent is None:
                raise CryptographicIdentityError(
                    "Не удалось сохранить криптографическую идентичность профиля."
                )
            return concurrent
        finally:
            del encryption_private_bytes
            del signing_seed

    def _unlock_record(
        self,
        record: CryptographicIdentity,
        master_key: bytes,
    ) -> UnlockedCryptographicIdentity:
        profile = self.repository.get_profile()
        if profile is None or record.profile_id != profile.profile_id:
            raise CryptographicIdentityError(
                "Криптографическая идентичность не относится к текущему профилю."
            )
        try:
            wrapper = secret.SecretBox(master_key)
            encryption_private = wrapper.decrypt(
                record.encrypted_encryption_private_key
            )
            signing_seed = wrapper.decrypt(record.encrypted_signing_seed)
            encryption_key = public.PrivateKey(encryption_private)
            signing_key = signing.SigningKey(signing_seed)
        except (exceptions.CryptoError, TypeError, ValueError) as error:
            raise CryptographicIdentityError(
                "Закрытые ключи профиля повреждены или недоступны."
            ) from error

        if (
            not hmac.compare_digest(
                bytes(encryption_key.public_key),
                record.encryption_public_key,
            )
            or not hmac.compare_digest(
                bytes(signing_key.verify_key),
                record.signing_public_key,
            )
        ):
            raise CryptographicIdentityError(
                "Открытые и закрытые ключи профиля не соответствуют друг другу."
            )
        public_identity = PublicIdentity(
            display_name=profile.display_name,
            fingerprint=identity_fingerprint(
                record.encryption_public_key,
                record.signing_public_key,
            ),
            encryption_public_key=record.encryption_public_key,
            signing_public_key=record.signing_public_key,
        )
        return UnlockedCryptographicIdentity(
            public_identity,
            encryption_private,
            signing_seed,
        )


def identity_fingerprint(
    encryption_public_key: bytes,
    signing_public_key: bytes,
) -> str:
    _validate_public_keys(encryption_public_key, signing_public_key)
    return hashlib.sha256(
        FINGERPRINT_DOMAIN + encryption_public_key + signing_public_key
    ).hexdigest().upper()


def formatted_fingerprint(fingerprint: str) -> str:
    normalized = _validate_fingerprint(fingerprint)
    return " ".join(
        normalized[index : index + 4]
        for index in range(0, len(normalized), 4)
    )


def public_identity_from_contact(contact: Contact) -> PublicIdentity:
    expected = identity_fingerprint(
        contact.encryption_public_key,
        contact.signing_public_key,
    )
    if not hmac.compare_digest(expected, _validate_fingerprint(contact.fingerprint)):
        raise CryptographicIdentityError("Открытые ключи контакта повреждены.")
    return PublicIdentity(
        display_name=_validate_display_name(contact.display_name),
        fingerprint=expected,
        encryption_public_key=contact.encryption_public_key,
        signing_public_key=contact.signing_public_key,
        expires_at=contact.expires_at,
    )


def decode_public_identity(data: bytes) -> PublicIdentity:
    if len(data) > PUBLIC_KEY_MAX_SIZE or not data.startswith(PUBLIC_KEY_MAGIC):
        raise ValidationError("Это не открытый ключ Clever PGP.")
    raw_payload = data[len(PUBLIC_KEY_MAGIC) :]
    try:
        payload = json.loads(raw_payload.decode("utf-8"))
        if not isinstance(payload, dict):
            raise TypeError
        if payload.get("format") != PUBLIC_KEY_FORMAT:
            raise ValueError("format")
        if payload.get("version") != PUBLIC_KEY_VERSION:
            raise ValueError("version")
        if payload.get("encryption_algorithm") != ENCRYPTION_ALGORITHM:
            raise ValueError("encryption_algorithm")
        if payload.get("signature_algorithm") != SIGNATURE_ALGORITHM:
            raise ValueError("signature_algorithm")
        display_name = _validate_display_name(str(payload["display_name"]))
        encryption_public_key = base64.b64decode(
            payload["encryption_public_key"], validate=True
        )
        signing_public_key = base64.b64decode(
            payload["signing_public_key"], validate=True
        )
        fingerprint = _validate_fingerprint(str(payload["fingerprint"]))
        signature = base64.b64decode(payload["self_signature"], validate=True)
        expires_at = normalize_expiration(payload.get("expires_at"))
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
        binascii.Error,
    ) as error:
        raise ValidationError("Файл открытого ключа повреждён.") from error

    _validate_public_keys(encryption_public_key, signing_public_key)
    expected_fingerprint = identity_fingerprint(
        encryption_public_key,
        signing_public_key,
    )
    if not hmac.compare_digest(fingerprint, expected_fingerprint):
        raise ValidationError("Отпечаток открытого ключа не совпадает.")
    unsigned_payload = dict(payload)
    unsigned_payload.pop("self_signature", None)
    try:
        signing.VerifyKey(signing_public_key).verify(
            PUBLIC_BUNDLE_SIGNATURE_DOMAIN + _canonical_json(unsigned_payload),
            signature,
        )
    except (exceptions.BadSignatureError, TypeError, ValueError) as error:
        raise ValidationError("Самоподпись открытого ключа недействительна.") from error
    return PublicIdentity(
        display_name=display_name,
        fingerprint=fingerprint,
        encryption_public_key=encryption_public_key,
        signing_public_key=signing_public_key,
        expires_at=expires_at,
    )


def read_public_identity(source_path: Path) -> PublicIdentity:
    source = Path(source_path).expanduser().resolve()
    if not source.is_file():
        raise ValidationError("Файл открытого ключа не найден.")
    if source.stat().st_size > PUBLIC_KEY_MAX_SIZE:
        raise ValidationError("Файл открытого ключа имеет недопустимый размер.")
    return decode_public_identity(source.read_bytes())


def encode_public_identity(
    identity: PublicIdentity,
    signing_seed: bytes,
) -> bytes:
    """Return a self-signed, shareable public-key bundle."""

    if len(signing_seed) != bindings.crypto_sign_SEEDBYTES:
        raise ValidationError("Некорректный закрытый ключ подписи.")
    signing_key = signing.SigningKey(signing_seed)
    if not hmac.compare_digest(
        bytes(signing_key.verify_key), identity.signing_public_key
    ):
        raise CryptographicIdentityError(
            "Закрытый ключ подписи не соответствует открытому ключу."
        )
    payload = _public_bundle_payload(identity)
    signature = signing_key.sign(
        PUBLIC_BUNDLE_SIGNATURE_DOMAIN + _canonical_json(payload)
    ).signature
    return PUBLIC_KEY_MAGIC + _canonical_json(
        {
            **payload,
            "self_signature": base64.b64encode(signature).decode("ascii"),
        }
    )


def _public_bundle_payload(identity: PublicIdentity) -> dict[str, object]:
    expected = identity_fingerprint(
        identity.encryption_public_key,
        identity.signing_public_key,
    )
    if not hmac.compare_digest(expected, _validate_fingerprint(identity.fingerprint)):
        raise CryptographicIdentityError("Открытая идентичность повреждена.")
    return {
        "display_name": _validate_display_name(identity.display_name),
        "expires_at": normalize_expiration(identity.expires_at),
        "encryption_algorithm": ENCRYPTION_ALGORITHM,
        "encryption_public_key": base64.b64encode(
            identity.encryption_public_key
        ).decode("ascii"),
        "fingerprint": expected,
        "format": PUBLIC_KEY_FORMAT,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "signing_public_key": base64.b64encode(
            identity.signing_public_key
        ).decode("ascii"),
        "version": PUBLIC_KEY_VERSION,
    }


def _validate_master_key(master_key: bytes) -> None:
    if len(master_key) != secret.SecretBox.KEY_SIZE:
        raise ValidationError("Некорректный мастер-ключ текущего сеанса.")


def _validate_public_keys(
    encryption_public_key: bytes,
    signing_public_key: bytes,
) -> None:
    if len(encryption_public_key) != bindings.crypto_box_PUBLICKEYBYTES:
        raise ValidationError("Некорректный открытый ключ шифрования.")
    if len(signing_public_key) != bindings.crypto_sign_PUBLICKEYBYTES:
        raise ValidationError("Некорректный открытый ключ подписи.")
    try:
        public.PublicKey(encryption_public_key)
        signing.VerifyKey(signing_public_key)
    except (TypeError, ValueError) as error:
        raise ValidationError("Некорректная криптографическая идентичность.") from error


def _validate_fingerprint(fingerprint: str) -> str:
    normalized = str(fingerprint).replace(" ", "").upper()
    if len(normalized) != 64 or any(
        character not in "0123456789ABCDEF" for character in normalized
    ):
        raise ValidationError("Некорректный отпечаток открытого ключа.")
    return normalized


def _validate_display_name(display_name: str) -> str:
    clean = str(display_name).strip()
    if not clean or len(clean) > 100:
        raise ValidationError("Некорректное имя владельца открытого ключа.")
    if any(unicodedata.category(character).startswith("C") for character in clean):
        raise ValidationError("Имя владельца содержит служебные символы.")
    return clean


def _canonical_json(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _temporary_output(target: Path) -> tuple[Path, BinaryIO]:
    temporary = tempfile.NamedTemporaryFile(
        mode="wb",
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
        delete=False,
    )
    return Path(temporary.name), temporary


__all__ = [
    "ENCRYPTION_ALGORITHM",
    "IdentityService",
    "PUBLIC_KEY_EXTENSION",
    "SIGNATURE_ALGORITHM",
    "UnlockedCryptographicIdentity",
    "decode_public_identity",
    "encode_public_identity",
    "formatted_fingerprint",
    "identity_fingerprint",
    "public_identity_from_contact",
    "read_public_identity",
]
