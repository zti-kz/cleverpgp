from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4

from nacl import bindings, exceptions, public, pwhash, secret, signing, utils

from cleverpgp.core.errors import (
    AuthenticationError,
    CryptographicIdentityError,
    OutputExistsError,
    ValidationError,
)
from cleverpgp.core.identity import (
    UnlockedCryptographicIdentity,
    encode_public_identity,
    identity_fingerprint,
)
from cleverpgp.core.models import PublicIdentity, UserKey
from cleverpgp.core.storage import ProfileRepository

PRIVATE_KEY_EXTENSION = ".cpgx"
PRIVATE_KEY_MAGIC = b"CPGP-PRIVATE-KEY-V1\n"
PRIVATE_KEY_FORMAT = "CLEVERPGP-PASSWORD-PROTECTED-PRIVATE-KEY"
PRIVATE_KEY_VERSION = 1
PRIVATE_KEY_MAX_SIZE = 128 * 1024
PRIVATE_BUNDLE_MAGIC = b"CPGP-PRIVATE-MATERIAL-V1\0"
MINIMUM_KEY_PASSWORD_LENGTH = 12


class PortableKeyService:
    """Create and move password-protected X25519/Ed25519 key pairs."""

    def __init__(
        self,
        repository: ProfileRepository,
        *,
        opslimit: int = pwhash.argon2id.OPSLIMIT_INTERACTIVE,
        memlimit: int = pwhash.argon2id.MEMLIMIT_INTERACTIVE,
    ) -> None:
        self.repository = repository
        self.opslimit = int(opslimit)
        self.memlimit = int(memlimit)

    def create_key(self, display_name: str, password: str) -> UserKey:
        name = self._validate_display_name(display_name)
        password_bytes = self._validate_password(password)
        encryption_private = public.PrivateKey.generate()
        signing_private = signing.SigningKey.generate()
        encryption_private_bytes = bytes(encryption_private)
        signing_seed = bytes(signing_private)
        key_id = str(uuid4())
        encryption_public = bytes(encryption_private.public_key)
        signing_public = bytes(signing_private.verify_key)
        fingerprint = identity_fingerprint(encryption_public, signing_public)
        salt = utils.random(pwhash.argon2id.SALTBYTES)
        access_key = bytearray(
            pwhash.argon2id.kdf(
                secret.SecretBox.KEY_SIZE,
                password_bytes,
                salt,
                opslimit=self.opslimit,
                memlimit=self.memlimit,
            )
        )
        try:
            private_payload = PRIVATE_BUNDLE_MAGIC + self._canonical_json(
                {
                    "display_name": name,
                    "encryption_private_key": base64.b64encode(
                        encryption_private_bytes
                    ).decode("ascii"),
                    "fingerprint": fingerprint,
                    "key_id": key_id,
                    "signing_seed": base64.b64encode(signing_seed).decode("ascii"),
                }
            )
            encrypted_private = bytes(
                secret.SecretBox(bytes(access_key)).encrypt(private_payload)
            )
            record = UserKey(
                key_id=key_id,
                display_name=name,
                fingerprint=fingerprint,
                encryption_public_key=encryption_public,
                signing_public_key=signing_public,
                kdf_salt=salt,
                kdf_opslimit=self.opslimit,
                kdf_memlimit=self.memlimit,
                encrypted_private_bundle=encrypted_private,
                created_at=datetime.now(UTC).isoformat(),
            )
            self.repository.save_user_key(record)
            return record
        finally:
            self._wipe(access_key)

    def unlock_key(
        self,
        key_or_id: UserKey | str,
        password: str,
    ) -> UnlockedCryptographicIdentity:
        record = self._resolve_key(key_or_id)
        return self._unlock_record(record, password)

    def _unlock_record(
        self,
        record: UserKey,
        password: str,
    ) -> UnlockedCryptographicIdentity:
        password_bytes = self._validate_password(password)
        access_key = bytearray(
            pwhash.argon2id.kdf(
                secret.SecretBox.KEY_SIZE,
                password_bytes,
                record.kdf_salt,
                opslimit=record.kdf_opslimit,
                memlimit=record.kdf_memlimit,
            )
        )
        try:
            try:
                payload = secret.SecretBox(bytes(access_key)).decrypt(
                    record.encrypted_private_bundle
                )
            except (exceptions.CryptoError, ValueError, TypeError) as error:
                raise AuthenticationError("Неверный пароль цифрового ключа.") from error
        finally:
            self._wipe(access_key)

        if not payload.startswith(PRIVATE_BUNDLE_MAGIC):
            raise CryptographicIdentityError(
                "Закрытая часть цифрового ключа повреждена."
            )
        try:
            private_payload = json.loads(
                payload[len(PRIVATE_BUNDLE_MAGIC) :].decode("utf-8")
            )
            if not isinstance(private_payload, dict):
                raise TypeError
            encryption_private = base64.b64decode(
                private_payload["encryption_private_key"], validate=True
            )
            signing_seed = base64.b64decode(
                private_payload["signing_seed"], validate=True
            )
            protected_key_id = str(private_payload["key_id"])
            protected_name = str(private_payload["display_name"])
            protected_fingerprint = str(private_payload["fingerprint"])
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
            binascii.Error,
        ) as error:
            raise CryptographicIdentityError(
                "Закрытая часть цифрового ключа повреждена."
            ) from error
        if (
            len(encryption_private) != bindings.crypto_box_SECRETKEYBYTES
            or len(signing_seed) != bindings.crypto_sign_SEEDBYTES
            or not hmac.compare_digest(
                protected_key_id.encode("utf-8"), record.key_id.encode("utf-8")
            )
            or not hmac.compare_digest(
                protected_name.encode("utf-8"),
                record.display_name.encode("utf-8"),
            )
            or not hmac.compare_digest(
                protected_fingerprint.encode("ascii"),
                record.fingerprint.encode("ascii"),
            )
        ):
            raise CryptographicIdentityError(
                "Защищённые сведения цифрового ключа не совпадают с заголовком."
            )
        encryption_key = public.PrivateKey(encryption_private)
        signing_key = signing.SigningKey(signing_seed)
        if not (
            hmac.compare_digest(
                bytes(encryption_key.public_key), record.encryption_public_key
            )
            and hmac.compare_digest(
                bytes(signing_key.verify_key), record.signing_public_key
            )
            and hmac.compare_digest(
                identity_fingerprint(
                    record.encryption_public_key, record.signing_public_key
                ),
                record.fingerprint,
            )
        ):
            raise CryptographicIdentityError(
                "Открытая и закрытая части цифрового ключа не соответствуют друг другу."
            )
        return UnlockedCryptographicIdentity(
            PublicIdentity(
                display_name=record.display_name,
                fingerprint=record.fingerprint,
                encryption_public_key=record.encryption_public_key,
                signing_public_key=record.signing_public_key,
            ),
            encryption_private,
            signing_seed,
        )

    def export_private_key(
        self,
        key_or_id: UserKey | str,
        password: str,
        target_path: Path,
        *,
        overwrite: bool = False,
    ) -> Path:
        record = self._resolve_key(key_or_id)
        with self.unlock_key(record, password):
            encoded = PRIVATE_KEY_MAGIC + self._canonical_json(
                self._record_payload(record)
            )
        return self._atomic_write(target_path, encoded, overwrite=overwrite)

    def import_private_key(self, source_path: Path, password: str) -> UserKey:
        source = Path(source_path).expanduser().resolve()
        if not source.is_file() or source.stat().st_size > PRIVATE_KEY_MAX_SIZE:
            raise ValidationError("Файл закрытого ключа не найден или слишком велик.")
        record = self._decode_private_key(source.read_bytes())
        with self._unlock_record(record, password):
            pass
        self.repository.save_user_key(record)
        return record

    def export_public_key(
        self,
        key_or_id: UserKey | str,
        password: str,
        target_path: Path,
        *,
        overwrite: bool = False,
    ) -> Path:
        record = self._resolve_key(key_or_id)
        with self.unlock_key(record, password) as unlocked:
            encoded = encode_public_identity(
                unlocked.public_identity,
                unlocked.signing_seed_copy(),
            )
        return self._atomic_write(target_path, encoded, overwrite=overwrite)

    def _resolve_key(self, key_or_id: UserKey | str) -> UserKey:
        if isinstance(key_or_id, UserKey):
            stored = self.repository.get_user_key(key_or_id.key_id)
        else:
            stored = self.repository.get_user_key(str(key_or_id))
        if stored is None:
            raise ValidationError("Цифровой ключ не найден.")
        return stored

    @staticmethod
    def _record_payload(record: UserKey) -> dict[str, object]:
        return {
            "created_at": record.created_at,
            "display_name": record.display_name,
            "encrypted_private_bundle": base64.b64encode(
                record.encrypted_private_bundle
            ).decode("ascii"),
            "encryption_public_key": base64.b64encode(
                record.encryption_public_key
            ).decode("ascii"),
            "fingerprint": record.fingerprint,
            "format": PRIVATE_KEY_FORMAT,
            "kdf": "ARGON2ID",
            "kdf_memlimit": record.kdf_memlimit,
            "kdf_opslimit": record.kdf_opslimit,
            "kdf_salt": base64.b64encode(record.kdf_salt).decode("ascii"),
            "key_id": record.key_id,
            "signing_public_key": base64.b64encode(
                record.signing_public_key
            ).decode("ascii"),
            "version": PRIVATE_KEY_VERSION,
        }

    def _decode_private_key(self, data: bytes) -> UserKey:
        if len(data) > PRIVATE_KEY_MAX_SIZE or not data.startswith(PRIVATE_KEY_MAGIC):
            raise ValidationError("Это не закрытый ключ Clever PGP.")
        try:
            payload = json.loads(data[len(PRIVATE_KEY_MAGIC) :].decode("utf-8"))
            if not isinstance(payload, dict):
                raise TypeError
            if payload.get("format") != PRIVATE_KEY_FORMAT:
                raise ValueError("format")
            if payload.get("version") != PRIVATE_KEY_VERSION:
                raise ValueError("version")
            if payload.get("kdf") != "ARGON2ID":
                raise ValueError("kdf")
            encryption_public = base64.b64decode(
                payload["encryption_public_key"], validate=True
            )
            signing_public = base64.b64decode(
                payload["signing_public_key"], validate=True
            )
            salt = base64.b64decode(payload["kdf_salt"], validate=True)
            encrypted_private = base64.b64decode(
                payload["encrypted_private_bundle"], validate=True
            )
            fingerprint = str(payload["fingerprint"]).replace(" ", "").upper()
            key_id = str(payload["key_id"])
            created_at = str(payload["created_at"])
            display_name = self._validate_display_name(str(payload["display_name"]))
            opslimit = int(payload["kdf_opslimit"])
            memlimit = int(payload["kdf_memlimit"])
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
            binascii.Error,
        ) as error:
            raise ValidationError("Файл закрытого ключа повреждён.") from error
        if (
            len(encryption_public) != bindings.crypto_box_PUBLICKEYBYTES
            or len(signing_public) != bindings.crypto_sign_PUBLICKEYBYTES
            or len(salt) != pwhash.argon2id.SALTBYTES
            or opslimit < pwhash.argon2id.OPSLIMIT_MIN
            or memlimit < pwhash.argon2id.MEMLIMIT_MIN
            or opslimit > 10
            or memlimit > 512 * 1024 * 1024
        ):
            raise ValidationError("Параметры закрытого ключа недопустимы.")
        expected = identity_fingerprint(encryption_public, signing_public)
        if not hmac.compare_digest(expected, fingerprint):
            raise ValidationError("Отпечаток закрытого ключа не совпадает.")
        return UserKey(
            key_id=key_id,
            display_name=display_name,
            fingerprint=expected,
            encryption_public_key=encryption_public,
            signing_public_key=signing_public,
            kdf_salt=salt,
            kdf_opslimit=opslimit,
            kdf_memlimit=memlimit,
            encrypted_private_bundle=encrypted_private,
            created_at=created_at,
        )

    @staticmethod
    def _validate_password(password: str) -> bytes:
        normalized = str(password)
        if len(normalized) < MINIMUM_KEY_PASSWORD_LENGTH:
            raise ValidationError(
                f"Пароль цифрового ключа должен содержать не менее {MINIMUM_KEY_PASSWORD_LENGTH} символов."
            )
        return normalized.encode("utf-8")

    @staticmethod
    def _validate_display_name(display_name: str) -> str:
        value = str(display_name).strip()
        if not value or len(value) > 100:
            raise ValidationError("Укажите имя владельца цифрового ключа.")
        return value

    @staticmethod
    def _canonical_json(payload: dict[str, object]) -> bytes:
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @staticmethod
    def _atomic_write(
        target_path: Path,
        data: bytes,
        *,
        overwrite: bool,
    ) -> Path:
        target = Path(target_path).expanduser().resolve()
        if target.exists() and not overwrite:
            raise OutputExistsError("Файл ключа уже существует.")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary: Path | None = None
        try:
            stream: BinaryIO
            handle = tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{target.name}.",
                suffix=".tmp",
                dir=target.parent,
                delete=False,
            )
            temporary = Path(handle.name)
            with handle as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            temporary = None
            return target
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def _wipe(value: bytearray) -> None:
        for index in range(len(value)):
            value[index] = 0


__all__ = [
    "MINIMUM_KEY_PASSWORD_LENGTH",
    "PRIVATE_KEY_EXTENSION",
    "PortableKeyService",
]
