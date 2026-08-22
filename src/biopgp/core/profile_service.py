from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from nacl import exceptions, pwhash, secret, utils

from biopgp.core.errors import (
    AuthenticationError,
    ProfileNotFoundError,
    SessionLockedError,
    ValidationError,
)
from biopgp.core.models import Profile, UnlockMode
from biopgp.core.storage import ProfileRepository

MINIMUM_PASSWORD_LENGTH = 12
MAXIMUM_PASSWORD_BYTES = 1024
MAXIMUM_KDF_MEMORY = pwhash.argon2id.MEMLIMIT_SENSITIVE
MAXIMUM_KDF_OPERATIONS = pwhash.argon2id.OPSLIMIT_SENSITIVE


@dataclass(frozen=True, slots=True)
class KdfParameters:
    opslimit: int = pwhash.argon2id.OPSLIMIT_MODERATE
    memlimit: int = pwhash.argon2id.MEMLIMIT_MODERATE


class UnlockedSession:
    """Best-effort in-memory owner of an unlocked master key."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != secret.SecretBox.KEY_SIZE:
            raise ValueError("Unexpected master-key length")
        self._master_key: bytearray | None = bytearray(master_key)

    @property
    def is_unlocked(self) -> bool:
        return self._master_key is not None

    def master_key_copy(self) -> bytes:
        if self._master_key is None:
            raise SessionLockedError("Сеанс заблокирован.")
        return bytes(self._master_key)

    def lock(self) -> None:
        if self._master_key is not None:
            for index in range(len(self._master_key)):
                self._master_key[index] = 0
            self._master_key = None

    def __enter__(self) -> UnlockedSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.lock()

    def __del__(self) -> None:
        self.lock()


class ProfileService:
    def __init__(
        self,
        repository: ProfileRepository,
        kdf_parameters: KdfParameters | None = None,
    ) -> None:
        self.repository = repository
        self.kdf_parameters = kdf_parameters or KdfParameters()
        self._validate_kdf_parameters(
            self.kdf_parameters.opslimit, self.kdf_parameters.memlimit
        )

    def create_profile(
        self,
        display_name: str,
        master_password: str,
        unlock_mode: UnlockMode = UnlockMode.PASSWORD_OR_FACE,
    ) -> Profile:
        clean_name = display_name.strip()
        if not clean_name:
            raise ValidationError("Введите имя профиля.")
        if len(clean_name) > 100:
            raise ValidationError("Имя профиля не должно превышать 100 символов.")
        password_bytes = self._validate_password(master_password)

        salt = utils.random(pwhash.argon2id.SALTBYTES)
        password_key = self._derive_password_key(
            password_bytes,
            salt,
            self.kdf_parameters.opslimit,
            self.kdf_parameters.memlimit,
        )
        master_key = utils.random(secret.SecretBox.KEY_SIZE)
        try:
            encrypted_master_key = bytes(secret.SecretBox(password_key).encrypt(master_key))
            profile = Profile(
                profile_id=str(uuid4()),
                display_name=clean_name,
                unlock_mode=unlock_mode,
                kdf_salt=salt,
                kdf_opslimit=self.kdf_parameters.opslimit,
                kdf_memlimit=self.kdf_parameters.memlimit,
                encrypted_master_key=encrypted_master_key,
                created_at=datetime.now(UTC).isoformat(),
            )
            self.repository.save_profile(profile)
            return profile
        finally:
            del password_key
            del master_key

    def unlock_with_password(self, master_password: str) -> UnlockedSession:
        profile = self.repository.get_profile()
        if profile is None:
            raise ProfileNotFoundError("Локальный профиль не найден.")

        password_bytes = self._validate_password(master_password)
        self._validate_kdf_parameters(profile.kdf_opslimit, profile.kdf_memlimit)
        password_key = self._derive_password_key(
            password_bytes,
            profile.kdf_salt,
            profile.kdf_opslimit,
            profile.kdf_memlimit,
        )
        try:
            master_key = secret.SecretBox(password_key).decrypt(
                profile.encrypted_master_key
            )
        except exceptions.CryptoError as error:
            raise AuthenticationError("Неверный мастер-пароль.") from error
        finally:
            del password_key

        return UnlockedSession(master_key)

    @staticmethod
    def _validate_password(password: str) -> bytes:
        if len(password) < MINIMUM_PASSWORD_LENGTH:
            raise ValidationError(
                f"Мастер-пароль должен содержать не менее {MINIMUM_PASSWORD_LENGTH} символов."
            )
        encoded = password.encode("utf-8")
        if len(encoded) > MAXIMUM_PASSWORD_BYTES:
            raise ValidationError("Мастер-пароль слишком длинный.")
        return encoded

    @staticmethod
    def _validate_kdf_parameters(opslimit: int, memlimit: int) -> None:
        if not pwhash.argon2id.OPSLIMIT_MIN <= opslimit <= MAXIMUM_KDF_OPERATIONS:
            raise ValidationError("Недопустимый параметр Argon2id opslimit.")
        if not pwhash.argon2id.MEMLIMIT_MIN <= memlimit <= MAXIMUM_KDF_MEMORY:
            raise ValidationError("Недопустимый параметр Argon2id memlimit.")

    @staticmethod
    def _derive_password_key(
        password: bytes,
        salt: bytes,
        opslimit: int,
        memlimit: int,
    ) -> bytes:
        return pwhash.argon2id.kdf(
            secret.SecretBox.KEY_SIZE,
            password,
            salt,
            opslimit=opslimit,
            memlimit=memlimit,
        )
