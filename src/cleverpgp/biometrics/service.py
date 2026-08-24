from __future__ import annotations

import struct
from datetime import UTC, datetime

import numpy as np
from nacl import exceptions, secret, utils

from cleverpgp.biometrics.face_engine import FACE_MATCH_THRESHOLD, FaceEngine
from cleverpgp.biometrics.key_protection import KeyProtector
from cleverpgp.biometrics.model_assets import MODEL_ID, MODEL_SHA256
from cleverpgp.core.errors import (
    AuthenticationError,
    BiometricNotEnrolledError,
    BiometricUnavailableError,
    ValidationError,
)
from cleverpgp.core.models import BiometricProfile
from cleverpgp.core.profile_service import UnlockedSession
from cleverpgp.core.storage import ProfileRepository

TEMPLATE_MAGIC = b"BPGPTPL1"
TEMPLATE_PREFIX = struct.Struct(">8sH")
MAXIMUM_TEMPLATE_ELEMENTS = 4096


class BiometricVerificationContext:
    def __init__(
        self,
        record: BiometricProfile,
        biometric_key: bytes,
        template: np.ndarray,
    ) -> None:
        self.record = record
        self._biometric_key: bytearray | None = bytearray(biometric_key)
        self.template = template.copy()
        self.threshold = max(record.match_threshold, FACE_MATCH_THRESHOLD)

    def unlock(self, match_score: float, *, liveness_passed: bool) -> UnlockedSession:
        if self._biometric_key is None:
            raise BiometricUnavailableError("Биометрическая проверка уже завершена.")
        if not liveness_passed or match_score < self.threshold:
            self.close()
            raise AuthenticationError("Лицо не прошло проверку Clever PGP.")
        try:
            master_key = secret.SecretBox(bytes(self._biometric_key)).decrypt(
                self.record.encrypted_master_key
            )
        except exceptions.CryptoError as error:
            self.close()
            raise BiometricUnavailableError(
                "Биометрический слот ключа повреждён. Используйте мастер-пароль."
            ) from error
        self.close()
        return UnlockedSession(master_key)

    def close(self) -> None:
        if self._biometric_key is not None:
            for index in range(len(self._biometric_key)):
                self._biometric_key[index] = 0
            self._biometric_key = None
        if self.template.size:
            self.template.fill(0)

    def __enter__(self) -> BiometricVerificationContext:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()


class BiometricService:
    def __init__(self, repository: ProfileRepository, protector: KeyProtector) -> None:
        self.repository = repository
        self.protector = protector

    def is_enrolled(self) -> bool:
        return self.repository.has_biometric_profile()

    def enroll(self, template: np.ndarray, master_key: bytes) -> None:
        profile = self.repository.get_profile()
        if profile is None:
            raise ValidationError("Сначала создайте локальный профиль.")
        if len(master_key) != secret.SecretBox.KEY_SIZE:
            raise ValidationError("Некорректный мастер-ключ текущего сеанса.")

        serialized_template = self._serialize_template(template)
        biometric_key = bytearray(utils.random(secret.SecretBox.KEY_SIZE))
        entropy = self._entropy(profile.profile_id)
        try:
            key_bytes = bytes(biometric_key)
            protected_key = self.protector.protect(key_bytes, entropy)
            encrypted_template = bytes(
                secret.SecretBox(key_bytes).encrypt(serialized_template)
            )
            encrypted_master_key = bytes(secret.SecretBox(key_bytes).encrypt(master_key))
            self.repository.save_biometric_profile(
                BiometricProfile(
                    profile_id=profile.profile_id,
                    protected_biometric_key=protected_key,
                    encrypted_template=encrypted_template,
                    encrypted_master_key=encrypted_master_key,
                    model_id=MODEL_ID,
                    model_sha256=MODEL_SHA256,
                    match_threshold=FACE_MATCH_THRESHOLD,
                    enrolled_at=datetime.now(UTC).isoformat(),
                )
            )
        finally:
            biometric_key[:] = b"\x00" * len(biometric_key)
            del master_key

    def begin_verification(self) -> BiometricVerificationContext:
        profile = self.repository.get_profile()
        record = self.repository.get_biometric_profile()
        if profile is None or record is None:
            raise BiometricNotEnrolledError("Лицо ещё не зарегистрировано.")
        if record.profile_id != profile.profile_id:
            raise BiometricUnavailableError("Биометрический слот относится к другому профилю.")
        if record.model_id != MODEL_ID or record.model_sha256 != MODEL_SHA256:
            raise BiometricUnavailableError(
                "Биометрический шаблон создан другой версией модели. Используйте пароль и перерегистрируйте лицо."
            )
        if not 0.0 < record.match_threshold <= 1.0:
            raise BiometricUnavailableError("Порог биометрического профиля повреждён.")

        entropy = self._entropy(profile.profile_id)
        biometric_key = bytearray(
            self.protector.unprotect(record.protected_biometric_key, entropy)
        )
        if len(biometric_key) != secret.SecretBox.KEY_SIZE:
            biometric_key[:] = b"\x00" * len(biometric_key)
            raise BiometricUnavailableError("Защищённый биометрический ключ повреждён.")
        try:
            serialized = secret.SecretBox(bytes(biometric_key)).decrypt(
                record.encrypted_template
            )
            template = self._deserialize_template(serialized)
            return BiometricVerificationContext(record, bytes(biometric_key), template)
        except exceptions.CryptoError as error:
            raise BiometricUnavailableError(
                "Биометрический шаблон повреждён. Используйте мастер-пароль."
            ) from error
        finally:
            biometric_key[:] = b"\x00" * len(biometric_key)

    @staticmethod
    def _entropy(profile_id: str) -> bytes:
        return b"BioPGP biometric slot v1|" + profile_id.encode("ascii")

    @staticmethod
    def _serialize_template(template: np.ndarray) -> bytes:
        vector = FaceEngine.normalize(template)
        if vector.size > MAXIMUM_TEMPLATE_ELEMENTS:
            raise ValidationError("Биометрический шаблон слишком большой.")
        little_endian = np.asarray(vector, dtype="<f4")
        return TEMPLATE_PREFIX.pack(TEMPLATE_MAGIC, vector.size) + little_endian.tobytes()

    @staticmethod
    def _deserialize_template(serialized: bytes) -> np.ndarray:
        if len(serialized) < TEMPLATE_PREFIX.size:
            raise BiometricUnavailableError("Биометрический шаблон оборван.")
        magic, element_count = TEMPLATE_PREFIX.unpack(
            serialized[: TEMPLATE_PREFIX.size]
        )
        if magic != TEMPLATE_MAGIC or not 64 <= element_count <= MAXIMUM_TEMPLATE_ELEMENTS:
            raise BiometricUnavailableError("Неподдерживаемый формат шаблона лица.")
        payload = serialized[TEMPLATE_PREFIX.size :]
        if len(payload) != element_count * 4:
            raise BiometricUnavailableError("Некорректный размер шаблона лица.")
        vector = np.frombuffer(payload, dtype="<f4").astype(np.float32, copy=True)
        return FaceEngine.normalize(vector)
