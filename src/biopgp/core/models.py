from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class UnlockMode(StrEnum):
    PASSWORD_OR_FACE = "password_or_face"
    PASSWORD_ONLY = "password_only"
    FACE_ONLY = "face_only"
    PASSWORD_AND_FACE = "password_and_face"

    @property
    def display_name(self) -> str:
        return {
            self.PASSWORD_OR_FACE: "Лицо или мастер-пароль",
            self.PASSWORD_ONLY: "Только мастер-пароль",
            self.FACE_ONLY: "Только лицо",
            self.PASSWORD_AND_FACE: "Мастер-пароль + лицо (MFA)",
        }[self]


@dataclass(frozen=True, slots=True)
class Profile:
    profile_id: str
    display_name: str
    unlock_mode: UnlockMode
    kdf_salt: bytes
    kdf_opslimit: int
    kdf_memlimit: int
    encrypted_master_key: bytes
    created_at: str


@dataclass(frozen=True, slots=True)
class BiometricProfile:
    profile_id: str
    protected_biometric_key: bytes
    encrypted_template: bytes
    encrypted_master_key: bytes
    model_id: str
    model_sha256: str
    match_threshold: float
    enrolled_at: str
