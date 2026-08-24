from pathlib import Path

import numpy as np
import pytest
from nacl import pwhash, secret, utils

from cleverpgp.biometrics.service import BiometricService
from cleverpgp.core.errors import AuthenticationError
from cleverpgp.core.profile_service import KdfParameters, ProfileService
from cleverpgp.core.storage import ProfileRepository


class MemoryProtector:
    def __init__(self) -> None:
        self.key = utils.random(secret.SecretBox.KEY_SIZE)

    def protect(self, plaintext: bytes, entropy: bytes) -> bytes:
        return bytes(secret.SecretBox(self.key).encrypt(entropy + plaintext))

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes:
        combined = secret.SecretBox(self.key).decrypt(protected)
        if not combined.startswith(entropy):
            raise ValueError("wrong entropy")
        return combined[len(entropy) :]


def make_repository(tmp_path: Path) -> tuple[ProfileRepository, bytes]:
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profiles = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    profiles.create_profile("Алмас", "correct horse battery staple")
    session = profiles.unlock_with_password("correct horse battery staple")
    key = session.master_key_copy()
    session.lock()
    return repository, key


def test_biometric_slot_unlocks_same_master_key(tmp_path: Path) -> None:
    repository, master_key = make_repository(tmp_path)
    service = BiometricService(repository, MemoryProtector())
    template = np.linspace(0.1, 1.0, 128, dtype=np.float32)
    service.enroll(template, master_key)

    context = service.begin_verification()
    assert context.threshold >= 0.45
    session = context.unlock(0.95, liveness_passed=True)

    assert session.master_key_copy() == master_key
    assert repository.get_biometric_profile() is not None
    session.lock()


def test_liveness_is_required_for_biometric_unlock(tmp_path: Path) -> None:
    repository, master_key = make_repository(tmp_path)
    service = BiometricService(repository, MemoryProtector())
    service.enroll(np.linspace(0.1, 1.0, 128, dtype=np.float32), master_key)
    context = service.begin_verification()

    with pytest.raises(AuthenticationError):
        context.unlock(0.99, liveness_passed=False)


def test_dpapi_round_trip_on_windows() -> None:
    import sys

    if sys.platform != "win32":
        pytest.skip("Windows-only DPAPI test")
    from cleverpgp.biometrics.key_protection import WindowsDpapiProtector

    protector = WindowsDpapiProtector()
    plaintext = utils.random(32)
    entropy = b"BioPGP test entropy"
    protected = protector.protect(plaintext, entropy)

    assert protected != plaintext
    assert protector.unprotect(protected, entropy) == plaintext
