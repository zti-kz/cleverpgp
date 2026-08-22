from pathlib import Path

import pytest
from nacl import pwhash, secret

from biopgp.core.errors import AuthenticationError, ValidationError
from biopgp.core.models import BiometricProfile
from biopgp.core.models import UnlockMode
from biopgp.core.profile_service import KdfParameters, ProfileService
from biopgp.core.storage import ProfileRepository


@pytest.fixture
def profile_service(tmp_path: Path) -> ProfileService:
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    return ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )


def test_profile_round_trip_and_unlock(profile_service: ProfileService) -> None:
    profile = profile_service.create_profile(
        "  Алмас  ", "correct horse battery staple", UnlockMode.PASSWORD_OR_FACE
    )

    assert profile.display_name == "Алмас"
    assert profile.unlock_mode is UnlockMode.PASSWORD_OR_FACE
    assert b"correct horse" not in profile.encrypted_master_key

    session = profile_service.unlock_with_password("correct horse battery staple")
    assert session.is_unlocked
    assert len(session.master_key_copy()) == secret.SecretBox.KEY_SIZE
    session.lock()
    assert not session.is_unlocked


def test_wrong_password_is_rejected(profile_service: ProfileService) -> None:
    profile_service.create_profile("Алмас", "correct horse battery staple")

    with pytest.raises(AuthenticationError):
        profile_service.unlock_with_password("this password is wrong")


def test_short_password_is_rejected(profile_service: ProfileService) -> None:
    with pytest.raises(ValidationError):
        profile_service.create_profile("Алмас", "short")


def test_master_password_change_preserves_master_key_and_biometric_slot(
    profile_service: ProfileService,
) -> None:
    old_password = "correct horse battery staple"
    new_password = "new correct horse battery staple"
    profile = profile_service.create_profile("Алмас", old_password)
    original_session = profile_service.unlock_with_password(old_password)
    original_master_key = original_session.master_key_copy()
    original_session.lock()
    biometric = BiometricProfile(
        profile_id=profile.profile_id,
        protected_biometric_key=b"protected-key",
        encrypted_template=b"encrypted-template",
        encrypted_master_key=b"biometric-master-key-slot",
        model_id="test-model",
        model_sha256="0" * 64,
        match_threshold=0.7,
        enrolled_at="2026-08-23T00:00:00+00:00",
    )
    profile_service.repository.save_biometric_profile(biometric)

    updated = profile_service.change_master_password(old_password, new_password)

    assert updated.profile_id == profile.profile_id
    assert updated.kdf_salt != profile.kdf_salt
    assert updated.encrypted_master_key != profile.encrypted_master_key
    assert profile_service.repository.get_biometric_profile() == biometric
    with pytest.raises(AuthenticationError):
        profile_service.unlock_with_password(old_password)
    new_session = profile_service.unlock_with_password(new_password)
    assert new_session.master_key_copy() == original_master_key
    new_session.lock()


def test_password_change_failure_leaves_existing_password_valid(
    profile_service: ProfileService,
) -> None:
    old_password = "correct horse battery staple"
    profile_service.create_profile("Алмас", old_password)

    with pytest.raises(AuthenticationError):
        profile_service.change_master_password(
            "wrong current password",
            "new correct horse battery staple",
        )
    with pytest.raises(ValidationError):
        profile_service.change_master_password(old_password, "too short")

    session = profile_service.unlock_with_password(old_password)
    assert session.is_unlocked
    session.lock()


def test_face_dependent_unlock_modes_require_enrollment(
    profile_service: ProfileService,
) -> None:
    profile = profile_service.create_profile(
        "Алмас", "correct horse battery staple"
    )

    with pytest.raises(ValidationError):
        profile_service.change_unlock_mode(UnlockMode.FACE_ONLY)
    with pytest.raises(ValidationError):
        profile_service.change_unlock_mode(UnlockMode.PASSWORD_AND_FACE)

    changed = profile_service.change_unlock_mode(UnlockMode.PASSWORD_ONLY)
    assert changed.unlock_mode is UnlockMode.PASSWORD_ONLY

    profile_service.repository.save_biometric_profile(
        BiometricProfile(
            profile_id=profile.profile_id,
            protected_biometric_key=b"protected-key",
            encrypted_template=b"encrypted-template",
            encrypted_master_key=b"biometric-master-key-slot",
            model_id="test-model",
            model_sha256="0" * 64,
            match_threshold=0.7,
            enrolled_at="2026-08-23T00:00:00+00:00",
        )
    )
    changed = profile_service.change_unlock_mode(UnlockMode.PASSWORD_AND_FACE)
    assert changed.unlock_mode is UnlockMode.PASSWORD_AND_FACE
