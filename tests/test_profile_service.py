from pathlib import Path

import pytest
from nacl import pwhash, secret

from biopgp.core.errors import AuthenticationError, ValidationError
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
