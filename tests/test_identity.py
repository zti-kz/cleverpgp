from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from nacl import pwhash

from biopgp.core.errors import ContactExistsError, ValidationError
from biopgp.core.identity import (
    IdentityService,
    decode_public_identity,
    formatted_fingerprint,
)
from biopgp.core.profile_service import KdfParameters, ProfileService
from biopgp.core.storage import ProfileRepository


def _profile(tmp_path: Path, name: str) -> tuple[ProfileRepository, ProfileService]:
    repository = ProfileRepository(tmp_path / f"{name}.sqlite3")
    repository.initialize()
    profiles = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    profiles.create_profile(name, "correct horse battery staple")
    return repository, profiles


def test_identity_is_random_stable_and_wrapped_by_master_key(tmp_path: Path) -> None:
    repository, profiles = _profile(tmp_path, "Алмас")
    session = profiles.unlock_with_password("correct horse battery staple")
    master_key = session.master_key_copy()
    identities = IdentityService(repository)

    first = identities.ensure_unlocked(master_key)
    first_public = first.public_identity
    first_private = first.encryption_private_key_copy()
    first.lock()
    second = identities.ensure_unlocked(master_key)

    assert second.public_identity == first_public
    assert second.encryption_private_key_copy() == first_private
    stored = repository.get_cryptographic_identity()
    assert stored is not None
    assert first_private not in stored.encrypted_encryption_private_key
    assert stored.encryption_public_key == first_public.encryption_public_key
    assert len(first_public.fingerprint) == 64
    second.lock()
    session.lock()


def test_public_bundle_self_signature_and_contact_import(tmp_path: Path) -> None:
    sender_repository, sender_profiles = _profile(tmp_path, "Alice")
    sender_session = sender_profiles.unlock_with_password(
        "correct horse battery staple"
    )
    key_file = tmp_path / "alice.cpgk"
    IdentityService(sender_repository).export_public_identity(
        key_file,
        sender_session.master_key_copy(),
    )

    decoded = decode_public_identity(key_file.read_bytes())
    assert decoded.display_name == "Alice"
    assert formatted_fingerprint(decoded.fingerprint).replace(" ", "") == (
        decoded.fingerprint
    )

    recipient_repository, _recipient_profiles = _profile(tmp_path, "Bob")
    contact = IdentityService(recipient_repository).import_contact(key_file)
    assert contact.display_name == "Alice"
    assert recipient_repository.list_contacts() == (contact,)
    with pytest.raises(ContactExistsError):
        IdentityService(recipient_repository).import_contact(key_file)
    sender_session.lock()


def test_tampered_public_bundle_is_rejected(tmp_path: Path) -> None:
    repository, profiles = _profile(tmp_path, "Alice")
    session = profiles.unlock_with_password("correct horse battery staple")
    key_file = tmp_path / "alice.cpgk"
    IdentityService(repository).export_public_identity(
        key_file,
        session.master_key_copy(),
    )
    damaged = bytearray(key_file.read_bytes())
    damaged[-10] ^= 1

    with pytest.raises(ValidationError):
        decode_public_identity(bytes(damaged))
    session.lock()


def test_master_password_change_keeps_identity_accessible(tmp_path: Path) -> None:
    repository, profiles = _profile(tmp_path, "Alice")
    old_session = profiles.unlock_with_password("correct horse battery staple")
    identity_service = IdentityService(repository)
    old_identity = identity_service.public_identity(old_session.master_key_copy())
    old_session.lock()

    profiles.change_master_password(
        "correct horse battery staple",
        "new correct horse battery staple",
    )
    new_session = profiles.unlock_with_password(
        "new correct horse battery staple"
    )
    assert identity_service.public_identity(new_session.master_key_copy()) == old_identity
    new_session.lock()


def test_current_profile_key_cannot_be_imported_as_contact(tmp_path: Path) -> None:
    repository, profiles = _profile(tmp_path, "Alice")
    session = profiles.unlock_with_password("correct horse battery staple")
    service = IdentityService(repository)
    key_file = tmp_path / "alice.cpgk"
    service.export_public_identity(key_file, session.master_key_copy())

    with pytest.raises(ValidationError, match="текущего профиля"):
        service.import_contact(key_file)
    session.lock()


def test_schema_two_profile_is_upgraded_without_replacement(tmp_path: Path) -> None:
    repository, _profiles = _profile(tmp_path, "Alice")
    original_profile = repository.get_profile()
    with sqlite3.connect(repository.path) as connection:
        connection.execute("DROP TABLE contact")
        connection.execute("DROP TABLE cryptographic_identity")
        connection.execute(
            "UPDATE metadata SET value = '2' WHERE key = 'schema_version'"
        )

    repository.initialize()

    assert repository.get_profile() == original_profile
    assert repository.get_setting("schema_version") == "3"
    with sqlite3.connect(repository.path) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert {"cryptographic_identity", "contact"} <= tables
