from __future__ import annotations

from pathlib import Path

import pytest
from nacl import pwhash

from cleverpgp.core.errors import AuthenticationError
from cleverpgp.core.identity import IdentityService, read_public_identity
from cleverpgp.core.file_crypto import FileCryptoService
from cleverpgp.core.portable_keys import PortableKeyService
from cleverpgp.core.storage import ProfileRepository


def _service(path: Path) -> tuple[ProfileRepository, PortableKeyService]:
    repository = ProfileRepository(path)
    repository.initialize()
    return repository, PortableKeyService(
        repository,
        opslimit=pwhash.argon2id.OPSLIMIT_MIN,
        memlimit=pwhash.argon2id.MEMLIMIT_MIN,
    )


def test_key_is_password_protected_and_private_export_requires_password(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "alice.sqlite3")
    record = service.create_key("Алмас Өскенбай", "FriendlyKey@2026")
    stored = repository.get_user_key(record.key_id)
    assert stored is not None

    with service.unlock_key(record, "FriendlyKey@2026") as unlocked:
        private = unlocked.encryption_private_key_copy()
        assert unlocked.public_identity.fingerprint == record.fingerprint
    assert private not in stored.encrypted_private_bundle

    with pytest.raises(AuthenticationError):
        service.export_private_key(
            record,
            "WrongPassword@2026",
            tmp_path / "alice.cpgx",
        )
    assert not (tmp_path / "alice.cpgx").exists()


def test_private_key_round_trip_requires_password_on_import(tmp_path: Path) -> None:
    alice_repository, alice = _service(tmp_path / "alice.sqlite3")
    record = alice.create_key("Alice", "FriendlyKey@2026")
    bundle = tmp_path / "alice.cpgx"
    alice.export_private_key(record, "FriendlyKey@2026", bundle)

    _bob_repository, bob = _service(tmp_path / "bob.sqlite3")
    with pytest.raises(AuthenticationError):
        bob.import_private_key(bundle, "WrongPassword@2026")
    imported = bob.import_private_key(bundle, "FriendlyKey@2026")
    assert imported.fingerprint == record.fingerprint
    assert alice_repository.list_user_keys() == (record,)


def test_public_key_is_self_signed_and_can_be_added_as_recipient(
    tmp_path: Path,
) -> None:
    _alice_repository, alice = _service(tmp_path / "alice.sqlite3")
    record = alice.create_key("Alice", "FriendlyKey@2026")
    public_bundle = tmp_path / "alice.cpgk"
    alice.export_public_key(
        record,
        "FriendlyKey@2026",
        public_bundle,
    )
    public_identity = read_public_identity(public_bundle)
    assert public_identity.fingerprint == record.fingerprint

    bob_repository, _bob = _service(tmp_path / "bob.sqlite3")
    contact = IdentityService(bob_repository).import_contact(public_bundle)
    assert contact.fingerprint == record.fingerprint


def test_file_can_be_encrypted_for_multiple_password_protected_keys(
    tmp_path: Path,
) -> None:
    alice_repository, alice = _service(tmp_path / "alice.sqlite3")
    bob_repository, bob = _service(tmp_path / "bob.sqlite3")
    alice_key = alice.create_key("Alice", "AliceFriendly@2026")
    bob_key = bob.create_key("Bob", "BobFriendly@2026")
    source = tmp_path / "message.txt"
    encrypted = tmp_path / "message.txt.cpgp"
    source.write_text("message for two recipients", encoding="utf-8")
    files = FileCryptoService(alice_repository)

    with alice.unlock_key(alice_key, "AliceFriendly@2026") as sender:
        files.encrypt_file_with_identity(
            source,
            encrypted,
            sender,
            recipients=(
                read_public_identity(
                    bob.export_public_key(
                        bob_key,
                        "BobFriendly@2026",
                        tmp_path / "bob.cpgk",
                    )
                ),
            ),
        )

    with bob.unlock_key(bob_key, "BobFriendly@2026") as recipient:
        result = FileCryptoService(bob_repository).decrypt_file_with_identity(
            encrypted,
            tmp_path / "restored.txt",
            recipient,
        )
    assert result.sender.display_name == "Alice"
    assert (tmp_path / "restored.txt").read_text(encoding="utf-8") == (
        "message for two recipients"
    )
