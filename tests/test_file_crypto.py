from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from nacl import pwhash, secret, utils

from cleverpgp.core.errors import (
    CryptographicIdentityError,
    InvalidEncryptedFileError,
    OutputExistsError,
    ValidationError,
)
from cleverpgp.core.file_crypto import FileCryptoService
from cleverpgp.core.identity import IdentityService
from cleverpgp.core.profile_service import KdfParameters, ProfileService
from cleverpgp.core.storage import ProfileRepository


def _profile(
    directory: Path,
    name: str,
) -> tuple[ProfileRepository, FileCryptoService, bytes]:
    repository = ProfileRepository(directory / f"{name}.sqlite3")
    repository.initialize()
    profiles = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    profiles.create_profile(name, "correct horse battery staple")
    session = profiles.unlock_with_password("correct horse battery staple")
    key = session.master_key_copy()
    session.lock()
    return repository, FileCryptoService(repository), key


@pytest.fixture
def crypto(tmp_path: Path) -> tuple[FileCryptoService, bytes]:
    _repository, service, master_key = _profile(tmp_path, "Алмас")
    return service, master_key


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"Clever PGP test data", id="short"),
        pytest.param(utils.random(2 * 1024 * 1024 + 137), id="multi-chunk"),
    ],
)
def test_file_round_trip_is_signed(
    tmp_path: Path,
    crypto: tuple[FileCryptoService, bytes],
    payload: bytes,
) -> None:
    service, master_key = crypto
    source = tmp_path / "document.bin"
    encrypted = tmp_path / "document.bin.cpgp"
    decrypted = tmp_path / "document.restored.bin"
    source.write_bytes(payload)

    service.encrypt_file(source, encrypted, master_key)
    result = service.decrypt_file_detailed(encrypted, decrypted, master_key)

    assert decrypted.read_bytes() == payload
    assert encrypted.read_bytes() != payload
    assert result.sender_is_self
    assert result.sender_is_known
    assert result.sender.display_name == "Алмас"


@pytest.mark.parametrize("extension", [".cpgp", ".cpgv", ".cpgk", ".CPGP"])
def test_cleverpgp_formats_are_not_encrypted_again(
    tmp_path: Path,
    crypto: tuple[FileCryptoService, bytes],
    extension: str,
) -> None:
    service, master_key = crypto
    source = tmp_path / f"protected{extension}"
    target = tmp_path / f"protected{extension}.cpgp"
    source.write_bytes(b"already protected")

    with pytest.raises(ValidationError, match="Повторное шифрование"):
        service.encrypt_file(source, target, master_key)

    assert not target.exists()


def test_multi_recipient_file_opens_for_sender_and_recipient(tmp_path: Path) -> None:
    alice_repo, alice_files, alice_key = _profile(tmp_path, "Alice")
    bob_repo, bob_files, bob_key = _profile(tmp_path, "Bob")
    alice_identity = IdentityService(alice_repo).public_identity(alice_key)
    bob_identity = IdentityService(bob_repo).public_identity(bob_key)
    source = tmp_path / "shared.txt"
    encrypted = tmp_path / "shared.txt.cpgp"
    source.write_text("shared authenticated message", encoding="utf-8")

    alice_files.encrypt_file(
        source,
        encrypted,
        alice_key,
        recipients=(bob_identity,),
    )
    own_result = alice_files.decrypt_file_detailed(
        encrypted,
        tmp_path / "alice.txt",
        alice_key,
    )
    unknown_result = bob_files.decrypt_file_detailed(
        encrypted,
        tmp_path / "bob-unknown.txt",
        bob_key,
    )

    assert own_result.sender_is_self
    assert not unknown_result.sender_is_self
    assert not unknown_result.sender_is_known

    alice_bundle = tmp_path / "alice.cpgk"
    IdentityService(alice_repo).export_public_identity(alice_bundle, alice_key)
    IdentityService(bob_repo).import_contact(alice_bundle)
    known_result = bob_files.decrypt_file_detailed(
        encrypted,
        tmp_path / "bob-known.txt",
        bob_key,
    )
    assert known_result.sender == alice_identity
    assert known_result.sender_is_known
    assert (tmp_path / "bob-known.txt").read_text(encoding="utf-8") == (
        "shared authenticated message"
    )


def test_corrupted_known_contact_never_publishes_plaintext(tmp_path: Path) -> None:
    alice_repo, alice_files, alice_key = _profile(tmp_path, "Alice")
    bob_repo, bob_files, bob_key = _profile(tmp_path, "Bob")
    bob_identity = IdentityService(bob_repo).public_identity(bob_key)
    source = tmp_path / "shared.txt"
    encrypted = tmp_path / "shared.txt.cpgp"
    restored = tmp_path / "must-not-exist.txt"
    source.write_text("authenticated message", encoding="utf-8")
    alice_files.encrypt_file(
        source,
        encrypted,
        alice_key,
        recipients=(bob_identity,),
    )

    alice_bundle = tmp_path / "alice.cpgk"
    IdentityService(alice_repo).export_public_identity(alice_bundle, alice_key)
    contact = IdentityService(bob_repo).import_contact(alice_bundle)
    with sqlite3.connect(bob_repo.path) as connection:
        connection.execute(
            "UPDATE contact SET signing_public_key = ? WHERE contact_id = ?",
            (utils.random(32), contact.contact_id),
        )

    with pytest.raises(CryptographicIdentityError, match="повреждены"):
        bob_files.decrypt_file_detailed(encrypted, restored, bob_key)
    assert not restored.exists()


def test_file_not_addressed_to_profile_is_rejected(tmp_path: Path) -> None:
    _alice_repo, alice_files, alice_key = _profile(tmp_path, "Alice")
    _bob_repo, bob_files, bob_key = _profile(tmp_path, "Bob")
    source = tmp_path / "private.txt"
    encrypted = tmp_path / "private.txt.cpgp"
    source.write_text("for Alice", encoding="utf-8")
    alice_files.encrypt_file(source, encrypted, alice_key)

    with pytest.raises(InvalidEncryptedFileError, match="не зашифрован"):
        bob_files.decrypt_file(
            encrypted,
            tmp_path / "should-not-exist.txt",
            bob_key,
        )
    assert not (tmp_path / "should-not-exist.txt").exists()


def test_tampering_is_detected_without_output(
    tmp_path: Path,
    crypto: tuple[FileCryptoService, bytes],
) -> None:
    service, master_key = crypto
    source = tmp_path / "source.txt"
    encrypted = tmp_path / "source.txt.cpgp"
    decrypted = tmp_path / "should-not-exist.txt"
    source.write_bytes(b"authenticated content")
    service.encrypt_file(source, encrypted, master_key)

    damaged = bytearray(encrypted.read_bytes())
    damaged[-1] ^= 1
    encrypted.write_bytes(damaged)

    with pytest.raises(InvalidEncryptedFileError):
        service.decrypt_file(encrypted, decrypted, master_key)

    assert not decrypted.exists()


def test_wrong_master_key_is_rejected(
    tmp_path: Path,
    crypto: tuple[FileCryptoService, bytes],
) -> None:
    service, master_key = crypto
    source = tmp_path / "source.txt"
    encrypted = tmp_path / "source.txt.cpgp"
    decrypted = tmp_path / "should-not-exist.txt"
    source.write_text("secret", encoding="utf-8")
    service.encrypt_file(source, encrypted, master_key)

    with pytest.raises(CryptographicIdentityError):
        service.decrypt_file(
            encrypted,
            decrypted,
            utils.random(secret.SecretBox.KEY_SIZE),
        )
    assert not decrypted.exists()


def test_trailing_data_is_rejected(
    tmp_path: Path,
    crypto: tuple[FileCryptoService, bytes],
) -> None:
    service, master_key = crypto
    source = tmp_path / "source.txt"
    encrypted = tmp_path / "source.txt.cpgp"
    decrypted = tmp_path / "should-not-exist.txt"
    source.write_text("secret", encoding="utf-8")
    service.encrypt_file(source, encrypted, master_key)

    with encrypted.open("ab") as stream:
        stream.write(b"untrusted trailing bytes")

    with pytest.raises(InvalidEncryptedFileError):
        service.decrypt_file(encrypted, decrypted, master_key)
    assert not decrypted.exists()


def test_existing_target_is_not_overwritten(
    tmp_path: Path,
    crypto: tuple[FileCryptoService, bytes],
) -> None:
    service, master_key = crypto
    source = tmp_path / "source.txt"
    target = tmp_path / "target.cpgp"
    source.write_text("source", encoding="utf-8")
    target.write_text("keep me", encoding="utf-8")

    with pytest.raises(OutputExistsError):
        service.encrypt_file(source, target, master_key)
    assert target.read_text(encoding="utf-8") == "keep me"


def test_new_extension_magic_and_version_are_used(
    tmp_path: Path,
    crypto: tuple[FileCryptoService, bytes],
) -> None:
    service, master_key = crypto
    source = tmp_path / "report.txt"
    source.write_text("Clever PGP", encoding="utf-8")
    target = service.default_encrypted_path(source)

    service.encrypt_file(source, target, master_key)

    assert target.name == "report.txt.cpgp"
    assert target.read_bytes().startswith(b"CPGPFILE\x02")


def test_old_file_version_is_rejected(
    tmp_path: Path,
    crypto: tuple[FileCryptoService, bytes],
) -> None:
    service, master_key = crypto
    source = tmp_path / "report.txt"
    encrypted = tmp_path / "report.txt.cpgp"
    source.write_text("Clever PGP", encoding="utf-8")
    service.encrypt_file(source, encrypted, master_key)
    raw = bytearray(encrypted.read_bytes())
    raw[8] = 1
    encrypted.write_bytes(raw)

    with pytest.raises(InvalidEncryptedFileError, match="Версия формата 1"):
        service.decrypt_file(encrypted, tmp_path / "restored.txt", master_key)


def test_file_operations_report_real_percentage_progress(
    tmp_path: Path,
    crypto: tuple[FileCryptoService, bytes],
) -> None:
    service, master_key = crypto
    source = tmp_path / "large.bin"
    encrypted = tmp_path / "large.bin.cpgp"
    restored = tmp_path / "large.restored.bin"
    source.write_bytes(utils.random(2 * 1024 * 1024 + 123))
    encrypted_updates: list[tuple[int, str]] = []
    decrypted_updates: list[tuple[int, str]] = []

    service.encrypt_file(
        source,
        encrypted,
        master_key,
        progress=lambda value, message: encrypted_updates.append((value, message)),
    )
    service.decrypt_file(
        encrypted,
        restored,
        master_key,
        progress=lambda value, message: decrypted_updates.append((value, message)),
    )

    for updates in (encrypted_updates, decrypted_updates):
        values = [value for value, _message in updates]
        assert values == sorted(values)
        assert values[-1] == 100
        assert len(set(values)) >= 4
        assert all(message for _value, message in updates)
    assert restored.read_bytes() == source.read_bytes()
def test_password_file_is_portable_without_a_local_profile(tmp_path: Path) -> None:
    source = tmp_path / "portable report.txt"
    encrypted = tmp_path / "portable report.txt.cpgp"
    restored = tmp_path / "portable report.restored.txt"
    source.write_bytes((b"portable Clever PGP file\n" * 100_000) + b"end")
    service = FileCryptoService()

    service.encrypt_file_with_password(
        source,
        encrypted,
        "Friendly@2026",
    )
    service.decrypt_file_with_password(
        encrypted,
        restored,
        "Friendly@2026",
    )

    assert restored.read_bytes() == source.read_bytes()


def test_password_file_rejects_wrong_password_and_tampering(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    encrypted = tmp_path / "source.bin.cpgp"
    source.write_bytes(b"authenticated payload" * 10_000)
    service = FileCryptoService()
    service.encrypt_file_with_password(source, encrypted, "Friendly@2026")

    with pytest.raises(Exception, match="Неверный пароль"):
        service.decrypt_file_with_password(
            encrypted,
            tmp_path / "wrong.bin",
            "Incorrect@2026",
        )

    payload = bytearray(encrypted.read_bytes())
    payload[-1] ^= 1
    encrypted.write_bytes(payload)
    with pytest.raises(Exception, match="целостност"):
        service.decrypt_file_with_password(
            encrypted,
            tmp_path / "tampered.bin",
            "Friendly@2026",
        )
