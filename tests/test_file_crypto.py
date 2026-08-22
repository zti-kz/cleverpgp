from pathlib import Path

import pytest
from nacl import secret, utils

from biopgp.core.errors import InvalidEncryptedFileError, OutputExistsError
from biopgp.core.file_crypto import FileCryptoService


@pytest.fixture
def service() -> FileCryptoService:
    return FileCryptoService()


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"BioPGP test data", id="short"),
        pytest.param(utils.random(2 * 1024 * 1024 + 137), id="multi-chunk"),
    ],
)
def test_file_round_trip(
    tmp_path: Path, service: FileCryptoService, payload: bytes
) -> None:
    master_key = utils.random(secret.SecretBox.KEY_SIZE)
    source = tmp_path / "document.bin"
    encrypted = tmp_path / "document.bin.cpgp"
    decrypted = tmp_path / "document.restored.bin"
    source.write_bytes(payload)

    service.encrypt_file(source, encrypted, master_key)
    service.decrypt_file(encrypted, decrypted, master_key)

    assert decrypted.read_bytes() == payload
    assert encrypted.read_bytes() != payload


def test_tampering_is_detected_without_output(
    tmp_path: Path, service: FileCryptoService
) -> None:
    master_key = utils.random(secret.SecretBox.KEY_SIZE)
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
    tmp_path: Path, service: FileCryptoService
) -> None:
    source = tmp_path / "source.txt"
    encrypted = tmp_path / "source.txt.cpgp"
    decrypted = tmp_path / "should-not-exist.txt"
    source.write_text("secret", encoding="utf-8")
    service.encrypt_file(
        source, encrypted, utils.random(secret.SecretBox.KEY_SIZE)
    )

    with pytest.raises(InvalidEncryptedFileError):
        service.decrypt_file(
            encrypted, decrypted, utils.random(secret.SecretBox.KEY_SIZE)
        )

    assert not decrypted.exists()


def test_trailing_data_is_rejected(
    tmp_path: Path, service: FileCryptoService
) -> None:
    master_key = utils.random(secret.SecretBox.KEY_SIZE)
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
    tmp_path: Path, service: FileCryptoService
) -> None:
    source = tmp_path / "source.txt"
    target = tmp_path / "target.cpgp"
    source.write_text("source", encoding="utf-8")
    target.write_text("keep me", encoding="utf-8")

    with pytest.raises(OutputExistsError):
        service.encrypt_file(
            source, target, utils.random(secret.SecretBox.KEY_SIZE)
        )

    assert target.read_text(encoding="utf-8") == "keep me"


def test_new_extension_and_signature_are_used(
    tmp_path: Path, service: FileCryptoService
) -> None:
    source = tmp_path / "report.txt"
    source.write_text("Clever PGP", encoding="utf-8")
    target = service.default_encrypted_path(source)

    service.encrypt_file(source, target, utils.random(secret.SecretBox.KEY_SIZE))

    assert target.name == "report.txt.cpgp"
    assert target.read_bytes().startswith(b"CPGPFILE")


def test_old_file_signature_is_rejected(
    tmp_path: Path, service: FileCryptoService
) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    source = tmp_path / "report.txt"
    encrypted = tmp_path / "report.txt.cpgp"
    source.write_text("Clever PGP", encoding="utf-8")
    service.encrypt_file(source, encrypted, key)
    raw = bytearray(encrypted.read_bytes())
    raw[:8] = b"BPGPFILE"
    encrypted.write_bytes(raw)

    with pytest.raises(InvalidEncryptedFileError):
        service.decrypt_file(encrypted, tmp_path / "restored.txt", key)
