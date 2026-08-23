from __future__ import annotations

import pytest
from nacl import exceptions, secret, utils

from biopgp.core.disk_crypto import (
    AES256_GCM,
    DISK_NONCE_FIELD_SIZE,
    XCHACHA20_POLY1305,
    available_disk_ciphers,
    get_disk_cipher,
)


@pytest.mark.parametrize(
    "identifier",
    [cipher.identifier for cipher in available_disk_ciphers()],
)
def test_available_disk_cipher_round_trip_and_authenticates_context(
    identifier: str,
) -> None:
    cipher = get_disk_cipher(identifier)
    key = utils.random(secret.SecretBox.KEY_SIZE)
    nonce = utils.random(DISK_NONCE_FIELD_SIZE)
    encrypted = cipher.encrypt(b"payload", b"block 7", nonce, key)

    assert cipher.decrypt(encrypted, b"block 7", nonce, key) == b"payload"
    with pytest.raises(exceptions.CryptoError):
        cipher.decrypt(encrypted, b"block 8", nonce, key)


def test_aes_authenticates_unused_nonce_field_bytes_when_available() -> None:
    available = {cipher.identifier for cipher in available_disk_ciphers()}
    if AES256_GCM not in available:
        pytest.skip("AES-256-GCM is not available on this processor")
    cipher = get_disk_cipher(AES256_GCM)
    key = utils.random(secret.SecretBox.KEY_SIZE)
    nonce = bytearray(utils.random(DISK_NONCE_FIELD_SIZE))
    encrypted = cipher.encrypt(b"payload", b"block", bytes(nonce), key)
    nonce[-1] ^= 1

    with pytest.raises(exceptions.CryptoError):
        cipher.decrypt(encrypted, b"block", bytes(nonce), key)


def test_portable_method_is_always_first() -> None:
    identifiers = [cipher.identifier for cipher in available_disk_ciphers()]

    assert identifiers[0] == XCHACHA20_POLY1305
