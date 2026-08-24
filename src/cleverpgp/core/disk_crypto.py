from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from nacl import bindings, exceptions, hash, secret, utils
from nacl.encoding import RawEncoder

from cleverpgp.core.errors import ValidationError

XCHACHA20_POLY1305 = "XCHACHA20-POLY1305-BLOCK-V1"
AES256_GCM = "AES-256-GCM-BLOCK-V1"
DEFAULT_DISK_ALGORITHM = XCHACHA20_POLY1305

# A fixed 24-byte field keeps the physical block layout stable for every
# supported method. AES-GCM uses the first 12 bytes as its nonce and
# authenticates the remaining 12 bytes together with the block address.
DISK_NONCE_FIELD_SIZE = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
DISK_TAG_SIZE = bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES
_AES_NONCE_SIZE = bindings.crypto_aead_aes256gcm_NPUBBYTES
_AES_PADDING_DOMAIN = b"CPGP-AES-GCM-NONCE-PADDING-V1"
_AES_SUBKEY_DOMAIN = b"CPGP-AES-GCM-BLOCK-SUBKEY-V1"


@dataclass(frozen=True, slots=True)
class DiskCipherSpec:
    identifier: str
    name: str
    portable: bool

    def encrypt(
        self,
        plaintext: bytes,
        aad: bytes,
        nonce_field: bytes,
        key: bytes,
    ) -> bytes:
        _validate_material(nonce_field, key)
        if self.identifier == XCHACHA20_POLY1305:
            return bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext,
                aad,
                nonce_field,
                key,
            )
        if self.identifier == AES256_GCM:
            block_key = _aes_block_key(key, aad)
            try:
                return bindings.crypto_aead_aes256gcm_encrypt(
                    plaintext,
                    _aes_aad(aad, nonce_field),
                    nonce_field[:_AES_NONCE_SIZE],
                    block_key,
                )
            finally:
                del block_key
        raise ValidationError("Неподдерживаемый метод защиты диска.")

    def decrypt(
        self,
        ciphertext: bytes,
        aad: bytes,
        nonce_field: bytes,
        key: bytes,
    ) -> bytes:
        _validate_material(nonce_field, key)
        if self.identifier == XCHACHA20_POLY1305:
            return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext,
                aad,
                nonce_field,
                key,
            )
        if self.identifier == AES256_GCM:
            block_key = _aes_block_key(key, aad)
            try:
                return bindings.crypto_aead_aes256gcm_decrypt(
                    ciphertext,
                    _aes_aad(aad, nonce_field),
                    nonce_field[:_AES_NONCE_SIZE],
                    block_key,
                )
            finally:
                del block_key
        raise ValidationError("Неподдерживаемый метод защиты диска.")


_CIPHERS = {
    XCHACHA20_POLY1305: DiskCipherSpec(
        XCHACHA20_POLY1305,
        "XChaCha20-Poly1305",
        True,
    ),
    AES256_GCM: DiskCipherSpec(
        AES256_GCM,
        "AES-256-GCM",
        False,
    ),
}


def get_disk_cipher(identifier: str) -> DiskCipherSpec:
    try:
        return _CIPHERS[identifier]
    except KeyError as error:
        raise ValidationError("Неподдерживаемый метод защиты диска.") from error


def available_disk_ciphers() -> tuple[DiskCipherSpec, ...]:
    return tuple(
        cipher for cipher in _CIPHERS.values() if disk_cipher_available(cipher.identifier)
    )


@lru_cache(maxsize=None)
def disk_cipher_available(identifier: str) -> bool:
    cipher = get_disk_cipher(identifier)
    if cipher.identifier == XCHACHA20_POLY1305:
        return True
    try:
        key = bytes(secret.SecretBox.KEY_SIZE)
        nonce_field = bytes(DISK_NONCE_FIELD_SIZE)
        aad = b"Clever PGP algorithm availability test"
        encrypted = cipher.encrypt(b"test", aad, nonce_field, key)
        return cipher.decrypt(encrypted, aad, nonce_field, key) == b"test"
    except (RuntimeError, ValueError, exceptions.CryptoError):
        return False


def require_disk_cipher(identifier: str) -> DiskCipherSpec:
    cipher = get_disk_cipher(identifier)
    if not disk_cipher_available(identifier):
        raise ValidationError(
            f"Метод {cipher.name} недоступен на этом компьютере."
        )
    return cipher


def random_nonce_fields(block_count: int) -> bytes:
    if not isinstance(block_count, int) or block_count <= 0:
        raise ValidationError("Некорректное число блоков диска.")
    return utils.random(block_count * DISK_NONCE_FIELD_SIZE)


def _aes_aad(aad: bytes, nonce_field: bytes) -> bytes:
    return aad + _AES_PADDING_DOMAIN + nonce_field[_AES_NONCE_SIZE:]


def _aes_block_key(volume_key: bytes, aad: bytes) -> bytes:
    # Per-block subkeys confine the 96-bit GCM nonce space to rewrites of one
    # logical address instead of sharing it across the entire long-lived disk.
    return hash.blake2b(
        _AES_SUBKEY_DOMAIN + aad,
        key=volume_key,
        digest_size=bindings.crypto_aead_aes256gcm_KEYBYTES,
        encoder=RawEncoder,
    )


def _validate_material(nonce_field: bytes, key: bytes) -> None:
    if len(nonce_field) != DISK_NONCE_FIELD_SIZE:
        raise ValidationError("Некорректный одноразовый параметр блока.")
    if len(key) != secret.SecretBox.KEY_SIZE:
        raise ValidationError("Некорректный ключ зашифрованного диска.")


__all__ = [
    "AES256_GCM",
    "DEFAULT_DISK_ALGORITHM",
    "DISK_NONCE_FIELD_SIZE",
    "DISK_TAG_SIZE",
    "DiskCipherSpec",
    "XCHACHA20_POLY1305",
    "available_disk_ciphers",
    "disk_cipher_available",
    "get_disk_cipher",
    "random_nonce_fields",
    "require_disk_cipher",
]
