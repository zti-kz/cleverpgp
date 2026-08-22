from __future__ import annotations

import base64
import binascii
import json
import os
import struct
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from nacl import bindings, exceptions, secret

from biopgp.core.errors import (
    InvalidEncryptedFileError,
    OutputExistsError,
    ValidationError,
)

MAGIC = b"CPGPFILE"
FORMAT_VERSION = 1
PREFIX = struct.Struct(">8sBI")
RECORD_LENGTH = struct.Struct(">I")
CHUNK_SIZE = 1024 * 1024
MAX_HEADER_SIZE = 64 * 1024
ALGORITHM = "XCHACHA20-POLY1305-SECRETSTREAM"
KEY_WRAP = "XSALSA20-POLY1305-SECRETBOX"

ProgressCallback = Callable[[int, str], None]


class FileCryptoService:
    """Versioned, streaming `.cpgp` encryption backed by libsodium."""

    def encrypt_file(
        self,
        source_path: Path,
        target_path: Path,
        master_key: bytes,
        *,
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
    ) -> Path:
        self._report_progress(progress, 2, "Проверка исходного файла")
        source, target = self._validate_paths(source_path, target_path, overwrite)
        self._validate_master_key(master_key)

        file_key = bindings.crypto_secretstream_xchacha20poly1305_keygen()
        state = bindings.crypto_secretstream_xchacha20poly1305_state()
        stream_header = bindings.crypto_secretstream_xchacha20poly1305_init_push(
            state, file_key
        )
        wrapped_file_key = bytes(secret.SecretBox(master_key).encrypt(file_key))
        header = self._encode_header(stream_header, wrapped_file_key)
        prefix = PREFIX.pack(MAGIC, FORMAT_VERSION, len(header))
        associated_data = prefix + header
        source_size = source.stat().st_size

        temporary_path: Path | None = None
        try:
            self._report_progress(progress, 5, "Подготовка шифрования")
            temporary_path, target_stream = self._temporary_output(target)
            with source.open("rb") as source_stream, target_stream:
                target_stream.write(associated_data)
                self._encrypt_records(
                    source_stream,
                    target_stream,
                    state,
                    associated_data,
                    source_size=source_size,
                    progress=progress,
                )
                self._report_progress(progress, 97, "Сохранение результата")
                target_stream.flush()
                os.fsync(target_stream.fileno())
            os.replace(temporary_path, target)
            temporary_path = None
            self._report_progress(progress, 100, "Шифрование завершено")
            return target
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            del file_key
            del master_key

    def decrypt_file(
        self,
        source_path: Path,
        target_path: Path,
        master_key: bytes,
        *,
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
    ) -> Path:
        self._report_progress(progress, 2, "Проверка зашифрованного файла")
        source, target = self._validate_paths(source_path, target_path, overwrite)
        self._validate_master_key(master_key)

        temporary_path: Path | None = None
        try:
            encrypted_size = source.stat().st_size
            with source.open("rb") as source_stream:
                associated_data, stream_header, wrapped_key = self._read_header(
                    source_stream
                )
                try:
                    file_key = secret.SecretBox(master_key).decrypt(wrapped_key)
                except exceptions.CryptoError as error:
                    raise InvalidEncryptedFileError(
                        "Файл повреждён или зашифрован другим профилем."
                    ) from error

                state = bindings.crypto_secretstream_xchacha20poly1305_state()
                try:
                    bindings.crypto_secretstream_xchacha20poly1305_init_pull(
                        state, stream_header, file_key
                    )
                except (ValueError, RuntimeError) as error:
                    raise InvalidEncryptedFileError(
                        "Некорректный криптографический заголовок файла."
                    ) from error

                temporary_path, target_stream = self._temporary_output(target)
                self._report_progress(progress, 5, "Проверка ключа файла")
                with target_stream:
                    self._decrypt_records(
                        source_stream,
                        target_stream,
                        state,
                        associated_data,
                        encrypted_size=encrypted_size,
                        progress=progress,
                    )
                    self._report_progress(progress, 97, "Сохранение результата")
                    target_stream.flush()
                    os.fsync(target_stream.fileno())

            os.replace(temporary_path, target)
            temporary_path = None
            self._report_progress(progress, 100, "Расшифрование завершено")
            return target
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            del master_key

    @staticmethod
    def default_encrypted_path(source_path: Path) -> Path:
        source = Path(source_path)
        return source.with_name(source.name + ".cpgp")

    @staticmethod
    def default_decrypted_path(source_path: Path) -> Path:
        source = Path(source_path)
        if source.suffix.lower() == ".cpgp":
            candidate = source.with_suffix("")
        else:
            candidate = source.with_name(source.name + ".decrypted")
        if not candidate.exists():
            return candidate
        return candidate.with_name(candidate.stem + ".decrypted" + candidate.suffix)

    @staticmethod
    def _validate_paths(
        source_path: Path, target_path: Path, overwrite: bool
    ) -> tuple[Path, Path]:
        source = Path(source_path).expanduser().resolve()
        target = Path(target_path).expanduser().resolve()
        if not source.is_file():
            raise ValidationError("Исходный файл не найден.")
        if source == target:
            raise ValidationError("Исходный и целевой путь должны отличаться.")
        if target.exists() and not overwrite:
            raise OutputExistsError("Целевой файл уже существует.")
        target.parent.mkdir(parents=True, exist_ok=True)
        return source, target

    @staticmethod
    def _validate_master_key(master_key: bytes) -> None:
        if len(master_key) != secret.SecretBox.KEY_SIZE:
            raise ValidationError("Некорректный мастер-ключ текущего сеанса.")

    @staticmethod
    def _encode_header(stream_header: bytes, wrapped_file_key: bytes) -> bytes:
        payload = {
            "algorithm": ALGORITHM,
            "chunk_size": CHUNK_SIZE,
            "key_wrap": KEY_WRAP,
            "stream_header": base64.b64encode(stream_header).decode("ascii"),
            "wrapped_file_key": base64.b64encode(wrapped_file_key).decode("ascii"),
        }
        return json.dumps(
            payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")

    def _read_header(self, source_stream: BinaryIO) -> tuple[bytes, bytes, bytes]:
        raw_prefix = self._read_exact(source_stream, PREFIX.size)
        try:
            magic, version, header_size = PREFIX.unpack(raw_prefix)
        except struct.error as error:
            raise InvalidEncryptedFileError("Повреждён заголовок файла.") from error

        if magic != MAGIC:
            raise InvalidEncryptedFileError("Это не файл Clever PGP.")
        if version != FORMAT_VERSION:
            raise InvalidEncryptedFileError(
                f"Версия формата {version} пока не поддерживается."
            )
        if not 2 <= header_size <= MAX_HEADER_SIZE:
            raise InvalidEncryptedFileError("Недопустимый размер заголовка.")

        raw_header = self._read_exact(source_stream, header_size)
        try:
            payload = json.loads(raw_header.decode("ascii"))
            if not isinstance(payload, dict):
                raise TypeError
            if payload.get("algorithm") != ALGORITHM:
                raise ValueError("algorithm")
            if payload.get("key_wrap") != KEY_WRAP:
                raise ValueError("key_wrap")
            if payload.get("chunk_size") != CHUNK_SIZE:
                raise ValueError("chunk_size")
            stream_header = base64.b64decode(
                payload["stream_header"], validate=True
            )
            wrapped_key = base64.b64decode(
                payload["wrapped_file_key"], validate=True
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
            binascii.Error,
        ) as error:
            raise InvalidEncryptedFileError("Некорректный заголовок Clever PGP.") from error

        if len(stream_header) != bindings.crypto_secretstream_xchacha20poly1305_HEADERBYTES:
            raise InvalidEncryptedFileError("Некорректный заголовок secretstream.")
        minimum_wrapped_key_size = secret.SecretBox.NONCE_SIZE + secret.SecretBox.MACBYTES
        if len(wrapped_key) != minimum_wrapped_key_size + secret.SecretBox.KEY_SIZE:
            raise InvalidEncryptedFileError("Некорректная обёртка ключа файла.")
        return raw_prefix + raw_header, stream_header, wrapped_key

    @staticmethod
    def _encrypt_records(
        source_stream: BinaryIO,
        target_stream: BinaryIO,
        state: bindings.crypto_secretstream_xchacha20poly1305_state,
        associated_data: bytes,
        *,
        source_size: int,
        progress: ProgressCallback | None,
    ) -> None:
        chunk = source_stream.read(CHUNK_SIZE)
        if not chunk:
            FileCryptoService._write_encrypted_record(
                target_stream,
                bindings.crypto_secretstream_xchacha20poly1305_push(
                    state,
                    b"",
                    associated_data,
                    bindings.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
                ),
            )
            FileCryptoService._report_progress(progress, 95, "Шифрование данных")
            return

        processed = 0
        while True:
            next_chunk = source_stream.read(CHUNK_SIZE)
            is_final = not next_chunk
            tag = (
                bindings.crypto_secretstream_xchacha20poly1305_TAG_FINAL
                if is_final
                else bindings.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
            )
            encrypted = bindings.crypto_secretstream_xchacha20poly1305_push(
                state, chunk, associated_data, tag
            )
            FileCryptoService._write_encrypted_record(target_stream, encrypted)
            processed += len(chunk)
            fraction = processed / max(1, source_size)
            FileCryptoService._report_progress(
                progress,
                5 + round(90 * min(1.0, fraction)),
                "Шифрование данных",
            )
            if is_final:
                return
            chunk = next_chunk

    @staticmethod
    def _write_encrypted_record(target_stream: BinaryIO, encrypted: bytes) -> None:
        target_stream.write(RECORD_LENGTH.pack(len(encrypted)))
        target_stream.write(encrypted)

    def _decrypt_records(
        self,
        source_stream: BinaryIO,
        target_stream: BinaryIO,
        state: bindings.crypto_secretstream_xchacha20poly1305_state,
        associated_data: bytes,
        *,
        encrypted_size: int,
        progress: ProgressCallback | None,
    ) -> None:
        maximum_record_size = (
            CHUNK_SIZE + bindings.crypto_secretstream_xchacha20poly1305_ABYTES
        )
        while True:
            raw_length = source_stream.read(RECORD_LENGTH.size)
            if not raw_length:
                raise InvalidEncryptedFileError("В файле отсутствует завершающий блок.")
            if len(raw_length) != RECORD_LENGTH.size:
                raise InvalidEncryptedFileError("Оборвана длина блока шифротекста.")
            (record_size,) = RECORD_LENGTH.unpack(raw_length)
            if not (
                bindings.crypto_secretstream_xchacha20poly1305_ABYTES
                <= record_size
                <= maximum_record_size
            ):
                raise InvalidEncryptedFileError("Недопустимый размер блока шифротекста.")
            encrypted = self._read_exact(source_stream, record_size)
            try:
                plaintext, tag = bindings.crypto_secretstream_xchacha20poly1305_pull(
                    state, encrypted, associated_data
                )
            except (exceptions.CryptoError, ValueError, RuntimeError) as error:
                raise InvalidEncryptedFileError(
                    "Нарушена целостность зашифрованного файла."
                ) from error

            if tag not in (
                bindings.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
                bindings.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
            ):
                raise InvalidEncryptedFileError("Недопустимый тег блока.")
            target_stream.write(plaintext)
            fraction = source_stream.tell() / max(1, encrypted_size)
            self._report_progress(
                progress,
                5 + round(90 * min(1.0, fraction)),
                "Расшифрование данных",
            )

            if tag == bindings.crypto_secretstream_xchacha20poly1305_TAG_FINAL:
                if source_stream.read(1):
                    raise InvalidEncryptedFileError(
                        "После завершающего блока обнаружены лишние данные."
                    )
                return

    @staticmethod
    def _report_progress(
        progress: ProgressCallback | None, value: int, message: str
    ) -> None:
        if progress is not None:
            progress(max(0, min(100, int(value))), message)

    @staticmethod
    def _read_exact(source_stream: BinaryIO, size: int) -> bytes:
        data = source_stream.read(size)
        if len(data) != size:
            raise InvalidEncryptedFileError("Зашифрованный файл оборван.")
        return data

    @staticmethod
    def _temporary_output(target: Path) -> tuple[Path, BinaryIO]:
        temporary = tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        )
        return Path(temporary.name), temporary
