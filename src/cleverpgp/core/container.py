from __future__ import annotations

import base64
import binascii
import ctypes
import json
import os
import shutil
import sqlite3
import struct
import tempfile
import threading
import unicodedata
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TypeVar

from nacl import bindings, exceptions, secret, utils

from cleverpgp.core.errors import (
    ContainerDirectoryNotEmptyError,
    ContainerEntryExistsError,
    ContainerEntryNotFoundError,
    ContainerFullError,
    ContainerIsDirectoryError,
    ContainerNotDirectoryError,
    InvalidContainerError,
    OutputExistsError,
    ValidationError,
)

MAGIC = b"CPGPVAULT"
FORMAT_VERSION = 2
PREFIX = struct.Struct(">9sBI")
HEADER_AREA_SIZE = 4096
DATABASE_LENGTH = struct.Struct(">Q")
PAYLOAD_LENGTH = struct.Struct(">Q")
MIN_DATA_CAPACITY = 1024 * 1024
DATABASE_RESERVE = 1024 * 1024
MAX_FORMAT_FILE_SIZE = (1 << 63) - 1
ALGORITHM = "XCHACHA20-POLY1305-IETF"
KEY_WRAP = "XSALSA20-POLY1305-SECRETBOX"
CONTAINER_SUFFIX = ".cpgv"
STORAGE_FORMAT = "COMPACT-AEAD-V2"

ProgressCallback = Callable[[int, str], None]

_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class VaultNode:
    node_id: int
    parent_id: int | None
    name: str
    is_directory: bool
    size: int
    created_ns: int
    modified_ns: int


class EncryptedContainer:
    """An authenticated container whose plaintext exists only in RAM.

    Version 2 stores only the encrypted bytes that are currently in use. The
    selected disk capacity remains a hard limit exposed to the mounted file
    system, but creating an empty multi-gigabyte disk no longer requires Windows
    to size the backing file to that full capacity.
    """

    def __init__(
        self,
        path: Path,
        container_key: bytes,
        raw_header: bytes,
        metadata: dict[str, object],
        connection: sqlite3.Connection,
    ) -> None:
        self.path = Path(path)
        self._container_key = bytearray(container_key)
        self._raw_header = raw_header
        self._metadata = metadata
        self._connection = connection
        self._lock = threading.RLock()
        self._closed = False

    @classmethod
    def create(
        cls,
        path: Path,
        master_key: bytes,
        *,
        data_capacity: int = 20 * 1024 * 1024,
        label: str = "Clever PGP",
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
    ) -> EncryptedContainer:
        cls._report_progress(progress, 5, "Проверка параметров диска")
        target = Path(path).expanduser().resolve()
        cls._validate_master_key(master_key)
        cls._validate_capacity(data_capacity)
        label = label.strip() or "Clever PGP"
        if len(label) > 31:
            raise ValidationError("Название диска должно быть не длиннее 31 символа.")
        if target.exists() and not overwrite:
            raise OutputExistsError(f"Контейнер уже существует: {target}")
        if not target.parent.is_dir():
            raise ValidationError("Папка для контейнера не существует.")
        if data_capacity > cls.available_data_capacity(target):
            raise ValidationError(
                "Недостаточно свободного места на выбранном накопителе."
            )

        cls._report_progress(progress, 20, "Создание ключа контейнера")
        container_key = utils.random(secret.SecretBox.KEY_SIZE)
        wrapped_key = bytes(secret.SecretBox(master_key).encrypt(container_key))
        metadata: dict[str, object] = {
            "algorithm": ALGORITHM,
            "key_wrap": KEY_WRAP,
            "container_id": str(uuid.uuid4()),
            "created_at": datetime.now(UTC).isoformat(),
            "label": label,
            "data_capacity": data_capacity,
            "payload_capacity": data_capacity + DATABASE_RESERVE,
            "storage_format": STORAGE_FORMAT,
            "wrapped_container_key": base64.b64encode(wrapped_key).decode("ascii"),
        }
        cls._report_progress(progress, 35, "Формирование защищённого заголовка")
        raw_header = cls._encode_header(metadata)
        connection = cls._new_database(label)
        container = cls(
            target, container_key, raw_header, metadata, connection
        )
        try:
            container.save(progress=progress, progress_start=45, progress_end=100)
        except Exception:
            container.close(save=False)
            raise
        return container

    @classmethod
    def required_storage_size(cls, data_capacity: int) -> int:
        """Return the logical container file size for a requested disk capacity."""

        cls._validate_capacity(data_capacity)
        return cls._container_file_size(data_capacity + DATABASE_RESERVE)

    @classmethod
    def storage_space(cls, path: Path) -> tuple[int, int]:
        """Return free bytes and maximum usable data capacity at ``path``.

        The result is tied to the file system containing the selected container
        directory. It intentionally uses the container's complete logical size,
        even when that file system supports sparse files.
        """

        target = Path(path).expanduser().resolve()
        directory = target if target.is_dir() else target.parent
        if not directory.is_dir():
            raise ValidationError("Папка для контейнера не существует.")
        try:
            free_bytes = int(shutil.disk_usage(directory).free)
        except OSError as error:
            raise ValidationError(
                "Не удалось определить свободное место на выбранном накопителе."
            ) from error

        fixed_overhead = cls._container_file_size(DATABASE_RESERVE)
        format_maximum = (
            MAX_FORMAT_FILE_SIZE - DATABASE_RESERVE - HEADER_AREA_SIZE - 128
        )
        maximum_capacity = max(0, min(format_maximum, free_bytes - fixed_overhead))
        return free_bytes, maximum_capacity

    @classmethod
    def available_data_capacity(cls, path: Path) -> int:
        return cls.storage_space(path)[1]

    @classmethod
    def open(cls, path: Path, master_key: bytes) -> EncryptedContainer:
        source = Path(path).expanduser().resolve()
        cls._validate_master_key(master_key)
        if not source.is_file():
            raise InvalidContainerError("Файл контейнера не найден.")

        try:
            with source.open("rb") as stream:
                raw_prefix = cls._read_exact(stream, PREFIX.size)
                magic, version, header_size = PREFIX.unpack(raw_prefix)
                if magic != MAGIC:
                    raise InvalidContainerError("Это не контейнер Clever PGP.")
                if version != FORMAT_VERSION:
                    raise InvalidContainerError(
                        f"Версия контейнера {version} пока не поддерживается."
                    )
                if header_size != HEADER_AREA_SIZE:
                    raise InvalidContainerError("Некорректный размер заголовка.")
                header_area = cls._read_exact(stream, header_size)
                raw_header = raw_prefix + header_area
                metadata = cls._decode_header(header_area)
                payload_capacity = cls._payload_capacity(metadata)
                cls._storage_format(metadata)
                wrapped_key = base64.b64decode(
                    str(metadata["wrapped_container_key"]), validate=True
                )
                container_key = secret.SecretBox(master_key).decrypt(wrapped_key)

                length_nonce = cls._read_exact(
                    stream,
                    bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                )
                encrypted_length = cls._read_exact(
                    stream,
                    PAYLOAD_LENGTH.size
                    + bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES,
                )
                encoded_length = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                    encrypted_length,
                    raw_header,
                    length_nonce,
                    container_key,
                )
                (ciphertext_size,) = PAYLOAD_LENGTH.unpack(encoded_length)
                minimum_ciphertext_size = (
                    DATABASE_LENGTH.size
                    + 1
                    + bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES
                )
                maximum_ciphertext_size = (
                    payload_capacity
                    + bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES
                )
                if not minimum_ciphertext_size <= ciphertext_size <= maximum_ciphertext_size:
                    raise InvalidContainerError("Некорректный размер данных контейнера.")
                payload_nonce = cls._read_exact(
                    stream,
                    bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                )
                ciphertext = cls._read_exact(stream, ciphertext_size)
                if stream.read(1):
                    raise InvalidContainerError(
                        "После данных контейнера обнаружены лишние байты."
                    )
                associated_data = raw_header + length_nonce + encrypted_length
        except (
            OSError,
            struct.error,
            KeyError,
            ValueError,
            binascii.Error,
            exceptions.CryptoError,
        ) as error:
            if isinstance(error, InvalidContainerError):
                raise
            raise InvalidContainerError(
                "Контейнер повреждён или создан другим профилем."
            ) from error

        try:
            payload = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext, associated_data, payload_nonce, container_key
            )
        except (
            KeyError,
            ValueError,
            binascii.Error,
            exceptions.CryptoError,
        ) as error:
            raise InvalidContainerError(
                "Контейнер повреждён или создан другим профилем."
            ) from error

        try:
            if len(payload) < DATABASE_LENGTH.size + 1:
                raise ValueError("payload length")
            (database_size,) = DATABASE_LENGTH.unpack(
                payload[: DATABASE_LENGTH.size]
            )
            maximum_database_size = payload_capacity - DATABASE_LENGTH.size
            if not 1 <= database_size <= maximum_database_size:
                raise ValueError("database length")
            if len(payload) != DATABASE_LENGTH.size + database_size:
                raise ValueError("compact payload length")
            database = payload[
                DATABASE_LENGTH.size : DATABASE_LENGTH.size + database_size
            ]
            connection = cls._empty_connection()
            connection.deserialize(database)
            cls._validate_database(connection)
        except (sqlite3.Error, struct.error, ValueError) as error:
            raise InvalidContainerError("Повреждена файловая система контейнера.") from error

        return cls(source, container_key, raw_header, metadata, connection)

    @property
    def label(self) -> str:
        return str(self._metadata["label"])

    @property
    def data_capacity(self) -> int:
        return int(self._metadata["data_capacity"])

    @property
    def used_space(self) -> int:
        with self._lock:
            self._ensure_open()
            row = self._connection.execute(
                "SELECT COALESCE(SUM(length(content)), 0) FROM nodes WHERE is_directory = 0"
            ).fetchone()
            return int(row[0])

    @property
    def free_space(self) -> int:
        return self.data_capacity - self.used_space

    def node(self, path: str | PurePosixPath) -> VaultNode:
        with self._lock:
            row = self._resolve_row(path)
            return self._row_to_node(row)

    def list_directory(self, path: str | PurePosixPath = "/") -> list[VaultNode]:
        with self._lock:
            parent = self._resolve_row(path)
            if not bool(parent["is_directory"]):
                raise ContainerNotDirectoryError("Указанный путь не является папкой.")
            rows = self._connection.execute(
                """
                SELECT id, parent_id, name, is_directory, length(content) AS size,
                       created_ns, modified_ns
                FROM nodes WHERE parent_id = ? ORDER BY name_key, name
                """,
                (int(parent["id"]),),
            ).fetchall()
            return [self._row_to_node(row) for row in rows]

    def create_file(
        self, path: str | PurePosixPath, *, persist: bool = True
    ) -> VaultNode:
        return self._create_entry(path, is_directory=False, persist=persist)

    def create_directory(
        self, path: str | PurePosixPath, *, persist: bool = True
    ) -> VaultNode:
        return self._create_entry(path, is_directory=True, persist=persist)

    def read_file(
        self,
        path: str | PurePosixPath,
        *,
        offset: int = 0,
        length: int | None = None,
    ) -> bytes:
        if offset < 0 or length is not None and length < 0:
            raise ValidationError("Некорректный диапазон чтения.")
        with self._lock:
            row = self._resolve_row(path)
            if bool(row["is_directory"]):
                raise ContainerIsDirectoryError("Нельзя читать папку как файл.")
            content = bytes(row["content"])
            if length is None:
                return content[offset:]
            return content[offset : offset + length]

    def write_file(
        self,
        path: str | PurePosixPath,
        data: bytes,
        *,
        offset: int = 0,
        append: bool = False,
        constrained: bool = False,
        persist: bool = True,
    ) -> int:
        if offset < 0:
            raise ValidationError("Смещение записи не может быть отрицательным.")
        payload = bytes(data)

        def mutation() -> int:
            row = self._resolve_row(path)
            if bool(row["is_directory"]):
                raise ContainerIsDirectoryError("Нельзя записывать данные в папку.")
            current = bytes(row["content"])
            actual_offset = len(current) if append else offset
            if constrained:
                if actual_offset >= len(current):
                    return 0
                payload_part = payload[: len(current) - actual_offset]
                updated = (
                    current[:actual_offset]
                    + payload_part
                    + current[actual_offset + len(payload_part) :]
                )
                transferred = len(payload_part)
            else:
                gap = b"\x00" * max(0, actual_offset - len(current))
                tail_offset = actual_offset + len(payload)
                tail = current[tail_offset:] if tail_offset < len(current) else b""
                updated = current[:actual_offset] + gap + payload + tail
                transferred = len(payload)
            self._ensure_data_capacity(len(updated) - len(current))
            now = self._now_ns()
            self._connection.execute(
                "UPDATE nodes SET content = ?, modified_ns = ? WHERE id = ?",
                (updated, now, int(row["id"])),
            )
            return transferred

        return self._mutate(mutation, persist=persist)

    def truncate_file(
        self,
        path: str | PurePosixPath,
        size: int,
        *,
        persist: bool = True,
    ) -> None:
        if size < 0:
            raise ValidationError("Размер файла не может быть отрицательным.")

        def mutation() -> None:
            row = self._resolve_row(path)
            if bool(row["is_directory"]):
                raise ContainerIsDirectoryError("Нельзя изменить размер папки.")
            current = bytes(row["content"])
            self._ensure_data_capacity(size - len(current))
            updated = current[:size].ljust(size, b"\x00")
            self._connection.execute(
                "UPDATE nodes SET content = ?, modified_ns = ? WHERE id = ?",
                (updated, self._now_ns(), int(row["id"])),
            )

        self._mutate(mutation, persist=persist)

    def remove(
        self, path: str | PurePosixPath, *, persist: bool = True
    ) -> None:
        normalized = self._normalize_path(path)
        if normalized == PurePosixPath("/"):
            raise ValidationError("Корневую папку удалить нельзя.")

        def mutation() -> None:
            row = self._resolve_row(normalized)
            if bool(row["is_directory"]):
                child = self._connection.execute(
                    "SELECT 1 FROM nodes WHERE parent_id = ? LIMIT 1",
                    (int(row["id"]),),
                ).fetchone()
                if child is not None:
                    raise ContainerDirectoryNotEmptyError("Папка не пуста.")
            self._connection.execute("DELETE FROM nodes WHERE id = ?", (int(row["id"]),))

        self._mutate(mutation, persist=persist)

    def rename(
        self,
        source: str | PurePosixPath,
        target: str | PurePosixPath,
        *,
        replace: bool = False,
        persist: bool = True,
    ) -> None:
        source_path = self._normalize_path(source)
        target_path = self._normalize_path(target)
        if source_path == PurePosixPath("/") or target_path == PurePosixPath("/"):
            raise ValidationError("Корневую папку перемещать нельзя.")
        if source_path == target_path:
            return
        if source_path in target_path.parents:
            raise ValidationError("Нельзя переместить папку внутрь неё самой.")

        def mutation() -> None:
            source_row = self._resolve_row(source_path)
            target_parent, target_name = self._resolve_parent(target_path)
            existing = self._find_child(int(target_parent["id"]), target_name)
            if existing is not None:
                if int(existing["id"]) == int(source_row["id"]):
                    existing = None
                elif not replace:
                    raise ContainerEntryExistsError("Объект с таким именем уже существует.")
                elif bool(existing["is_directory"]) != bool(source_row["is_directory"]):
                    if bool(existing["is_directory"]):
                        raise ContainerIsDirectoryError("Целевой путь является папкой.")
                    raise ContainerNotDirectoryError("Целевой путь не является папкой.")
                elif bool(existing["is_directory"]):
                    child = self._connection.execute(
                        "SELECT 1 FROM nodes WHERE parent_id = ? LIMIT 1",
                        (int(existing["id"]),),
                    ).fetchone()
                    if child is not None:
                        raise ContainerDirectoryNotEmptyError("Целевая папка не пуста.")
                if existing is not None:
                    self._connection.execute(
                        "DELETE FROM nodes WHERE id = ?", (int(existing["id"]),)
                    )
            self._connection.execute(
                """
                UPDATE nodes SET parent_id = ?, name = ?, name_key = ?, modified_ns = ?
                WHERE id = ?
                """,
                (
                    int(target_parent["id"]),
                    target_name,
                    self._name_key(target_name),
                    self._now_ns(),
                    int(source_row["id"]),
                ),
            )

        self._mutate(mutation, persist=persist)

    def update_times(
        self,
        path: str | PurePosixPath,
        *,
        modified_ns: int | None = None,
        persist: bool = True,
    ) -> None:
        if modified_ns is None:
            modified_ns = self._now_ns()

        def mutation() -> None:
            row = self._resolve_row(path)
            self._connection.execute(
                "UPDATE nodes SET modified_ns = ? WHERE id = ?",
                (modified_ns, int(row["id"])),
            )

        self._mutate(mutation, persist=persist)

    def save(
        self,
        *,
        progress: ProgressCallback | None = None,
        progress_start: int = 0,
        progress_end: int = 100,
    ) -> None:
        with self._lock:
            self._ensure_open()
            report = lambda fraction, message: self._report_progress(
                progress,
                progress_start + round((progress_end - progress_start) * fraction),
                message,
            )
            report(0.05, "Подготовка файловой системы")
            database = self._connection.serialize()
            payload_capacity = self._payload_capacity(self._metadata)
            required = DATABASE_LENGTH.size + len(database)
            if required > payload_capacity:
                raise ContainerFullError("В контейнере недостаточно места для метаданных.")
            plaintext = DATABASE_LENGTH.pack(len(database)) + database
            self._storage_format(self._metadata)

            report(0.25, "Шифрование данных контейнера")
            length_nonce = utils.random(
                bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
            )
            payload_nonce = utils.random(
                bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
            )
            ciphertext_size = (
                len(plaintext) + bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES
            )
            encrypted_length = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                PAYLOAD_LENGTH.pack(ciphertext_size),
                self._raw_header,
                length_nonce,
                bytes(self._container_key),
            )
            associated_data = self._raw_header + length_nonce + encrypted_length
            ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext,
                associated_data,
                payload_nonce,
                bytes(self._container_key),
            )
            temporary_path: Path | None = None
            try:
                report(0.65, "Запись контейнера на накопитель")
                temporary_path, stream = self._temporary_output(self.path)
                with stream:
                    stream.write(self._raw_header)
                    stream.write(length_nonce)
                    stream.write(encrypted_length)
                    stream.write(payload_nonce)
                    stream.write(ciphertext)
                    stream.flush()
                    os.fsync(stream.fileno())
                report(0.9, "Завершение создания диска")
                os.replace(temporary_path, self.path)
                temporary_path = None
                report(1.0, "Готово")
            finally:
                if temporary_path is not None:
                    temporary_path.unlink(missing_ok=True)

    def close(self, *, save: bool = True) -> None:
        with self._lock:
            if self._closed:
                return
            if save:
                self.save()
            self._connection.close()
            for index in range(len(self._container_key)):
                self._container_key[index] = 0
            self._closed = True

    @staticmethod
    def _report_progress(
        progress: ProgressCallback | None, value: int, message: str
    ) -> None:
        if progress is not None:
            progress(max(0, min(100, int(value))), message)

    def __enter__(self) -> EncryptedContainer:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close(save=exc is None)

    def _create_entry(
        self,
        path: str | PurePosixPath,
        *,
        is_directory: bool,
        persist: bool,
    ) -> VaultNode:
        normalized = self._normalize_path(path)
        if normalized == PurePosixPath("/"):
            raise ContainerEntryExistsError("Корневая папка уже существует.")

        def mutation() -> int:
            parent, name = self._resolve_parent(normalized)
            if self._find_child(int(parent["id"]), name) is not None:
                raise ContainerEntryExistsError("Объект с таким именем уже существует.")
            now = self._now_ns()
            cursor = self._connection.execute(
                """
                INSERT INTO nodes(
                    parent_id, name, name_key, is_directory, content,
                    created_ns, modified_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(parent["id"]),
                    name,
                    self._name_key(name),
                    int(is_directory),
                    b"",
                    now,
                    now,
                ),
            )
            return int(cursor.lastrowid)

        node_id = self._mutate(mutation, persist=persist)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT id, parent_id, name, is_directory, length(content) AS size,
                       created_ns, modified_ns FROM nodes WHERE id = ?
                """,
                (node_id,),
            ).fetchone()
            if row is None:
                raise InvalidContainerError("Не удалось создать объект контейнера.")
            return self._row_to_node(row)

    def _mutate(self, operation: Callable[[], _T], *, persist: bool) -> _T:
        with self._lock:
            self._ensure_open()
            self._connection.execute("SAVEPOINT cleverpgp_mutation")
            try:
                result = operation()
                if persist:
                    self.save()
                self._connection.execute("RELEASE SAVEPOINT cleverpgp_mutation")
                return result
            except Exception:
                self._connection.execute("ROLLBACK TO SAVEPOINT cleverpgp_mutation")
                self._connection.execute("RELEASE SAVEPOINT cleverpgp_mutation")
                raise

    def _resolve_parent(self, path: PurePosixPath) -> tuple[sqlite3.Row, str]:
        name = path.name
        self._validate_name(name)
        parent = self._resolve_row(path.parent)
        if not bool(parent["is_directory"]):
            raise ContainerNotDirectoryError("Родительский путь не является папкой.")
        return parent, name

    def _resolve_row(self, path: str | PurePosixPath) -> sqlite3.Row:
        normalized = self._normalize_path(path)
        row = self._connection.execute(
            """
            SELECT id, parent_id, name, is_directory, content,
                   created_ns, modified_ns
            FROM nodes WHERE id = 1
            """
        ).fetchone()
        if row is None:
            raise InvalidContainerError("В контейнере отсутствует корневая папка.")
        if normalized == PurePosixPath("/"):
            return row
        for name in normalized.parts[1:]:
            row = self._find_child(int(row["id"]), name)
            if row is None:
                raise ContainerEntryNotFoundError(f"Объект не найден: {normalized}")
        return row

    def _find_child(self, parent_id: int, name: str) -> sqlite3.Row | None:
        return self._connection.execute(
            """
            SELECT id, parent_id, name, is_directory, content,
                   created_ns, modified_ns
            FROM nodes WHERE parent_id = ? AND name_key = ?
            """,
            (parent_id, self._name_key(name)),
        ).fetchone()

    def _ensure_data_capacity(self, growth: int) -> None:
        if growth > 0 and self.used_space + growth > self.data_capacity:
            raise ContainerFullError("В контейнере недостаточно свободного места.")

    def _ensure_open(self) -> None:
        if self._closed:
            raise InvalidContainerError("Контейнер уже закрыт.")

    @staticmethod
    def _new_database(label: str) -> sqlite3.Connection:
        connection = EncryptedContainer._empty_connection()
        connection.executescript(
            """
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE nodes (
                id INTEGER PRIMARY KEY,
                parent_id INTEGER REFERENCES nodes(id),
                name TEXT NOT NULL,
                name_key TEXT NOT NULL,
                is_directory INTEGER NOT NULL CHECK(is_directory IN (0, 1)),
                content BLOB NOT NULL,
                created_ns INTEGER NOT NULL,
                modified_ns INTEGER NOT NULL,
                UNIQUE(parent_id, name_key)
            );
            CREATE INDEX nodes_parent_index ON nodes(parent_id);
            """
        )
        now = EncryptedContainer._now_ns()
        connection.execute(
            "INSERT INTO settings(key, value) VALUES ('schema_version', '1')"
        )
        connection.execute(
            "INSERT INTO settings(key, value) VALUES ('label', ?)", (label,)
        )
        connection.execute(
            """
            INSERT INTO nodes(
                id, parent_id, name, name_key, is_directory, content,
                created_ns, modified_ns
            ) VALUES (1, NULL, '', '', 1, x'', ?, ?)
            """,
            (now, now),
        )
        connection.commit()
        return connection

    @staticmethod
    def _empty_connection() -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:", check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _validate_database(connection: sqlite3.Connection) -> None:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise InvalidContainerError("Нарушена целостность файловой системы.")
        version = connection.execute(
            "SELECT value FROM settings WHERE key = 'schema_version'"
        ).fetchone()
        root = connection.execute(
            "SELECT is_directory FROM nodes WHERE id = 1 AND parent_id IS NULL"
        ).fetchone()
        if version is None or version[0] != "1" or root is None or root[0] != 1:
            raise InvalidContainerError("Неизвестная файловая система контейнера.")

    @classmethod
    def _encode_header(cls, metadata: dict[str, object]) -> bytes:
        encoded = json.dumps(
            metadata, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        if len(encoded) > HEADER_AREA_SIZE:
            raise ValidationError("Заголовок контейнера слишком большой.")
        prefix = PREFIX.pack(MAGIC, FORMAT_VERSION, HEADER_AREA_SIZE)
        return prefix + encoded.ljust(HEADER_AREA_SIZE, b"\x00")

    @classmethod
    def _decode_header(cls, header_area: bytes) -> dict[str, object]:
        try:
            encoded = header_area.rstrip(b"\x00")
            metadata = json.loads(encoded.decode("ascii"))
            if not isinstance(metadata, dict):
                raise TypeError
            if metadata.get("algorithm") != ALGORITHM:
                raise ValueError("algorithm")
            if metadata.get("key_wrap") != KEY_WRAP:
                raise ValueError("key wrap")
            cls._validate_capacity(int(metadata["data_capacity"]))
            payload_capacity = int(metadata["payload_capacity"])
            if payload_capacity != int(metadata["data_capacity"]) + DATABASE_RESERVE:
                raise ValueError("payload capacity")
            cls._storage_format(metadata)
            if not 1 <= len(str(metadata["label"])) <= 31:
                raise ValueError("label")
            uuid.UUID(str(metadata["container_id"]))
            base64.b64decode(str(metadata["wrapped_container_key"]), validate=True)
            return metadata
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
            binascii.Error,
        ) as error:
            raise InvalidContainerError("Некорректный заголовок контейнера.") from error

    @staticmethod
    def _payload_capacity(metadata: dict[str, object]) -> int:
        try:
            return int(metadata["payload_capacity"])
        except (KeyError, TypeError, ValueError) as error:
            raise InvalidContainerError("Некорректный размер контейнера.") from error

    @staticmethod
    def _storage_format(metadata: dict[str, object]) -> str:
        storage_format = str(metadata.get("storage_format", ""))
        if storage_format != STORAGE_FORMAT:
            raise InvalidContainerError("Неизвестный формат хранения контейнера.")
        return storage_format

    @staticmethod
    def _container_file_size(payload_capacity: int) -> int:
        nonce_size = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
        mac_size = bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES
        base_size = PREFIX.size + HEADER_AREA_SIZE
        return (
            base_size
            + nonce_size
            + PAYLOAD_LENGTH.size
            + mac_size
            + nonce_size
            + payload_capacity
            + mac_size
        )

    @staticmethod
    def _normalize_path(path: str | PurePosixPath) -> PurePosixPath:
        raw = str(path).replace("\\", "/")
        if "\x00" in raw:
            raise ValidationError("Путь содержит недопустимый символ.")
        normalized = PurePosixPath("/" + raw.lstrip("/"))
        if any(part in (".", "..") for part in normalized.parts):
            raise ValidationError("Относительные компоненты пути запрещены.")
        return normalized

    @staticmethod
    def _validate_name(name: str) -> None:
        if not name or name in (".", "..") or "/" in name or "\\" in name:
            raise ValidationError("Некорректное имя объекта.")
        if "\x00" in name or len(name) > 255:
            raise ValidationError("Имя объекта содержит недопустимые символы.")

    @staticmethod
    def _name_key(name: str) -> str:
        EncryptedContainer._validate_name(name)
        return unicodedata.normalize("NFC", name).casefold()

    @staticmethod
    def _row_to_node(row: sqlite3.Row) -> VaultNode:
        size = int(row["size"]) if "size" in row.keys() else len(bytes(row["content"]))
        return VaultNode(
            node_id=int(row["id"]),
            parent_id=int(row["parent_id"]) if row["parent_id"] is not None else None,
            name=str(row["name"]),
            is_directory=bool(row["is_directory"]),
            size=size,
            created_ns=int(row["created_ns"]),
            modified_ns=int(row["modified_ns"]),
        )

    @staticmethod
    def _validate_master_key(master_key: bytes) -> None:
        if not isinstance(master_key, bytes) or len(master_key) != secret.SecretBox.KEY_SIZE:
            raise ValidationError("Некорректный мастер-ключ профиля.")

    @staticmethod
    def _validate_capacity(data_capacity: int) -> None:
        if not isinstance(data_capacity, int) or data_capacity < MIN_DATA_CAPACITY:
            raise ValidationError("Размер контейнера должен быть не меньше 1 МБ.")
        maximum_capacity = MAX_FORMAT_FILE_SIZE - DATABASE_RESERVE - HEADER_AREA_SIZE - 128
        if data_capacity > maximum_capacity:
            raise ValidationError("Указанный размер превышает возможности файловой системы.")

    @staticmethod
    def _read_exact(stream: object, size: int) -> bytes:
        data = stream.read(size)
        if len(data) != size:
            raise InvalidContainerError("Контейнер неожиданно оборван.")
        return data

    @staticmethod
    def _temporary_output(target: Path) -> tuple[Path, object]:
        temporary = tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
            delete=False,
        )
        return Path(temporary.name), temporary

    @staticmethod
    def _enable_sparse_file(stream: object) -> None:
        if os.name != "nt":
            return
        try:
            import msvcrt

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            bytes_returned = ctypes.c_ulong()
            success = kernel32.DeviceIoControl(
                ctypes.c_void_p(msvcrt.get_osfhandle(stream.fileno())),
                0x000900C4,  # FSCTL_SET_SPARSE
                None,
                0,
                None,
                0,
                ctypes.byref(bytes_returned),
                None,
            )
            if not success:
                raise ctypes.WinError(ctypes.get_last_error())
        except (AttributeError, OSError):
            # The format still works on file systems without sparse-file
            # support; only physical allocation can be larger there.
            return

    @staticmethod
    def _release_sparse_tail(stream: object, start: int, end: int) -> None:
        if os.name != "nt" or start >= end:
            return
        try:
            import msvcrt

            class FileZeroDataInformation(ctypes.Structure):
                _fields_ = [
                    ("file_offset", ctypes.c_longlong),
                    ("beyond_final_zero", ctypes.c_longlong),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            bytes_returned = ctypes.c_ulong()
            zero_range = FileZeroDataInformation(start, end)
            success = kernel32.DeviceIoControl(
                ctypes.c_void_p(msvcrt.get_osfhandle(stream.fileno())),
                0x000980C8,  # FSCTL_SET_ZERO_DATA
                ctypes.byref(zero_range),
                ctypes.sizeof(zero_range),
                None,
                0,
                ctypes.byref(bytes_returned),
                None,
            )
            if not success:
                raise ctypes.WinError(ctypes.get_last_error())
        except (AttributeError, OSError):
            return

    @staticmethod
    def _now_ns() -> int:
        return int(datetime.now(UTC).timestamp() * 1_000_000_000)
