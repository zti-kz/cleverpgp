from __future__ import annotations

import copy
import hashlib
import json
import math
import secrets
import struct
import threading
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import TypeVar

from nacl import secret

from biopgp.core.block_volume import (
    HEADER_AREA_SIZE,
    HEADER_PREFIX,
    LOGICAL_BLOCK_SIZE,
    PHYSICAL_SLOT_SIZE,
    BlockVolumeError,
    EncryptedBlockVolume,
)
from biopgp.core.disk_crypto import DEFAULT_DISK_ALGORITHM
from biopgp.core.container import (
    CONTAINER_SUFFIX,
    MAX_FORMAT_FILE_SIZE,
    MIN_DATA_CAPACITY,
    ProgressCallback,
    VaultNode,
)
from biopgp.core.errors import (
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

FILESYSTEM_MAGIC = b"CPGPFS3\0"
FILESYSTEM_VERSION = 1
BLOCK_VAULT_STORAGE_FORMAT = "CLEVERPGP-BLOCK-VAULT-V3"
METADATA_SLOT_BLOCKS = 256
METADATA_SLOT_COUNT = 2
METADATA_BLOCKS = METADATA_SLOT_BLOCKS * METADATA_SLOT_COUNT
COW_RESERVE_BLOCKS = 256
METADATA_HEADER = struct.Struct(">8sQQ32s")
METADATA_PAYLOAD_LIMIT = (
    METADATA_SLOT_BLOCKS * LOGICAL_BLOCK_SIZE - METADATA_HEADER.size
)

_T = TypeVar("_T")


@dataclass(slots=True)
class _NodeState:
    node_id: int
    parent_id: int | None
    name: str
    is_directory: bool
    size: int
    created_ns: int
    modified_ns: int
    blocks: dict[int, tuple[int, bytes]] = field(default_factory=dict)


class BlockVaultContainer:
    """Mounted container backed by independently encrypted logical blocks.

    File content is never serialized into one large database. Only blocks that
    intersect a write request are read, encrypted and replaced. Filesystem
    metadata uses two alternating authenticated checkpoints, so an interrupted
    checkpoint leaves the previous complete generation available.
    """

    def __init__(
        self,
        path: Path,
        volume: EncryptedBlockVolume,
        nodes: dict[int, _NodeState],
        next_node_id: int,
        data_capacity: int,
        sequence: int,
    ) -> None:
        self.path = Path(path)
        self._volume = volume
        self._nodes = nodes
        self._next_node_id = next_node_id
        self._data_capacity = data_capacity
        self._sequence = sequence
        self._lock = threading.RLock()
        self._closed = False
        self._dirty = False
        self._children: dict[tuple[int, str], int] = {}
        self._allocated: set[int] = set()
        self._allocation_hint = 0
        self._rebuild_indexes()

    @classmethod
    def create(
        cls,
        path: Path,
        master_key: bytes,
        *,
        data_capacity: int = 20 * 1024 * 1024,
        label: str = "Clever PGP",
        algorithm: str = DEFAULT_DISK_ALGORITHM,
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
    ) -> BlockVaultContainer:
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

        cls._report_progress(progress, 3, "Проверка параметров диска")
        data_blocks = math.ceil(data_capacity / LOGICAL_BLOCK_SIZE)
        logical_capacity = (
            METADATA_BLOCKS + data_blocks + COW_RESERVE_BLOCKS
        ) * LOGICAL_BLOCK_SIZE

        def initialize_progress(completed: int, total: int) -> None:
            fraction = completed / total if total else 1.0
            cls._report_progress(
                progress,
                5 + round(fraction * 85),
                "Подготовка зашифрованных блоков",
            )

        volume = EncryptedBlockVolume.create(
            target,
            master_key,
            logical_capacity=logical_capacity,
            label=label,
            algorithm=algorithm,
            overwrite=overwrite,
            storage_format=BLOCK_VAULT_STORAGE_FORMAT,
            progress=initialize_progress,
        )
        now = cls._now_ns()
        container = cls(
            target,
            volume,
            {
                1: _NodeState(
                    node_id=1,
                    parent_id=None,
                    name="",
                    is_directory=True,
                    size=0,
                    created_ns=now,
                    modified_ns=now,
                )
            },
            2,
            data_capacity,
            0,
        )
        container._dirty = True
        try:
            container.save(progress=progress, progress_start=90, progress_end=100)
        except Exception:
            container.close(save=False)
            target.unlink(missing_ok=True)
            raise
        return container

    @classmethod
    def open(cls, path: Path, master_key: bytes) -> BlockVaultContainer:
        source = Path(path).expanduser().resolve()
        cls._validate_master_key(master_key)
        try:
            volume = EncryptedBlockVolume.open(source, master_key)
        except BlockVolumeError as error:
            raise InvalidContainerError(str(error)) from error

        try:
            if volume.storage_format not in (None, BLOCK_VAULT_STORAGE_FORMAT):
                raise InvalidContainerError(
                    "Этот диск содержит обычную файловую систему Windows."
                )
            candidates: list[
                tuple[int, dict[int, _NodeState], int, int]
            ] = []
            for slot in range(METADATA_SLOT_COUNT):
                decoded = cls._read_metadata_slot(volume, slot)
                if decoded is not None:
                    candidates.append(decoded)
            if not candidates:
                raise InvalidContainerError(
                    "Файловая система зашифрованного диска повреждена."
                )
            sequence, nodes, next_node_id, data_capacity = max(
                candidates, key=lambda item: item[0]
            )
            expected_blocks = (
                METADATA_BLOCKS
                + math.ceil(data_capacity / LOGICAL_BLOCK_SIZE)
                + COW_RESERVE_BLOCKS
            )
            if expected_blocks != volume.block_count:
                raise InvalidContainerError(
                    "Размер файловой системы не соответствует контейнеру."
                )
            container = cls(
                source,
                volume,
                nodes,
                next_node_id,
                data_capacity,
                sequence,
            )
            container._validate_state()
            return container
        except Exception:
            volume.close()
            raise

    @property
    def label(self) -> str:
        return self._volume.label

    @property
    def data_capacity(self) -> int:
        return self._data_capacity

    @property
    def used_space(self) -> int:
        with self._lock:
            self._ensure_open()
            return sum(
                node.size for node in self._nodes.values() if not node.is_directory
            )

    @property
    def free_space(self) -> int:
        return self.data_capacity - self.used_space

    @classmethod
    def required_storage_size(cls, data_capacity: int) -> int:
        cls._validate_capacity(data_capacity)
        data_blocks = math.ceil(data_capacity / LOGICAL_BLOCK_SIZE)
        return EncryptedBlockVolume.physical_size(
            METADATA_BLOCKS + data_blocks + COW_RESERVE_BLOCKS
        )

    @classmethod
    def storage_space(cls, path: Path) -> tuple[int, int]:
        target = Path(path).expanduser().resolve()
        directory = target if target.is_dir() else target.parent
        if not directory.is_dir():
            raise ValidationError("Папка для контейнера не существует.")
        try:
            import shutil

            free_bytes = int(shutil.disk_usage(directory).free)
        except OSError as error:
            raise ValidationError(
                "Не удалось определить свободное место на выбранном накопителе."
            ) from error
        fixed_size = HEADER_PREFIX.size + HEADER_AREA_SIZE
        usable_slots = max(0, (free_bytes - fixed_size) // PHYSICAL_SLOT_SIZE)
        data_blocks = max(
            0, usable_slots - METADATA_BLOCKS - COW_RESERVE_BLOCKS
        )
        maximum_capacity = min(
            MAX_FORMAT_FILE_SIZE,
            data_blocks * LOGICAL_BLOCK_SIZE,
        )
        return free_bytes, maximum_capacity

    @classmethod
    def available_data_capacity(cls, path: Path) -> int:
        return cls.storage_space(path)[1]

    def node(self, path: str | PurePosixPath) -> VaultNode:
        with self._lock:
            return self._public_node(self._resolve_node(path))

    def list_directory(self, path: str | PurePosixPath = "/") -> list[VaultNode]:
        with self._lock:
            parent = self._resolve_node(path)
            if not parent.is_directory:
                raise ContainerNotDirectoryError("Указанный путь не является папкой.")
            children = [
                node
                for node in self._nodes.values()
                if node.parent_id == parent.node_id
            ]
            children.sort(key=lambda node: (self._name_key(node.name), node.name))
            return [self._public_node(node) for node in children]

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
            self._ensure_open()
            node = self._resolve_node(path)
            if node.is_directory:
                raise ContainerIsDirectoryError("Нельзя читать папку как файл.")
            if offset >= node.size:
                return b""
            end = node.size if length is None else min(node.size, offset + length)
            first_block = offset // LOGICAL_BLOCK_SIZE
            last_block = (end - 1) // LOGICAL_BLOCK_SIZE
            plaintext = self._read_logical_blocks(
                node, first_block, last_block - first_block + 1
            )
            start_in_buffer = offset - first_block * LOGICAL_BLOCK_SIZE
            return plaintext[start_in_buffer : start_in_buffer + end - offset]

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
        if not payload:
            return 0
        with self._lock:
            self._ensure_open()
            node = self._resolve_node(path)
            if node.is_directory:
                raise ContainerIsDirectoryError("Нельзя записывать данные в папку.")
            actual_offset = node.size if append else offset
            if constrained:
                if actual_offset >= node.size:
                    return 0
                payload = payload[: node.size - actual_offset]
                if not payload:
                    return 0
            new_size = max(node.size, actual_offset + len(payload))
            self._ensure_data_capacity(new_size - node.size)

            first_block = actual_offset // LOGICAL_BLOCK_SIZE
            last_block = (actual_offset + len(payload) - 1) // LOGICAL_BLOCK_SIZE
            logical_blocks = list(range(first_block, last_block + 1))
            self._ensure_cow_capacity(len(logical_blocks))
            old_mapping = {index: node.blocks.get(index) for index in logical_blocks}
            old_size = node.size
            old_modified = node.modified_ns
            allocated_now: list[int] = []
            new_mapping: dict[int, tuple[int, bytes]] = {}
            block_payloads: list[tuple[int, bytes, bytes]] = []
            payload_position = 0
            write_context = secrets.token_bytes(16)
            try:
                for logical_index in logical_blocks:
                    block_start = logical_index * LOGICAL_BLOCK_SIZE
                    write_start = max(actual_offset, block_start)
                    write_end = min(
                        actual_offset + len(payload), block_start + LOGICAL_BLOCK_SIZE
                    )
                    source_start = write_start - actual_offset
                    source_end = write_end - actual_offset
                    if write_start == block_start and write_end == block_start + LOGICAL_BLOCK_SIZE:
                        block = payload[source_start:source_end]
                    else:
                        previous = node.blocks.get(logical_index)
                        if previous is None:
                            mutable = bytearray(LOGICAL_BLOCK_SIZE)
                        else:
                            mutable = bytearray(
                                self._read_physical_blocks(
                                    previous[0], 1, previous[1]
                                )
                            )
                        mutable[
                            write_start - block_start : write_end - block_start
                        ] = payload[source_start:source_end]
                        block = bytes(mutable)
                    previous = node.blocks.get(logical_index)
                    physical = self._allocate_data_block()
                    allocated_now.append(physical)
                    new_mapping[logical_index] = (physical, write_context)
                    block_payloads.append((physical, block, write_context))
                    payload_position += source_end - source_start

                self._write_physical_runs(block_payloads)
                node.blocks.update(new_mapping)
                node.size = new_size
                node.modified_ns = self._now_ns()
                self._dirty = True
                if persist:
                    self.save()
                return payload_position
            except Exception:
                for logical_index, physical in old_mapping.items():
                    if physical is None:
                        node.blocks.pop(logical_index, None)
                    else:
                        node.blocks[logical_index] = physical
                node.size = old_size
                node.modified_ns = old_modified
                for physical in allocated_now:
                    if physical not in (
                        reference[0] for reference in node.blocks.values()
                    ):
                        self._allocated.discard(physical)
                raise

    def truncate_file(
        self,
        path: str | PurePosixPath,
        size: int,
        *,
        persist: bool = True,
    ) -> None:
        if size < 0:
            raise ValidationError("Размер файла не может быть отрицательным.")
        with self._lock:
            node = self._resolve_node(path)
            if node.is_directory:
                raise ContainerIsDirectoryError("Нельзя изменить размер папки.")
            self._ensure_data_capacity(size - node.size)
            if size == node.size:
                return
            needs_partial_rewrite = (
                size < node.size
                and bool(size % LOGICAL_BLOCK_SIZE)
                and size // LOGICAL_BLOCK_SIZE in node.blocks
            )
            if needs_partial_rewrite:
                self._ensure_cow_capacity(1)
            old_size = node.size
            old_blocks = dict(node.blocks)
            old_modified = node.modified_ns
            try:
                if size < node.size:
                    first_removed = math.ceil(size / LOGICAL_BLOCK_SIZE)
                    node.blocks = {
                        logical: physical
                        for logical, physical in node.blocks.items()
                        if logical < first_removed
                    }
                    if size and size % LOGICAL_BLOCK_SIZE:
                        logical = size // LOGICAL_BLOCK_SIZE
                        previous = node.blocks.get(logical)
                        if previous is not None:
                            block = bytearray(
                                self._read_physical_blocks(
                                    previous[0], 1, previous[1]
                                )
                            )
                            block[size % LOGICAL_BLOCK_SIZE :] = bytes(
                                LOGICAL_BLOCK_SIZE - size % LOGICAL_BLOCK_SIZE
                            )
                            physical = self._allocate_data_block()
                            write_context = secrets.token_bytes(16)
                            self._volume.write_blocks(
                                METADATA_BLOCKS + physical,
                                bytes(block),
                                context=write_context,
                            )
                            node.blocks[logical] = (physical, write_context)
                node.size = size
                node.modified_ns = self._now_ns()
                self._dirty = True
                if persist:
                    self.save()
            except Exception:
                node.size = old_size
                node.blocks = old_blocks
                node.modified_ns = old_modified
                self._rebuild_allocated()
                raise

    def remove(self, path: str | PurePosixPath, *, persist: bool = True) -> None:
        normalized = self._normalize_path(path)
        if normalized == PurePosixPath("/"):
            raise ValidationError("Корневую папку удалить нельзя.")

        def mutation() -> None:
            node = self._resolve_node(normalized)
            if node.is_directory and any(
                child.parent_id == node.node_id for child in self._nodes.values()
            ):
                raise ContainerDirectoryNotEmptyError("Папка не пуста.")
            del self._nodes[node.node_id]

        self._mutate_metadata(mutation, persist=persist)

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
            source_node = self._resolve_node(source_path)
            target_parent, target_name = self._resolve_parent(target_path)
            existing = self._find_child(target_parent.node_id, target_name)
            if existing is not None and existing.node_id != source_node.node_id:
                if not replace:
                    raise ContainerEntryExistsError(
                        "Объект с таким именем уже существует."
                    )
                if existing.is_directory != source_node.is_directory:
                    if existing.is_directory:
                        raise ContainerIsDirectoryError("Целевой путь является папкой.")
                    raise ContainerNotDirectoryError(
                        "Целевой путь не является папкой."
                    )
                if existing.is_directory and any(
                    child.parent_id == existing.node_id
                    for child in self._nodes.values()
                ):
                    raise ContainerDirectoryNotEmptyError("Целевая папка не пуста.")
                del self._nodes[existing.node_id]
            source_node.parent_id = target_parent.node_id
            source_node.name = target_name
            source_node.modified_ns = self._now_ns()

        self._mutate_metadata(mutation, persist=persist)

    def update_times(
        self,
        path: str | PurePosixPath,
        *,
        modified_ns: int | None = None,
        persist: bool = True,
    ) -> None:
        value = self._now_ns() if modified_ns is None else modified_ns

        def mutation() -> None:
            self._resolve_node(path).modified_ns = value

        self._mutate_metadata(mutation, persist=persist)

    def save(
        self,
        *,
        progress: ProgressCallback | None = None,
        progress_start: int = 0,
        progress_end: int = 100,
    ) -> None:
        with self._lock:
            self._ensure_open()

            def report(fraction: float, message: str) -> None:
                self._report_progress(
                    progress,
                    progress_start
                    + round((progress_end - progress_start) * fraction),
                    message,
                )

            report(0.1, "Подготовка файловой системы")
            payload = self._encode_state()
            if len(payload) > METADATA_PAYLOAD_LIMIT:
                raise ContainerFullError(
                    "В контейнере недостаточно места для метаданных."
                )
            sequence = self._sequence + 1
            digest = hashlib.blake2b(payload, digest_size=32).digest()
            encoded = METADATA_HEADER.pack(
                FILESYSTEM_MAGIC, sequence, len(payload), digest
            ) + payload
            slot_data = encoded.ljust(
                METADATA_SLOT_BLOCKS * LOGICAL_BLOCK_SIZE, b"\0"
            )
            target_slot = sequence % METADATA_SLOT_COUNT
            report(0.35, "Шифрование метаданных диска")
            self._volume.write_blocks(
                target_slot * METADATA_SLOT_BLOCKS, slot_data
            )
            report(0.75, "Синхронизация изменённых блоков")
            self._volume.flush()
            self._sequence = sequence
            self._dirty = False
            self._rebuild_allocated()
            report(1.0, "Готово")

    def close(self, *, save: bool = True) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                if save and self._dirty:
                    self.save()
                else:
                    self._volume.flush()
            finally:
                self._volume.close()
                self._closed = True

    def __enter__(self) -> BlockVaultContainer:
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
        created: _NodeState | None = None

        def mutation() -> None:
            nonlocal created
            parent, name = self._resolve_parent(normalized)
            if self._find_child(parent.node_id, name) is not None:
                raise ContainerEntryExistsError(
                    "Объект с таким именем уже существует."
                )
            now = self._now_ns()
            created = _NodeState(
                node_id=self._next_node_id,
                parent_id=parent.node_id,
                name=name,
                is_directory=is_directory,
                size=0,
                created_ns=now,
                modified_ns=now,
            )
            self._nodes[created.node_id] = created
            self._next_node_id += 1

        self._mutate_metadata(mutation, persist=persist)
        if created is None:
            raise InvalidContainerError("Не удалось создать объект контейнера.")
        return self._public_node(created)

    def _mutate_metadata(self, operation: Callable[[], _T], *, persist: bool) -> _T:
        with self._lock:
            self._ensure_open()
            nodes_before = copy.deepcopy(self._nodes)
            next_before = self._next_node_id
            dirty_before = self._dirty
            try:
                result = operation()
                self._rebuild_children()
                self._dirty = True
                if persist:
                    self.save()
                return result
            except Exception:
                self._nodes = nodes_before
                self._next_node_id = next_before
                self._dirty = dirty_before
                self._rebuild_indexes()
                raise

    def _resolve_parent(self, path: PurePosixPath) -> tuple[_NodeState, str]:
        name = path.name
        self._validate_name(name)
        parent = self._resolve_node(path.parent)
        if not parent.is_directory:
            raise ContainerNotDirectoryError("Родительский путь не является папкой.")
        return parent, name

    def _resolve_node(self, path: str | PurePosixPath) -> _NodeState:
        normalized = self._normalize_path(path)
        current = self._nodes.get(1)
        if current is None or not current.is_directory or current.parent_id is not None:
            raise InvalidContainerError("В контейнере отсутствует корневая папка.")
        if normalized == PurePosixPath("/"):
            return current
        for name in normalized.parts[1:]:
            current = self._find_child(current.node_id, name)
            if current is None:
                raise ContainerEntryNotFoundError(
                    f"Объект не найден: {normalized}"
                )
        return current

    def _find_child(self, parent_id: int, name: str) -> _NodeState | None:
        node_id = self._children.get((parent_id, self._name_key(name)))
        return self._nodes.get(node_id) if node_id is not None else None

    def _read_logical_blocks(
        self, node: _NodeState, first_block: int, block_count: int
    ) -> bytes:
        result = bytearray(block_count * LOGICAL_BLOCK_SIZE)
        index = 0
        while index < block_count:
            logical = first_block + index
            reference = node.blocks.get(logical)
            if reference is None:
                index += 1
                continue
            physical, context = reference
            run = 1
            while index + run < block_count:
                next_reference = node.blocks.get(first_block + index + run)
                if next_reference != (physical + run, context):
                    break
                run += 1
            data = self._read_physical_blocks(physical, run, context)
            start = index * LOGICAL_BLOCK_SIZE
            result[start : start + len(data)] = data
            index += run
        return bytes(result)

    def _read_physical_blocks(
        self, physical: int, block_count: int, context: bytes
    ) -> bytes:
        try:
            return self._volume.read_blocks(
                METADATA_BLOCKS + physical,
                block_count,
                context=context,
            )
        except BlockVolumeError as error:
            raise InvalidContainerError(
                "Нарушена целостность зашифрованных данных диска."
            ) from error

    def _write_physical_runs(
        self, blocks: list[tuple[int, bytes, bytes]]
    ) -> None:
        index = 0
        while index < len(blocks):
            start_physical, first, context = blocks[index]
            payload = bytearray(first)
            run = 1
            while index + run < len(blocks):
                physical, block, next_context = blocks[index + run]
                if physical != start_physical + run or next_context != context:
                    break
                payload.extend(block)
                run += 1
            self._volume.write_blocks(
                METADATA_BLOCKS + start_physical,
                bytes(payload),
                context=context,
            )
            index += run

    def _allocate_data_block(self) -> int:
        total = self._data_block_count
        for step in range(total):
            candidate = (self._allocation_hint + step) % total
            if candidate not in self._allocated:
                self._allocated.add(candidate)
                self._allocation_hint = (candidate + 1) % total
                return candidate
        raise ContainerFullError("В контейнере недостаточно свободного места.")

    def _ensure_cow_capacity(self, required_blocks: int) -> None:
        available = self._data_block_count - len(self._allocated)
        if required_blocks > available and self._dirty:
            self.save()
            available = self._data_block_count - len(self._allocated)
        if required_blocks > available:
            raise ContainerFullError(
                "Недостаточно резервных блоков для безопасной записи."
            )

    @property
    def _data_block_count(self) -> int:
        return self._volume.block_count - METADATA_BLOCKS

    def _ensure_data_capacity(self, growth: int) -> None:
        if growth > 0 and self.used_space + growth > self.data_capacity:
            raise ContainerFullError("В контейнере недостаточно свободного места.")

    def _encode_state(self) -> bytes:
        nodes: list[list[object]] = []
        for node in sorted(self._nodes.values(), key=lambda item: item.node_id):
            nodes.append(
                [
                    node.node_id,
                    node.parent_id,
                    node.name,
                    int(node.is_directory),
                    node.size,
                    node.created_ns,
                    node.modified_ns,
                    self._mapping_to_extents(node.blocks),
                ]
            )
        state = {
            "version": FILESYSTEM_VERSION,
            "data_capacity": self.data_capacity,
            "label": self.label,
            "next_node_id": self._next_node_id,
            "nodes": nodes,
        }
        return json.dumps(
            state,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def _read_metadata_slot(
        cls, volume: EncryptedBlockVolume, slot: int
    ) -> tuple[int, dict[int, _NodeState], int, int] | None:
        try:
            raw = volume.read_blocks(
                slot * METADATA_SLOT_BLOCKS, METADATA_SLOT_BLOCKS
            )
            magic, sequence, payload_size, digest = METADATA_HEADER.unpack(
                raw[: METADATA_HEADER.size]
            )
            if magic != FILESYSTEM_MAGIC or not 1 <= payload_size <= METADATA_PAYLOAD_LIMIT:
                return None
            payload = raw[
                METADATA_HEADER.size : METADATA_HEADER.size + payload_size
            ]
            if hashlib.blake2b(payload, digest_size=32).digest() != digest:
                return None
            state = json.loads(payload.decode("utf-8"))
            if not isinstance(state, dict) or state.get("version") != FILESYSTEM_VERSION:
                return None
            data_capacity = int(state["data_capacity"])
            next_node_id = int(state["next_node_id"])
            if str(state["label"]) != volume.label:
                return None
            nodes: dict[int, _NodeState] = {}
            raw_nodes = state["nodes"]
            if not isinstance(raw_nodes, list):
                return None
            for raw_node in raw_nodes:
                if not isinstance(raw_node, list) or len(raw_node) != 8:
                    return None
                node = _NodeState(
                    node_id=int(raw_node[0]),
                    parent_id=(
                        None if raw_node[1] is None else int(raw_node[1])
                    ),
                    name=str(raw_node[2]),
                    is_directory=bool(raw_node[3]),
                    size=int(raw_node[4]),
                    created_ns=int(raw_node[5]),
                    modified_ns=int(raw_node[6]),
                    blocks=cls._extents_to_mapping(raw_node[7]),
                )
                if node.node_id in nodes:
                    return None
                nodes[node.node_id] = node
            cls._validate_capacity(data_capacity)
            return sequence, nodes, next_node_id, data_capacity
        except (BlockVolumeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

    @staticmethod
    def _mapping_to_extents(
        mapping: dict[int, tuple[int, bytes]]
    ) -> list[list[object]]:
        extents: list[list[object]] = []
        for logical, reference in sorted(mapping.items()):
            physical, context = reference
            if (
                extents
                and logical == extents[-1][0] + extents[-1][2]
                and physical == extents[-1][1] + extents[-1][2]
                and context.hex() == extents[-1][3]
            ):
                extents[-1][2] += 1
            else:
                extents.append([logical, physical, 1, context.hex()])
        return extents

    @staticmethod
    def _extents_to_mapping(raw: object) -> dict[int, tuple[int, bytes]]:
        if not isinstance(raw, list):
            raise ValueError("extents")
        mapping: dict[int, tuple[int, bytes]] = {}
        for extent in raw:
            if not isinstance(extent, list) or len(extent) != 4:
                raise ValueError("extent")
            logical, physical, count = map(int, extent[:3])
            context = bytes.fromhex(str(extent[3]))
            if logical < 0 or physical < 0 or count <= 0:
                raise ValueError("extent range")
            if len(context) != 16:
                raise ValueError("extent context")
            for offset in range(count):
                if logical + offset in mapping:
                    raise ValueError("overlapping extents")
                mapping[logical + offset] = (physical + offset, context)
        return mapping

    def _validate_state(self) -> None:
        root = self._nodes.get(1)
        if (
            root is None
            or not root.is_directory
            or root.parent_id is not None
            or root.name
        ):
            raise InvalidContainerError("Повреждена корневая папка контейнера.")
        if self._next_node_id <= max(self._nodes, default=0):
            raise InvalidContainerError("Некорректный счётчик файловой системы.")
        seen_names: set[tuple[int, str]] = set()
        seen_blocks: set[int] = set()
        total_size = 0
        for node in self._nodes.values():
            if node.node_id <= 0 or node.size < 0:
                raise InvalidContainerError("Повреждены метаданные объекта.")
            if node.node_id != 1:
                parent = self._nodes.get(node.parent_id or -1)
                if parent is None or not parent.is_directory:
                    raise InvalidContainerError("Повреждена структура каталогов.")
                self._validate_name(node.name)
                identity = (parent.node_id, self._name_key(node.name))
                if identity in seen_names:
                    raise InvalidContainerError("Обнаружены повторяющиеся имена.")
                seen_names.add(identity)
            if node.is_directory:
                if node.size or node.blocks:
                    raise InvalidContainerError("Папка содержит файловые блоки.")
                continue
            total_size += node.size
            maximum_logical = math.ceil(node.size / LOGICAL_BLOCK_SIZE)
            for logical, reference in node.blocks.items():
                physical, context = reference
                if (
                    logical < 0
                    or logical >= maximum_logical
                    or physical < 0
                    or physical >= self._data_block_count
                    or physical in seen_blocks
                    or len(context) != 16
                ):
                    raise InvalidContainerError("Повреждена карта блоков файла.")
                seen_blocks.add(physical)
        if total_size > self.data_capacity:
            raise InvalidContainerError("Данные превышают размер контейнера.")

    def _rebuild_indexes(self) -> None:
        self._rebuild_children()
        self._rebuild_allocated()

    def _rebuild_children(self) -> None:
        children: dict[tuple[int, str], int] = {}
        for node in self._nodes.values():
            if node.parent_id is not None:
                children[(node.parent_id, self._name_key(node.name))] = node.node_id
        self._children = children

    def _rebuild_allocated(self) -> None:
        self._allocated = {
            reference[0]
            for node in self._nodes.values()
            for reference in node.blocks.values()
        }
        self._allocation_hint = 0
        while (
            self._allocation_hint < self._data_block_count
            and self._allocation_hint in self._allocated
        ):
            self._allocation_hint += 1
        if self._allocation_hint >= self._data_block_count:
            self._allocation_hint = 0

    def _ensure_open(self) -> None:
        if self._closed:
            raise InvalidContainerError("Контейнер уже закрыт.")

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

    @classmethod
    def _name_key(cls, name: str) -> str:
        cls._validate_name(name)
        return unicodedata.normalize("NFC", name).casefold()

    @staticmethod
    def _public_node(node: _NodeState) -> VaultNode:
        return VaultNode(
            node_id=node.node_id,
            parent_id=node.parent_id,
            name=node.name,
            is_directory=node.is_directory,
            size=node.size,
            created_ns=node.created_ns,
            modified_ns=node.modified_ns,
        )

    @staticmethod
    def _report_progress(
        progress: ProgressCallback | None, value: int, message: str
    ) -> None:
        if progress is not None:
            progress(max(0, min(100, int(value))), message)

    @staticmethod
    def _validate_master_key(master_key: bytes) -> None:
        if not isinstance(master_key, bytes) or len(master_key) != secret.SecretBox.KEY_SIZE:
            raise ValidationError("Некорректный мастер-ключ профиля.")

    @staticmethod
    def _validate_capacity(data_capacity: int) -> None:
        if not isinstance(data_capacity, int) or data_capacity < MIN_DATA_CAPACITY:
            raise ValidationError("Размер контейнера должен быть не меньше 1 МБ.")
        if data_capacity > MAX_FORMAT_FILE_SIZE:
            raise ValidationError("Указанный размер превышает возможности файловой системы.")

    @staticmethod
    def _now_ns() -> int:
        return int(datetime.now(UTC).timestamp() * 1_000_000_000)


__all__ = [
    "BlockVaultContainer",
    "CONTAINER_SUFFIX",
    "METADATA_BLOCKS",
    "METADATA_SLOT_BLOCKS",
    "COW_RESERVE_BLOCKS",
    "BLOCK_VAULT_STORAGE_FORMAT",
]
