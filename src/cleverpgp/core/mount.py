from __future__ import annotations

import errno
import ctypes
import multiprocessing
import os
import platform
import stat
import threading
import time
from collections.abc import Callable
from ctypes.util import find_library
from pathlib import Path
from typing import Any

from cleverpgp.core.block_container import BlockVaultContainer
from cleverpgp.core.container import VaultNode
from cleverpgp.core.errors import (
    ContainerDirectoryNotEmptyError,
    ContainerEntryExistsError,
    ContainerEntryNotFoundError,
    ContainerError,
    ContainerFullError,
    ContainerIsDirectoryError,
    ContainerNotDirectoryError,
    MountUnavailableError,
    ValidationError,
)

CONTROL_PATH = "/.cleverpgp-unmount"
BLOCK_SIZE = 4096


class VaultFuseOperations:
    """Maps the encrypted in-memory filesystem to the cross-platform FUSE API."""

    def __init__(self, container: BlockVaultContainer, status_connection: Any = None):
        self.container = container
        self.status_connection = status_connection
        self._dirty = False
        self._handle = 0
        self._lock = threading.RLock()

    def __call__(self, operation: str, *args: object) -> object:
        method = getattr(self, operation, None)
        if method is None:
            raise OSError(errno.ENOSYS, os.strerror(errno.ENOSYS))
        try:
            return method(*args)
        except OSError:
            raise
        except ContainerEntryNotFoundError as error:
            raise OSError(errno.ENOENT, str(error)) from error
        except ContainerEntryExistsError as error:
            raise OSError(errno.EEXIST, str(error)) from error
        except ContainerNotDirectoryError as error:
            raise OSError(errno.ENOTDIR, str(error)) from error
        except ContainerIsDirectoryError as error:
            raise OSError(errno.EISDIR, str(error)) from error
        except ContainerDirectoryNotEmptyError as error:
            raise OSError(errno.ENOTEMPTY, str(error)) from error
        except ContainerFullError as error:
            raise OSError(errno.ENOSPC, str(error)) from error
        except ValidationError as error:
            raise OSError(errno.EINVAL, str(error)) from error
        except ContainerError as error:
            raise OSError(errno.EIO, str(error)) from error

    def init(self, path: str) -> None:
        self._send_status("ready", "")

    def destroy(self, path: str) -> None:
        try:
            self.container.close(save=True)
        finally:
            self._send_status("stopped", "")

    def getattr(self, path: str, file_handle: int | None = None) -> dict[str, object]:
        if path == CONTROL_PATH:
            return self._control_attributes()
        return self._attributes(self.container.node(path))

    def readdir(self, path: str, file_handle: int) -> list[str]:
        return [".", "..", *[node.name for node in self.container.list_directory(path)]]

    def mkdir(self, path: str, mode: int) -> int:
        self.container.create_directory(path, persist=True)
        return 0

    def rmdir(self, path: str) -> int:
        node = self.container.node(path)
        if not node.is_directory:
            raise OSError(errno.ENOTDIR, os.strerror(errno.ENOTDIR))
        self.container.remove(path, persist=True)
        return 0

    def create(self, path: str, mode: int, file_info: object = None) -> int:
        self.container.create_file(path, persist=False)
        self._dirty = True
        return self._next_handle()

    def mknod(self, path: str, mode: int, device: int) -> int:
        self.container.create_file(path, persist=False)
        self._dirty = True
        return 0

    def open(self, path: str, flags: int) -> int:
        if path == CONTROL_PATH:
            self._flush_dirty()
            from refuse.high import fuse_exit

            fuse_exit()
            return self._next_handle()
        node = self.container.node(path)
        if node.is_directory:
            raise OSError(errno.EISDIR, os.strerror(errno.EISDIR))
        return self._next_handle()

    def read(self, path: str, size: int, offset: int, file_handle: int) -> bytes:
        return self.container.read_file(path, offset=offset, length=size)

    def write(
        self, path: str, data: bytes, offset: int, file_handle: int
    ) -> int:
        with self._lock:
            written = self.container.write_file(
                path, data, offset=offset, persist=False
            )
            self._dirty = True
            return written

    def truncate(
        self, path: str, length: int, file_handle: int | None = None
    ) -> int:
        with self._lock:
            self.container.truncate_file(path, length, persist=False)
            self._dirty = True
        return 0

    def unlink(self, path: str) -> int:
        node = self.container.node(path)
        if node.is_directory:
            raise OSError(errno.EISDIR, os.strerror(errno.EISDIR))
        self.container.remove(path, persist=True)
        return 0

    def rename(self, source: str, target: str) -> int:
        self.container.rename(source, target, replace=True, persist=True)
        return 0

    def flush(self, path: str, file_handle: int) -> int:
        self._flush_dirty()
        return 0

    def fsync(self, path: str, datasync: bool, file_handle: int) -> int:
        self._flush_dirty()
        return 0

    def release(self, path: str, file_handle: int) -> int:
        self._flush_dirty()
        return 0

    def statfs(self, path: str) -> dict[str, int]:
        blocks = (self.container.data_capacity + BLOCK_SIZE - 1) // BLOCK_SIZE
        free_blocks = self.container.free_space // BLOCK_SIZE
        return {
            "f_bsize": BLOCK_SIZE,
            "f_frsize": BLOCK_SIZE,
            "f_blocks": blocks,
            "f_bfree": free_blocks,
            "f_bavail": free_blocks,
            "f_files": 100_000,
            "f_ffree": 100_000 - len(self.container.list_directory("/")),
            "f_favail": 100_000 - len(self.container.list_directory("/")),
            "f_namemax": 255,
        }

    def utimens(
        self, path: str, times: tuple[float, float] | None = None
    ) -> int:
        modified_ns = int(times[1] * 1_000_000_000) if times else time.time_ns()
        self.container.update_times(path, modified_ns=modified_ns, persist=True)
        return 0

    def access(self, path: str, mode: int) -> int:
        if path == CONTROL_PATH:
            return 0
        self.container.node(path)
        return 0

    def chmod(self, path: str, mode: int) -> int:
        self.container.node(path)
        return 0

    def chown(self, path: str, user_id: int, group_id: int) -> int:
        self.container.node(path)
        return 0

    def _flush_dirty(self) -> None:
        with self._lock:
            if self._dirty:
                self.container.save()
                self._dirty = False

    def _next_handle(self) -> int:
        with self._lock:
            self._handle += 1
            return self._handle

    def _send_status(self, status: str, message: str) -> None:
        if self.status_connection is None:
            return
        try:
            self.status_connection.send((status, message))
        except (BrokenPipeError, EOFError, OSError):
            pass

    @staticmethod
    def _attributes(node: VaultNode) -> dict[str, object]:
        permissions = 0o755 if node.is_directory else 0o644
        kind = stat.S_IFDIR if node.is_directory else stat.S_IFREG
        return {
            "st_mode": kind | permissions,
            "st_nlink": 2 if node.is_directory else 1,
            "st_size": node.size,
            "st_ctime": node.created_ns / 1_000_000_000,
            "st_mtime": node.modified_ns / 1_000_000_000,
            "st_atime": node.modified_ns / 1_000_000_000,
            "st_ino": node.node_id,
        }

    @staticmethod
    def _control_attributes() -> dict[str, object]:
        now = time.time()
        return {
            "st_mode": stat.S_IFREG | 0o400,
            "st_nlink": 1,
            "st_size": 0,
            "st_ctime": now,
            "st_mtime": now,
            "st_atime": now,
        }


class VaultMountManager:
    def __init__(self) -> None:
        self._process: multiprocessing.Process | None = None
        self._drive: str | None = None

    @property
    def mounted_drive(self) -> str | None:
        if self._process is not None and self._process.is_alive():
            return self._drive
        if self._process is not None:
            self._process.join(0)
            self._process = None
            self._drive = None
        return None

    def mount(
        self,
        container_path: Path,
        master_key: bytes,
        drive: str | None = None,
        *,
        progress: Callable[[int, str], None] | None = None,
    ) -> str:
        if progress is not None:
            progress(5, "Проверка компонента виртуального диска")
        if self.mounted_drive is not None:
            raise MountUnavailableError("Сначала отключите уже открытый диск Clever PGP.")
        if not mount_backend_available():
            raise MountUnavailableError(
                "Для виртуального диска установите системный компонент WinFsp. "
                "Обычное шифрование файлов работает без него."
            )
        mount_point = normalize_drive(drive or next_available_drive())
        if progress is not None:
            progress(15, "Проверка контейнера")
        receive_status, send_status = multiprocessing.Pipe(duplex=False)
        process = multiprocessing.Process(
            target=_mount_process,
            args=(str(Path(container_path).resolve()), bytes(master_key), mount_point, send_status),
            name="Clever PGP encrypted disk",
        )
        if progress is not None:
            progress(25, "Запуск виртуального диска")
        process.start()
        send_status.close()
        started_at = time.monotonic()
        ready = False
        while time.monotonic() - started_at < 12:
            if receive_status.poll(0.2):
                ready = True
                break
            if not process.is_alive():
                break
            if progress is not None:
                elapsed = time.monotonic() - started_at
                progress(
                    min(90, 25 + round(elapsed / 12 * 65)),
                    "Подключение зашифрованного диска",
                )
        if not ready:
            process.terminate()
            process.join(3)
            raise MountUnavailableError("Виртуальный диск не ответил вовремя.")
        status, message = receive_status.recv()
        receive_status.close()
        if status != "ready":
            process.join(3)
            if process.is_alive():
                process.terminate()
                process.join(3)
            raise MountUnavailableError(message or "Не удалось подключить контейнер.")
        self._process = process
        self._drive = mount_point
        if progress is not None:
            progress(100, "Диск подключён")
        return mount_point

    def unmount(self) -> None:
        process = self._process
        drive = self._drive
        if process is None:
            return
        if process.is_alive() and drive is not None:
            control = Path(f"{drive}/.cleverpgp-unmount")
            try:
                with control.open("rb"):
                    pass
            except OSError:
                pass
            process.join(8)
        if process.is_alive():
            process.terminate()
            process.join(3)
        self._process = None
        self._drive = None


def _mount_process(
    container_path: str,
    master_key: bytes,
    mount_point: str,
    status_connection: Any,
) -> None:
    container: BlockVaultContainer | None = None
    try:
        from refuse.high import FUSE

        container = BlockVaultContainer.open(Path(container_path), master_key)
        operations = VaultFuseOperations(container, status_connection)
        FUSE(operations, mount_point, **mount_fuse_options(container.label))
    except Exception as error:
        try:
            status_connection.send(("error", str(error)))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        if container is not None:
            try:
                container.close(save=True)
            except ContainerError:
                pass
        status_connection.close()


def mount_fuse_options(volume_label: str) -> dict[str, object]:
    options: dict[str, object] = {
        "foreground": True,
        "nothreads": False,
        "fsname": "CleverPGP",
        "volname": volume_label,
    }
    if platform.system() == "Windows":
        # WinFsp otherwise maps mode 0755 to an unknown owner on some Windows
        # accounts. Explorer then treats the root as read-only even though our
        # FUSE operations implement create/write. -1 maps ownership to the
        # Windows user that launched Clever PGP.
        options.update(uid=-1, gid=-1, umask=0, create_umask=0)
    return options


def mount_backend_available() -> bool:
    if platform.system() == "Windows":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\WinFsp",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_32KEY,
            ) as key:
                install_dir = Path(str(winreg.QueryValueEx(key, "InstallDir")[0]))
            return install_dir.is_dir()
        except (FileNotFoundError, OSError):
            return False
    return Path("/dev/fuse").exists() and bool(find_library("fuse"))


def next_available_drive() -> str:
    if platform.system() != "Windows":
        raise MountUnavailableError("Автовыбор буквы диска доступен только в Windows.")
    for letter in reversed("DEFGHIJKLMNOPQRSTUVWXYZ"):
        candidate = f"{letter}:"
        if not _drive_in_use(candidate):
            return candidate
    raise MountUnavailableError("Нет свободной буквы для виртуального диска.")


def normalize_drive(drive: str) -> str:
    normalized = normalized_drive_name(drive)
    if _drive_in_use(normalized):
        raise MountUnavailableError(f"Диск {normalized} уже используется.")
    return normalized


def normalized_drive_name(drive: str) -> str:
    normalized = drive.strip().upper().rstrip("\\/")
    if len(normalized) == 1:
        normalized += ":"
    if len(normalized) != 2 or normalized[1] != ":" or not normalized[0].isalpha():
        raise ValidationError("Некорректная буква диска.")
    return normalized


def unmount_drive(drive: str, *, timeout: float = 12.0) -> str:
    if platform.system() != "Windows":
        raise MountUnavailableError("Команда отключения диска доступна только в Windows.")
    normalized = normalized_drive_name(drive)
    if not _drive_in_use(normalized):
        raise MountUnavailableError(f"Диск {normalized} уже отключён.")
    control = Path(f"{normalized}/{CONTROL_PATH.lstrip('/')}")
    system_record = None
    try:
        with control.open("rb"):
            pass
    except OSError:
        from cleverpgp.core.disk_control import DiskControlStore

        control_store = DiskControlStore()
        system_record = control_store.find_by_drive(normalized)
        if system_record is None:
            raise MountUnavailableError(
                f"Диск {normalized} не является диском Clever PGP."
            )
        control_store.send(system_record, "stop")

    deadline = time.monotonic() + timeout
    while _drive_in_use(normalized) and time.monotonic() < deadline:
        time.sleep(0.05)
    if _drive_in_use(normalized):
        raise MountUnavailableError(f"Не удалось отключить диск {normalized}.")
    if system_record is not None:
        DiskControlStore.remove(system_record)
        try:
            from cleverpgp.core.windows_shell import WindowsDriveContextMenu

            WindowsDriveContextMenu().remove(normalized)
        except OSError:
            pass
    return normalized


def _drive_in_use(drive: str) -> bool:
    if platform.system() != "Windows":
        return Path(f"{drive}/").exists()
    bit = ord(drive[0].upper()) - ord("A")
    mask = int(ctypes.windll.kernel32.GetLogicalDrives())
    return bool(mask & (1 << bit))
