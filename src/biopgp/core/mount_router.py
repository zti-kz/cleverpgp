from __future__ import annotations

import platform
from collections.abc import Callable
from pathlib import Path
from typing import Any

from biopgp.core.block_container import BLOCK_VAULT_STORAGE_FORMAT
from biopgp.core.block_volume import BlockVolumeError, EncryptedBlockVolume
from biopgp.core.errors import InvalidContainerError, MountUnavailableError
from biopgp.core.mount import VaultMountManager
from biopgp.core.volume_path import resolve_file_hosted_container_path
from biopgp.core.winspd import WINDOWS_BLOCK_STORAGE_FORMAT

BACKEND_WINDOWS = "windows"
BACKEND_WINFSP = "winfsp"


def detect_container_backend(path: Path, master_key: bytes) -> str:
    """Authenticate only the block header and return its required backend."""

    source = resolve_file_hosted_container_path(path)
    try:
        with EncryptedBlockVolume.open(source, master_key) as volume:
            storage_format = volume.storage_format
    except BlockVolumeError as error:
        raise InvalidContainerError(str(error)) from error
    if storage_format == WINDOWS_BLOCK_STORAGE_FORMAT:
        return BACKEND_WINDOWS
    if storage_format == BLOCK_VAULT_STORAGE_FORMAT:
        return BACKEND_WINFSP
    raise InvalidContainerError(
        "Назначение зашифрованного диска не поддерживается этой версией Clever PGP."
    )


class AutomaticMountManager:
    """Route an authenticated .cpgv to WinSpd or WinFsp without conversion."""

    automatically_selects_backend = True

    def __init__(
        self,
        *,
        system_manager: object | None = None,
        winfsp_manager: VaultMountManager | None = None,
    ) -> None:
        if system_manager is None and platform.system() == "Windows":
            from biopgp.core.windows_storage import WindowsSystemDiskManager

            system_manager = WindowsSystemDiskManager()
        self._system_manager = system_manager
        self._winfsp_manager = winfsp_manager or VaultMountManager()
        self._active_manager: object | None = None
        self._mounted_container: Path | None = None
        self._recover_active_manager()

    @property
    def mounted_drive(self) -> str | None:
        manager = self._selected_active_manager()
        return None if manager is None else _manager_drive(manager)

    @property
    def mounted_container(self) -> Path | None:
        manager = self._selected_active_manager()
        if manager is None:
            return None
        if manager is self._system_manager:
            value = getattr(manager, "mounted_container", None)
            return Path(value).resolve() if value is not None else None
        return self._mounted_container

    @property
    def mounted_algorithm(self) -> str | None:
        manager = self._selected_active_manager()
        if manager is None or manager is not self._system_manager:
            return None
        value = getattr(manager, "mounted_algorithm", None)
        return str(value) if value is not None else None

    @property
    def uses_windows_system_disk(self) -> bool:
        manager = self._selected_active_manager()
        return manager is not None and manager is self._system_manager

    @property
    def active_backend(self) -> str | None:
        manager = self._selected_active_manager()
        if manager is self._system_manager and manager is not None:
            return BACKEND_WINDOWS
        if manager is self._winfsp_manager:
            return BACKEND_WINFSP
        return None

    def mount(
        self,
        container_path: Path,
        master_key: bytes,
        drive: str | None = None,
        *,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> str:
        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый диск Clever PGP."
            )
        source = resolve_file_hosted_container_path(container_path)
        if progress is not None:
            progress(3, "Проверка типа зашифрованного диска")
        backend = detect_container_backend(source, master_key)
        if backend == BACKEND_WINDOWS:
            manager = self._system_manager
            if manager is None:
                raise MountUnavailableError(
                    "Виртуальный диск Clever PGP можно подключить только в Windows."
                )
            mounted = manager.mount(
                source,
                master_key,
                context_menu_labels=context_menu_labels,
                progress=progress,
            )
        else:
            manager = self._winfsp_manager
            mounted = manager.mount(
                source,
                master_key,
                drive,
                progress=progress,
            )
        self._active_manager = manager
        self._mounted_container = source
        return str(mounted)

    def create_and_mount(
        self,
        container_path: Path,
        master_key: bytes,
        **options: object,
    ) -> str:
        """Create the preferred fast Windows disk without removing WinFsp."""

        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый диск Clever PGP."
            )
        source = resolve_file_hosted_container_path(container_path)
        manager = self._system_manager
        if manager is None:
            raise MountUnavailableError(
                "Виртуальный диск Clever PGP можно создать только в Windows."
            )
        creator = getattr(manager, "create_and_mount", None)
        if not callable(creator):
            raise MountUnavailableError(
                "Компонент создания виртуального диска недоступен."
            )
        mounted = creator(source, master_key, **options)
        self._active_manager = manager
        self._mounted_container = source
        return str(mounted)

    def prepare_system_backend(self) -> None:
        """Preload the Windows bridge before a background disk operation."""

        manager = self._system_manager
        prepare = getattr(manager, "prepare_backend", None)
        if callable(prepare):
            prepare()

    def create_hidden_and_mount(
        self,
        container_path: Path,
        outer_password: str,
        hidden_password: str,
        **options: object,
    ) -> str:
        """Create a new file-hosted outer/hidden disk through WinSpd."""

        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый диск Clever PGP."
            )
        source = resolve_file_hosted_container_path(container_path)
        manager = self._system_manager
        creator = (
            getattr(manager, "create_hidden_and_mount", None)
            if manager is not None
            else None
        )
        if not callable(creator):
            raise MountUnavailableError(
                "Скрытый виртуальный диск можно создать только в Windows с WinSpd."
            )
        mounted = creator(
            source,
            outer_password,
            hidden_password,
            **options,
        )
        self._active_manager = manager
        self._mounted_container = source
        return str(mounted)

    def mount_opaque(
        self,
        container_path: Path,
        password: str,
        **options: object,
    ) -> str:
        """Unlock a portable ordinary disk or an opaque outer/hidden disk."""

        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый диск Clever PGP."
            )
        source = resolve_file_hosted_container_path(container_path)
        try:
            portable_key = EncryptedBlockVolume.password_access_key(
                source,
                password,
            )
        except BlockVolumeError as portable_error:
            if "Неверный пароль" in str(portable_error):
                raise
        else:
            ordinary_options = dict(options)
            ordinary_options.pop("hidden_protection_password", None)
            try:
                return self.mount(source, portable_key, **ordinary_options)
            finally:
                del portable_key

        manager = self._system_manager
        opener = (
            getattr(manager, "mount_opaque", None)
            if manager is not None
            else None
        )
        if not callable(opener):
            raise MountUnavailableError(
                "Этот зашифрованный диск можно открыть только в Windows с WinSpd."
            )
        mounted = opener(source, password, **options)
        self._active_manager = manager
        self._mounted_container = source
        return str(mounted)

    def unmount(self) -> None:
        manager = self._selected_active_manager()
        if manager is None:
            return
        manager.unmount()
        if _manager_drive(manager) is None:
            self._active_manager = None
            self._mounted_container = None

    def inspect_mounted_disk(self) -> Any:
        manager = self._require_system_manager()
        return manager.inspect_mounted_disk()

    def resize_mounted_disk(self, *args: object, **kwargs: object) -> str:
        manager = self._require_system_manager()
        return str(manager.resize_mounted_disk(*args, **kwargs))

    def change_mounted_disk_algorithm(
        self,
        *args: object,
        **kwargs: object,
    ) -> str:
        manager = self._require_system_manager()
        changer = getattr(manager, "change_mounted_disk_algorithm", None)
        if not callable(changer):
            raise MountUnavailableError(
                "Изменение метода шифрования этого диска недоступно."
            )
        return str(changer(*args, **kwargs))

    def change_opaque_password(self, *args: object, **kwargs: object) -> Path:
        manager = self._require_system_manager()
        changer = getattr(manager, "change_opaque_password", None)
        if not callable(changer):
            raise MountUnavailableError(
                "Смена пароля этого зашифрованного диска недоступна."
            )
        return Path(changer(*args, **kwargs)).resolve()

    def _require_system_manager(self) -> Any:
        manager = self._selected_active_manager()
        if manager is None or manager is not self._system_manager:
            raise MountUnavailableError(
                "Операция доступна только для виртуального диска Windows."
            )
        return manager

    def _recover_active_manager(self) -> None:
        system = self._system_manager
        if system is not None and _manager_drive(system) is not None:
            self._active_manager = system
            value = getattr(system, "mounted_container", None)
            self._mounted_container = (
                Path(value).resolve() if value is not None else None
            )

    def _selected_active_manager(self) -> object | None:
        manager = self._active_manager
        if manager is not None:
            if _manager_drive(manager) is not None:
                return manager
            self._active_manager = None
            self._mounted_container = None
        self._recover_active_manager()
        return self._active_manager


def _manager_drive(manager: object) -> str | None:
    value = getattr(manager, "mounted_drive", None)
    return str(value) if value is not None else None
