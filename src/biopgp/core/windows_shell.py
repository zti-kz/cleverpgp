from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from biopgp.core.errors import MountUnavailableError

SYSTEM_DRIVE_MENU_KEY = (
    r"Software\Classes\Drive\shell\CleverPGP.SystemMenu"
)
_SHELL_ASSOCIATIONS_CHANGED = 0x08000000
_SHELL_NOTIFY_IDLIST = 0x0000


@dataclass(frozen=True, slots=True)
class RegistryValue:
    subkey: str
    name: str
    value: str | int
    kind: str = "string"


def application_command_prefix() -> tuple[str, ...]:
    executable = Path(sys.executable).resolve()
    if getattr(sys, "frozen", False):
        return (str(executable),)
    pythonw = executable.with_name("pythonw.exe")
    if sys.platform == "win32" and pythonw.is_file():
        executable = pythonw
    return (str(executable), "-m", "biopgp")


def drive_context_menu_values(
    drive: str,
    *,
    command_prefix: Iterable[str],
    icon_path: Path,
    open_label: str,
    info_label: str,
    settings_label: str,
    resize_label: str | None,
    unmount_label: str,
    password_label: str | None = None,
    algorithm_label: str | None = None,
) -> tuple[RegistryValue, ...]:
    normalized_drive = _normalize_drive(drive)
    prefix = tuple(str(value) for value in command_prefix)
    if not prefix:
        raise ValueError("Application command prefix must not be empty.")
    icon = f"{Path(icon_path).resolve()},0"
    applies_to = f'System.ItemPathDisplay:="{normalized_drive}\\' + '"'
    explorer = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "explorer.exe"
    open_command = subprocess.list2cmdline([str(explorer), "%1"])
    unmount_command = subprocess.list2cmdline(
        [*prefix, "--unmount", "%1"]
    )
    settings_command = subprocess.list2cmdline(
        [*prefix, "--settings", "%1"]
    )
    password_command = subprocess.list2cmdline(
        [*prefix, "--change-disk-password", "%1"]
    )
    algorithm_command = subprocess.list2cmdline(
        [*prefix, "--change-disk-algorithm", "%1"]
    )
    resize_command = subprocess.list2cmdline(
        [*prefix, "--resize-drive", "%1"]
    )
    info_command = subprocess.list2cmdline(
        [*prefix, "--disk-info", "%1"]
    )
    open_key = SYSTEM_DRIVE_MENU_KEY + r"\shell\Open"
    info_key = SYSTEM_DRIVE_MENU_KEY + r"\shell\Info"
    settings_key = SYSTEM_DRIVE_MENU_KEY + r"\shell\Settings"
    password_key = SYSTEM_DRIVE_MENU_KEY + r"\shell\Password"
    algorithm_key = SYSTEM_DRIVE_MENU_KEY + r"\shell\Algorithm"
    resize_key = SYSTEM_DRIVE_MENU_KEY + r"\shell\Resize"
    unmount_key = SYSTEM_DRIVE_MENU_KEY + r"\shell\Unmount"
    values = [
        RegistryValue(SYSTEM_DRIVE_MENU_KEY, "MUIVerb", "Clever PGP"),
        RegistryValue(SYSTEM_DRIVE_MENU_KEY, "Icon", icon),
        RegistryValue(SYSTEM_DRIVE_MENU_KEY, "AppliesTo", applies_to),
        RegistryValue(SYSTEM_DRIVE_MENU_KEY, "SubCommands", ""),
        RegistryValue(open_key, "MUIVerb", open_label),
        RegistryValue(open_key, "Icon", icon),
        RegistryValue(open_key + r"\command", "", open_command),
        RegistryValue(info_key, "MUIVerb", info_label),
        RegistryValue(info_key, "Icon", icon),
        RegistryValue(info_key + r"\command", "", info_command),
        RegistryValue(settings_key, "MUIVerb", settings_label),
        RegistryValue(settings_key, "Icon", icon),
        RegistryValue(settings_key + r"\command", "", settings_command),
    ]
    if password_label:
        values.extend(
            [
                RegistryValue(password_key, "MUIVerb", password_label),
                RegistryValue(password_key, "Icon", icon),
                RegistryValue(
                    password_key + r"\command",
                    "",
                    password_command,
                ),
            ]
        )
    if algorithm_label:
        values.extend(
            [
                RegistryValue(algorithm_key, "MUIVerb", algorithm_label),
                RegistryValue(algorithm_key, "Icon", icon),
                RegistryValue(
                    algorithm_key + r"\command",
                    "",
                    algorithm_command,
                ),
            ]
        )
    if resize_label:
        values.extend(
            [
                RegistryValue(resize_key, "MUIVerb", resize_label),
                RegistryValue(resize_key, "Icon", icon),
                RegistryValue(resize_key + r"\command", "", resize_command),
            ]
        )
    values.extend(
        [
            RegistryValue(unmount_key, "MUIVerb", unmount_label),
            RegistryValue(unmount_key, "Icon", icon),
            RegistryValue(unmount_key, "CommandFlags", 0x20, "dword"),
            RegistryValue(unmount_key + r"\command", "", unmount_command),
        ]
    )
    return tuple(values)


class WindowsDriveContextMenu:
    """Per-user Explorer menu restricted to the active Clever PGP drive."""

    def __init__(
        self,
        *,
        registry: Any = None,
        notifier: Callable[[], None] | None = None,
        command_prefix: Iterable[str] | None = None,
        icon_path: Path | None = None,
    ) -> None:
        self._registry = registry
        self._notifier = notifier
        self._command_prefix = tuple(command_prefix or application_command_prefix())
        self._icon_path = Path(icon_path or self._command_prefix[0]).resolve()

    def register(
        self,
        drive: str,
        *,
        open_label: str,
        info_label: str,
        settings_label: str,
        resize_label: str | None,
        unmount_label: str,
        password_label: str | None = None,
        algorithm_label: str | None = None,
    ) -> None:
        if sys.platform != "win32" and self._registry is None:
            raise MountUnavailableError(
                "Контекстное меню виртуального диска доступно только в Windows."
            )
        registry = self._registry_module()
        self._delete_existing(registry)
        values = drive_context_menu_values(
            drive,
            command_prefix=self._command_prefix,
            icon_path=self._icon_path,
            open_label=open_label,
            info_label=info_label,
            settings_label=settings_label,
            resize_label=resize_label,
            unmount_label=unmount_label,
            password_label=password_label,
            algorithm_label=algorithm_label,
        )
        view = getattr(registry, "KEY_WOW64_64KEY", 0)
        for item in values:
            with registry.CreateKeyEx(
                registry.HKEY_CURRENT_USER,
                item.subkey,
                0,
                registry.KEY_WRITE | view,
            ) as key:
                value_type = (
                    registry.REG_DWORD if item.kind == "dword" else registry.REG_SZ
                )
                registry.SetValueEx(key, item.name, 0, value_type, item.value)
        self._notify_shell()

    def remove(self) -> None:
        if sys.platform != "win32" and self._registry is None:
            return
        registry = self._registry_module()
        self._delete_existing(registry)
        self._notify_shell()

    def _delete_existing(self, registry: Any) -> None:
        view = getattr(registry, "KEY_WOW64_64KEY", 0)
        _delete_registry_tree(
            registry,
            registry.HKEY_CURRENT_USER,
            SYSTEM_DRIVE_MENU_KEY,
            view=view,
        )

    def _registry_module(self) -> Any:
        if self._registry is None:
            import winreg

            self._registry = winreg
        return self._registry

    def _notify_shell(self) -> None:
        if self._notifier is not None:
            self._notifier()
            return
        if sys.platform == "win32":
            ctypes.windll.shell32.SHChangeNotify(
                _SHELL_ASSOCIATIONS_CHANGED,
                _SHELL_NOTIFY_IDLIST,
                None,
                None,
            )


def _delete_registry_tree(
    registry: Any,
    root: Any,
    subkey: str,
    *,
    view: int,
) -> None:
    try:
        with registry.OpenKey(
            root,
            subkey,
            0,
            registry.KEY_READ | registry.KEY_WRITE | view,
        ) as key:
            children: list[str] = []
            index = 0
            while True:
                try:
                    children.append(registry.EnumKey(key, index))
                    index += 1
                except OSError:
                    break
    except FileNotFoundError:
        return
    for child in children:
        _delete_registry_tree(
            registry,
            root,
            subkey + "\\" + child,
            view=view,
        )
    try:
        if hasattr(registry, "DeleteKeyEx"):
            registry.DeleteKeyEx(root, subkey, view, 0)
        else:
            registry.DeleteKey(root, subkey)
    except FileNotFoundError:
        pass


def _normalize_drive(drive: str) -> str:
    normalized = str(drive).strip().upper().rstrip("\\/")
    if len(normalized) == 1:
        normalized += ":"
    if (
        len(normalized) != 2
        or normalized[1] != ":"
        or not normalized[0].isalpha()
    ):
        raise ValueError("Invalid disk drive letter.")
    return normalized
