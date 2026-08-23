from __future__ import annotations

from pathlib import Path

from biopgp.core.windows_shell import (
    SYSTEM_DRIVE_MENU_KEY,
    WindowsDriveContextMenu,
    drive_context_menu_values,
)


class FakeKey:
    def __init__(self, path: str) -> None:
        self.path = path

    def __enter__(self) -> FakeKey:
        return self

    def __exit__(self, *_args: object) -> None:
        pass


class FakeRegistry:
    HKEY_CURRENT_USER = object()
    KEY_READ = 1
    KEY_WRITE = 2
    KEY_WOW64_64KEY = 4
    REG_SZ = 1
    REG_DWORD = 4

    def __init__(self) -> None:
        self.keys: dict[str, dict[str, tuple[int, str | int]]] = {}

    def CreateKeyEx(
        self,
        _root: object,
        subkey: str,
        _reserved: int,
        _access: int,
    ) -> FakeKey:
        self.keys.setdefault(subkey, {})
        return FakeKey(subkey)

    def SetValueEx(
        self,
        key: FakeKey,
        name: str,
        _reserved: int,
        value_type: int,
        value: str | int,
    ) -> None:
        self.keys[key.path][name] = (value_type, value)

    def OpenKey(
        self,
        _root: object,
        subkey: str,
        _reserved: int,
        _access: int,
    ) -> FakeKey:
        prefix = subkey + "\\"
        if subkey not in self.keys and not any(
            candidate.startswith(prefix) for candidate in self.keys
        ):
            raise FileNotFoundError(subkey)
        return FakeKey(subkey)

    def EnumKey(self, key: FakeKey, index: int) -> str:
        prefix = key.path + "\\"
        children = sorted(
            {
                candidate[len(prefix) :].split("\\", 1)[0]
                for candidate in self.keys
                if candidate.startswith(prefix)
            }
        )
        if index >= len(children):
            raise OSError("No more keys")
        return children[index]

    def DeleteKeyEx(
        self,
        _root: object,
        subkey: str,
        _view: int,
        _reserved: int,
    ) -> None:
        if subkey not in self.keys:
            raise FileNotFoundError(subkey)
        if any(candidate.startswith(subkey + "\\") for candidate in self.keys):
            raise OSError("Key has children")
        del self.keys[subkey]


def test_drive_context_menu_is_restricted_to_selected_drive(tmp_path: Path) -> None:
    executable = tmp_path / "CleverPGP.exe"
    values = drive_context_menu_values(
        "z:\\",
        command_prefix=(str(executable),),
        icon_path=executable,
        open_label="Open encrypted disk",
        info_label="Disk information",
        settings_label="Access settings",
        resize_label="Increase disk",
        unmount_label="Unmount encrypted disk",
    )
    lookup = {(item.subkey, item.name): item.value for item in values}

    assert lookup[(SYSTEM_DRIVE_MENU_KEY, "AppliesTo")] == (
        'System.ItemPathDisplay:="Z:\\' + '"'
    )
    unmount_command = lookup[
        (SYSTEM_DRIVE_MENU_KEY + r"\shell\Unmount\command", "")
    ]
    assert str(executable) in str(unmount_command)
    assert "--unmount" in str(unmount_command)
    assert "%1" in str(unmount_command)
    assert "cmd.exe" not in str(unmount_command).lower()
    settings_command = lookup[
        (SYSTEM_DRIVE_MENU_KEY + r"\shell\Settings\command", "")
    ]
    assert "--settings" in str(settings_command)
    assert "%1" in str(settings_command)
    assert "cmd.exe" not in str(settings_command).lower()
    info_command = lookup[
        (SYSTEM_DRIVE_MENU_KEY + r"\shell\Info\command", "")
    ]
    assert "--disk-info" in str(info_command)
    assert "%1" in str(info_command)
    assert "cmd.exe" not in str(info_command).lower()
    resize_command = lookup[
        (SYSTEM_DRIVE_MENU_KEY + r"\shell\Resize\command", "")
    ]
    assert "--resize-drive" in str(resize_command)
    assert "%1" in str(resize_command)
    assert "cmd.exe" not in str(resize_command).lower()


def test_context_menu_registers_and_removes_only_its_own_tree(
    tmp_path: Path,
) -> None:
    registry = FakeRegistry()
    registry.keys[r"Software\Classes\Drive\shell\Unrelated"] = {
        "": (registry.REG_SZ, "Keep")
    }
    notifications: list[bool] = []
    executable = tmp_path / "CleverPGP.exe"
    menu = WindowsDriveContextMenu(
        registry=registry,
        notifier=lambda: notifications.append(True),
        command_prefix=(str(executable),),
        icon_path=executable,
    )

    menu.register(
        "Y:",
        open_label="Открыть зашифрованный диск",
        info_label="Сведения о диске",
        settings_label="Настройки доступа",
        resize_label="Увеличить диск",
        unmount_label="Отключить зашифрованный диск",
    )

    assert SYSTEM_DRIVE_MENU_KEY in registry.keys
    assert registry.keys[SYSTEM_DRIVE_MENU_KEY]["AppliesTo"][1] == (
        'System.ItemPathDisplay:="Y:\\' + '"'
    )
    assert notifications == [True]

    menu.remove()

    assert not any(
        key == SYSTEM_DRIVE_MENU_KEY
        or key.startswith(SYSTEM_DRIVE_MENU_KEY + "\\")
        for key in registry.keys
    )
    assert r"Software\Classes\Drive\shell\Unrelated" in registry.keys
    assert notifications == [True, True]


def test_hidden_disk_menu_omits_unsupported_resize_action(tmp_path: Path) -> None:
    executable = tmp_path / "CleverPGP.exe"
    values = drive_context_menu_values(
        "H:",
        command_prefix=(str(executable),),
        icon_path=executable,
        open_label="Open",
        info_label="Info",
        settings_label="Settings",
        resize_label=None,
        unmount_label="Unmount",
    )

    assert not any("\\Resize" in value.subkey for value in values)
    assert any("\\Unmount" in value.subkey for value in values)


def test_installer_and_development_menu_include_compact_disk_information() -> None:
    project = Path(__file__).resolve().parents[1]
    installer = (project / "packaging" / "biopgp.iss").read_text(encoding="utf-8")
    development = (project / "install_context_menu.ps1").read_text(
        encoding="utf-8"
    )

    for source in (installer, development):
        assert "Сведения о диске" in source
        assert "--disk-info" in source
