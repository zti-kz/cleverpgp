from __future__ import annotations

from pathlib import Path

from cleverpgp.core.windows_shell import (
    CONTAINER_OPEN_VERB_KEY,
    SYSTEM_DRIVE_MENU_KEY,
    WindowsDriveContextMenu,
    drive_context_menu_key,
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

    def DeleteValue(self, key: FakeKey, name: str) -> None:
        try:
            del self.keys[key.path][name]
        except KeyError as error:
            raise FileNotFoundError(name) from error


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
        algorithm_label="Change encryption method",
    )
    lookup = {(item.subkey, item.name): item.value for item in values}
    menu_key = drive_context_menu_key("Z:")

    assert lookup[(menu_key, "AppliesTo")] == (
        'System.ItemPathDisplay:="Z:\\' + '"'
    )
    unmount_command = lookup[
        (menu_key + r"\shell\Unmount\command", "")
    ]
    assert str(executable) in str(unmount_command)
    assert "--unmount" in str(unmount_command)
    assert "%1" in str(unmount_command)
    assert "cmd.exe" not in str(unmount_command).lower()
    settings_command = lookup[
        (menu_key + r"\shell\Settings\command", "")
    ]
    assert "--settings" in str(settings_command)
    assert "%1" in str(settings_command)
    assert "cmd.exe" not in str(settings_command).lower()
    info_command = lookup[
        (menu_key + r"\shell\Info\command", "")
    ]
    assert "--disk-info" in str(info_command)
    assert "%1" in str(info_command)
    assert "cmd.exe" not in str(info_command).lower()
    resize_command = lookup[
        (menu_key + r"\shell\Resize\command", "")
    ]
    assert "--resize-drive" in str(resize_command)
    assert "%1" in str(resize_command)
    assert "cmd.exe" not in str(resize_command).lower()
    algorithm_command = lookup[
        (menu_key + r"\shell\Algorithm\command", "")
    ]
    assert "--change-disk-algorithm" in str(algorithm_command)
    assert "%1" in str(algorithm_command)
    assert "cmd.exe" not in str(algorithm_command).lower()
    assert not any(r"\shell\Open" in item.subkey for item in values)


def test_context_menu_registers_and_removes_only_its_own_tree(
    tmp_path: Path,
) -> None:
    registry = FakeRegistry()
    registry.keys[r"Software\Classes\Drive\shell\Unrelated"] = {
        "": (registry.REG_SZ, "Keep")
    }
    registry.keys[CONTAINER_OPEN_VERB_KEY] = {
        "LegacyDisable": (registry.REG_SZ, "")
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
        algorithm_label="Изменить метод шифрования",
    )

    menu_key = drive_context_menu_key("Y:")
    assert menu_key in registry.keys
    assert registry.keys[menu_key]["AppliesTo"][1] == (
        'System.ItemPathDisplay:="Y:\\' + '"'
    )
    assert notifications == [True]
    assert "LegacyDisable" not in registry.keys[CONTAINER_OPEN_VERB_KEY]

    menu.remove()

    assert not any(
        key == menu_key or key.startswith(menu_key + "\\")
        for key in registry.keys
    )
    assert r"Software\Classes\Drive\shell\Unrelated" in registry.keys
    assert notifications == [True, True]


def test_context_menus_for_two_drives_do_not_delete_each_other(
    tmp_path: Path,
) -> None:
    registry = FakeRegistry()
    executable = tmp_path / "CleverPGP.exe"
    first = WindowsDriveContextMenu(
        registry=registry,
        notifier=lambda: None,
        command_prefix=(str(executable),),
        icon_path=executable,
    )
    second = WindowsDriveContextMenu(
        registry=registry,
        notifier=lambda: None,
        command_prefix=(str(executable),),
        icon_path=executable,
    )

    for menu, drive in ((first, "D:"), (second, "F:")):
        menu.register(
            drive,
            open_label="Open",
            info_label="Info",
            settings_label="Settings",
            resize_label="Resize",
            unmount_label="Unmount",
        )

    first_key = drive_context_menu_key("D:")
    second_key = drive_context_menu_key("F:")
    assert first_key in registry.keys
    assert second_key in registry.keys

    second.remove("F:")

    assert first_key in registry.keys
    assert second_key not in registry.keys


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
        password_label="Change disk password",
    )

    assert not any("\\Resize" in value.subkey for value in values)
    assert not any("\\Algorithm" in value.subkey for value in values)
    password_command = next(
        value.value
        for value in values
        if value.subkey.endswith(r"\Password\command")
    )
    assert "--change-disk-password" in str(password_command)
    assert "%1" in str(password_command)
    assert any("\\Unmount" in value.subkey for value in values)


def test_disk_management_menu_is_created_only_for_an_active_drive() -> None:
    project = Path(__file__).resolve().parents[1]
    installer = (project / "packaging" / "cleverpgp.iss").read_text(encoding="utf-8")
    development = (project / "install_context_menu.ps1").read_text(
        encoding="utf-8"
    )
    runtime = (project / "src" / "cleverpgp" / "core" / "windows_shell.py").read_text(
        encoding="utf-8"
    )

    assert 'Subkey: "Software\\Classes\\Drive\\shell\\CleverPGP.Menu"; ValueType: none; Flags: deletekey' in installer
    assert "$LegacyDriveVerb" in development
    assert "--disk-info" in runtime
    assert r"\shell\Open" not in runtime


def test_file_menu_uses_explicit_actions_and_excludes_cleverpgp_formats() -> None:
    project = Path(__file__).resolve().parents[1]
    installer = (project / "packaging" / "cleverpgp.iss").read_text(encoding="utf-8")
    development = (project / "install_context_menu.ps1").read_text(
        encoding="utf-8"
    )

    for source in (installer, development):
        assert "--shell encrypt" in source
        assert "--shell decrypt" in source
        assert "--secure-delete" in source
        assert "Безвозвратно удалить файл" in source
        assert 'System.FileExtension:=' in source
        assert '.cpgp' in source
        assert '.cpgv' in source
        assert '.cpgk' in source
        assert '.cpgx' in source
        assert "CleverPGP.Decrypt" in source


def test_public_key_association_imports_from_explorer() -> None:
    project = Path(__file__).resolve().parents[1]
    installer = (project / "packaging" / "cleverpgp.iss").read_text(encoding="utf-8")
    development = (project / "install_context_menu.ps1").read_text(
        encoding="utf-8"
    )
    uninstaller = (project / "uninstall_context_menu.ps1").read_text(
        encoding="utf-8"
    )

    for source in (installer, development):
        assert "CleverPGP.PublicKey" in source
        assert ".cpgk" in source
        assert "--import-key" in source
    assert ".cpgk" in uninstaller
    assert "CleverPGP.PublicKey" in uninstaller


def test_uninstaller_offers_to_keep_or_remove_only_local_profile() -> None:
    project = Path(__file__).resolve().parents[1]
    installer = (project / "packaging" / "cleverpgp.iss").read_text(encoding="utf-8")

    assert "function InitializeUninstall(): Boolean;" in installer
    assert "MB_YESNOCANCEL" in installer
    assert "--shutdown-for-uninstall" in installer
    assert "ShutdownResult <> 0" in installer
    assert "--purge-local-profile" in installer
    assert "PurgeResult <> 0" in installer
    assert "DirExists(ProfilePath)" in installer
    assert "Удаление программы остановлено" in installer
    assert 'Name: "{localappdata}\\CleverPGP"' not in installer
    assert 'Name: "*.cpgv"' not in installer
    assert 'Name: "*.cpgp"' not in installer


def test_installer_selects_application_language_before_first_launch() -> None:
    project = Path(__file__).resolve().parents[1]
    installer = (project / "packaging" / "cleverpgp.iss").read_text(
        encoding="utf-8"
    )

    assert "CreateInputOptionPage" in installer
    assert "AppLanguagePage.Add('Русский')" in installer
    assert "AppLanguagePage.Add('Қазақша')" in installer
    assert "AppLanguagePage.Add('English')" in installer
    assert "AppLanguagePage.SelectedValueIndex := 0" in installer
    assert "--set-language {code:SelectedAppLanguage}" in installer
    assert "runasoriginaluser" in installer
