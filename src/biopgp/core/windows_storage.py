from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from biopgp.core.errors import MountUnavailableError
from biopgp.core.disk_control import (
    DiskControlRecord,
    DiskControlStore,
)
from biopgp.core.disk_host import WinSpdHostManager
from biopgp.core.winspd import (
    WinSpdLibrary,
    create_windows_block_volume,
    open_windows_block_volume,
)
from biopgp.core.windows_shell import WindowsDriveContextMenu


@dataclass(frozen=True, slots=True)
class WindowsDiskInfo:
    number: int
    friendly_name: str
    serial_number: str
    unique_id: str
    size: int
    partition_style: str


def _powershell_executable() -> str:
    return "powershell.exe"


def winspd_driver_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import winreg

        for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\WinSpd",
                    0,
                    winreg.KEY_READ | view,
                ) as key:
                    install_dir = Path(str(winreg.QueryValueEx(key, "InstallDir")[0]))
                if (install_dir / "sys" / "winspd-x64.dll").is_file():
                    return True
            except OSError:
                continue
    except (ImportError, OSError):
        return False
    return False


def _run_powershell(script: str, *, timeout: float = 30.0) -> str:
    result = subprocess.run(
        [
            _powershell_executable(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode:
        message = result.stderr.strip() or result.stdout.strip()
        raise MountUnavailableError(
            message or f"Команда управления диском завершилась с кодом {result.returncode}."
        )
    return result.stdout.strip()


def list_windows_disks() -> list[WindowsDiskInfo]:
    raw = _run_powershell(
        "Get-Disk | Select-Object Number,FriendlyName,SerialNumber,UniqueId,Size,"
        "PartitionStyle | ConvertTo-Json -Compress"
    )
    if not raw:
        return []
    decoded = json.loads(raw)
    records = decoded if isinstance(decoded, list) else [decoded]
    result: list[WindowsDiskInfo] = []
    for record in records:
        if not isinstance(record, dict):
            raise MountUnavailableError("Windows вернула некорректный список дисков.")
        result.append(
            WindowsDiskInfo(
                number=int(record["Number"]),
                friendly_name=str(record.get("FriendlyName") or ""),
                serial_number=str(record.get("SerialNumber") or ""),
                unique_id=str(record.get("UniqueId") or ""),
                size=int(record["Size"]),
                partition_style=str(record.get("PartitionStyle") or ""),
            )
        )
    return result


def select_new_cleverpgp_disk(
    before: list[WindowsDiskInfo],
    after: list[WindowsDiskInfo],
    *,
    expected_size: int,
) -> WindowsDiskInfo:
    previous_numbers = {disk.number for disk in before}
    new_disks = [disk for disk in after if disk.number not in previous_numbers]
    matching = [
        disk
        for disk in new_disks
        if disk.size == expected_size
        and any(
            marker in disk.friendly_name.casefold()
            for marker in ("cleverpgp", "winspd")
        )
    ]
    if len(matching) != 1:
        descriptions = ", ".join(
            f"№{disk.number} {disk.friendly_name!r} {disk.size} байт"
            for disk in new_disks
        ) or "новых дисков нет"
        raise MountUnavailableError(
            "Нельзя однозначно определить временный диск Clever PGP: "
            + descriptions
        )
    candidate = matching[0]
    if candidate.partition_style.upper() not in ("MBR", "RAW"):
        raise MountUnavailableError(
            "Временный диск имеет неожиданную таблицу разделов."
        )
    return candidate


def wait_for_new_cleverpgp_disk(
    before: list[WindowsDiskInfo],
    *,
    expected_size: int,
    timeout: float = 15.0,
) -> WindowsDiskInfo:
    deadline = time.monotonic() + timeout
    last_error: MountUnavailableError | None = None
    while time.monotonic() < deadline:
        try:
            return select_new_cleverpgp_disk(
                before,
                list_windows_disks(),
                expected_size=expected_size,
            )
        except MountUnavailableError as error:
            last_error = error
            time.sleep(0.2)
    raise last_error or MountUnavailableError(
        "Временный системный диск Clever PGP не появился."
    )


def format_new_cleverpgp_disk(
    disk: WindowsDiskInfo,
    *,
    expected_size: int,
    file_system: str = "NTFS",
    label: str = "Clever PGP",
) -> str:
    normalized_file_system = file_system.upper()
    if normalized_file_system not in ("NTFS", "EXFAT"):
        raise ValueError("Test file system must be NTFS or exFAT.")
    if disk.size != expected_size or disk.number < 0:
        raise MountUnavailableError("Параметры временного диска изменились.")
    if not any(
        marker in disk.friendly_name.casefold()
        for marker in ("cleverpgp", "winspd")
    ):
        raise MountUnavailableError("Выбранный диск не принадлежит Clever PGP.")
    normalized_label = label.strip() or "Clever PGP"
    if len(normalized_label) > 32 or any(
        ord(character) < 32 for character in normalized_label
    ):
        raise ValueError("Disk label contains unsupported characters.")
    encoded_label = base64.b64encode(normalized_label.encode("utf-8")).decode("ascii")

    script = f"""
$ErrorActionPreference = 'Stop'
$label = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_label}'))
$disk = Get-Disk -Number {disk.number}
if ([UInt64]$disk.Size -ne [UInt64]{expected_size}) {{ throw 'Disk size changed.' }}
if ($disk.FriendlyName -notmatch 'CleverPGP|WinSpd') {{ throw 'Disk identity changed.' }}
if ($disk.PartitionStyle -ne 'MBR') {{ throw 'Expected an MBR test disk.' }}
$partitions = @(Get-Partition -DiskNumber {disk.number} | Where-Object {{ $_.Type -ne 'Reserved' }})
if ($partitions.Count -ne 1) {{ throw 'Expected exactly one data partition.' }}
$partition = $partitions[0]
if ([UInt64]$partition.Offset -ne [UInt64]1048576) {{ throw 'Unexpected partition offset.' }}
if (-not $partition.DriveLetter) {{
    $partition | Add-PartitionAccessPath -AssignDriveLetter
    $partition = Get-Partition -DiskNumber {disk.number} -PartitionNumber $partition.PartitionNumber
}}
$partition | Format-Volume -FileSystem {normalized_file_system} -NewFileSystemLabel $label -AllocationUnitSize 4096 -Force -Confirm:$false | Out-Null
$partition = Get-Partition -DiskNumber {disk.number} -PartitionNumber $partition.PartitionNumber
if (-not $partition.DriveLetter) {{ throw 'Windows did not assign a drive letter.' }}
[PSCustomObject]@{{ DriveLetter = [String]$partition.DriveLetter }} | ConvertTo-Json -Compress
"""
    raw = _run_powershell(script, timeout=120.0)
    decoded = json.loads(raw)
    drive_letter = str(decoded.get("DriveLetter") or "").upper()
    if len(drive_letter) != 1 or not drive_letter.isalpha():
        raise MountUnavailableError("Windows не назначила букву тестовому диску.")
    return f"{drive_letter}:"


def format_ephemeral_cleverpgp_disk(
    disk: WindowsDiskInfo,
    *,
    expected_size: int,
    file_system: str = "NTFS",
) -> str:
    return format_new_cleverpgp_disk(
        disk,
        expected_size=expected_size,
        file_system=file_system,
        label="CleverPGP Check",
    )


def disk_drive_letters(number: int) -> list[str]:
    if not isinstance(number, int) or number < 0:
        raise ValueError("Disk number must be non-negative.")
    raw = _run_powershell(
        f"@(Get-Partition -DiskNumber {number} | Where-Object {{ $_.DriveLetter }} | "
        "ForEach-Object { [String]$_.DriveLetter }) | ConvertTo-Json -Compress"
    )
    if not raw:
        return []
    decoded = json.loads(raw)
    values = decoded if isinstance(decoded, list) else [decoded]
    letters: list[str] = []
    for value in values:
        letter = str(value).upper()
        if len(letter) == 1 and letter.isalpha():
            letters.append(f"{letter}:")
    return letters


def wait_for_drive_letter(number: int, *, timeout: float = 15.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        letters = disk_drive_letters(number)
        if len(letters) == 1:
            return letters[0]
        if len(letters) > 1:
            raise MountUnavailableError(
                "Системный диск Clever PGP получил несколько букв."
            )
        time.sleep(0.2)
    raise MountUnavailableError(
        "Windows не назначила букву системному диску. Возможно, он ещё не отформатирован."
    )


def wait_for_disk_removal(number: int, *, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(disk.number != number for disk in list_windows_disks()):
            return
        time.sleep(0.2)
    raise MountUnavailableError("Временный системный диск не отключился.")


class WindowsSystemDiskManager:
    """Create, mount and detach Clever PGP disks backed by the Windows file system."""

    def __init__(
        self,
        process_manager: WinSpdHostManager | None = None,
        *,
        control_store: DiskControlStore | None = None,
        context_menu: WindowsDriveContextMenu | None = None,
        drive_available: Callable[[str], bool] | None = None,
        recover_existing: bool = True,
    ) -> None:
        self._process_manager = process_manager or WinSpdHostManager()
        self._control_store = control_store or DiskControlStore()
        self._context_menu = context_menu or WindowsDriveContextMenu()
        self._drive_available = drive_available or _drive_path_available
        self._recovery_enabled = recover_existing
        self._control_record: DiskControlRecord | None = None
        self._disk: WindowsDiskInfo | None = None
        self._drive: str | None = None
        if recover_existing:
            self._recover_existing_control_record()

    @property
    def mounted_drive(self) -> str | None:
        if self._process_manager.running:
            return self._drive
        if self._recovery_enabled and self._control_record is None:
            self._recover_existing_control_record()
            if self._control_record is not None:
                return self._drive
        if self._control_record is not None and self._drive is not None:
            try:
                self._control_store.send(
                    self._control_record,
                    "ping",
                    timeout=0.35,
                )
                return self._drive
            except MountUnavailableError:
                # A host can be briefly busy while Windows flushes the volume.
                # Keep recoverable state while its assigned drive still exists.
                if self._drive_available(self._drive):
                    return self._drive
        self._clear_control_record()
        self._disk = None
        self._drive = None
        return None

    def create_and_mount(
        self,
        container_path: Path,
        master_key: bytes,
        *,
        logical_capacity: int,
        label: str,
        file_system: str = "NTFS",
        overwrite: bool = False,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> str:
        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый системный диск Clever PGP."
            )
        library = WinSpdLibrary()

        def creation_progress(completed: int, total: int) -> None:
            if progress is not None:
                fraction = completed / total if total else 1.0
                progress(
                    5 + round(fraction * 55),
                    "Подготовка зашифрованных блоков",
                )

        if progress is not None:
            progress(3, "Проверка параметров системного диска")
        volume = create_windows_block_volume(
            container_path,
            master_key,
            logical_capacity=logical_capacity,
            library=library,
            label=label,
            overwrite=overwrite,
            progress=creation_progress,
        )
        volume.close()
        before = list_windows_disks()
        try:
            self._process_manager.start(
                container_path,
                master_key,
                device_name=None,
                progress=(
                    None
                    if progress is None
                    else lambda value, message: progress(
                        60 + round(value * 0.2), message
                    )
                ),
            )
            disk = wait_for_new_cleverpgp_disk(
                before,
                expected_size=logical_capacity,
            )
            if progress is not None:
                progress(85, "Форматирование системного диска")
            drive = format_new_cleverpgp_disk(
                disk,
                expected_size=logical_capacity,
                file_system=file_system,
                label=label,
            )
        except Exception:
            self._process_manager.stop()
            raise
        try:
            control_record = self._publish_control_record(
                drive,
                context_menu_labels=context_menu_labels,
            )
        except Exception:
            self._process_manager.stop()
            wait_for_disk_removal(disk.number)
            raise
        self._disk = disk
        self._drive = drive
        self._control_record = control_record
        if progress is not None:
            progress(100, "Системный диск готов")
        return drive

    def mount(
        self,
        container_path: Path,
        master_key: bytes,
        *,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> str:
        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый системный диск Clever PGP."
            )
        volume = open_windows_block_volume(container_path, master_key)
        try:
            logical_capacity = volume.logical_capacity
        finally:
            volume.close()
        before = list_windows_disks()
        try:
            self._process_manager.start(
                container_path,
                master_key,
                device_name=None,
                progress=progress,
            )
            disk = wait_for_new_cleverpgp_disk(
                before,
                expected_size=logical_capacity,
            )
            drive = wait_for_drive_letter(disk.number)
        except Exception:
            self._process_manager.stop()
            raise
        try:
            control_record = self._publish_control_record(
                drive,
                context_menu_labels=context_menu_labels,
            )
        except Exception:
            self._process_manager.stop()
            wait_for_disk_removal(disk.number)
            raise
        self._disk = disk
        self._drive = drive
        self._control_record = control_record
        if progress is not None:
            progress(100, "Системный диск подключён")
        return drive

    def unmount(self) -> None:
        disk = self._disk
        drive = self._drive
        if self._process_manager.running:
            self._process_manager.stop()
            if disk is not None:
                wait_for_disk_removal(disk.number)
            elif drive is not None:
                wait_for_drive_removal(
                    drive,
                    drive_available=self._drive_available,
                )
        elif self._control_record is not None:
            self._control_store.send(self._control_record, "stop")
            if drive is not None:
                wait_for_drive_removal(
                    drive,
                    drive_available=self._drive_available,
                )
        self._clear_control_record()
        self._disk = None
        self._drive = None

    def _recover_existing_control_record(self) -> None:
        active: list[DiskControlRecord] = []
        stale: list[DiskControlRecord] = []
        for record in self._control_store.records():
            if not self._control_record_responds(record):
                stale.append(record)
            else:
                active.append(record)
        for record in stale:
            self._control_store.remove(record)
        if active:
            self._control_record = active[0]
            self._drive = active[0].drive
            return
        if stale:
            try:
                self._context_menu.remove()
            except OSError:
                pass

    def _control_record_responds(self, record: DiskControlRecord) -> bool:
        for attempt in range(2):
            try:
                self._control_store.send(record, "ping", timeout=0.5)
                return True
            except MountUnavailableError:
                if attempt == 0:
                    time.sleep(0.05)
        return False

    def _publish_control_record(
        self,
        drive: str,
        *,
        context_menu_labels: tuple[str, ...] | None,
    ) -> DiskControlRecord | None:
        endpoint = getattr(self._process_manager, "control_endpoint", None)
        process_id = getattr(self._process_manager, "process_id", None)
        if endpoint is None or process_id is None:
            return None
        record = self._control_store.publish(
            endpoint,
            drive=drive,
            process_id=process_id,
        )
        if context_menu_labels is None:
            open_label = "Открыть зашифрованный диск"
            settings_label = "Настройки доступа"
            unmount_label = "Отключить зашифрованный диск"
        elif len(context_menu_labels) == 2:
            open_label, unmount_label = context_menu_labels
            settings_label = "Настройки доступа"
        elif len(context_menu_labels) == 3:
            open_label, settings_label, unmount_label = context_menu_labels
        else:
            raise ValueError("System disk context menu requires two or three labels.")
        try:
            self._context_menu.register(
                drive,
                open_label=open_label,
                settings_label=settings_label,
                unmount_label=unmount_label,
            )
        except OSError:
            pass
        return record

    def _clear_control_record(self) -> None:
        if self._control_record is None:
            return
        try:
            self._context_menu.remove()
        except OSError:
            pass
        self._control_store.remove(self._control_record)
        self._control_record = None


def wait_for_drive_removal(
    drive: str,
    *,
    timeout: float = 15.0,
    drive_available: Callable[[str], bool] | None = None,
) -> None:
    probe = drive_available or _drive_path_available
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not probe(drive):
            return
        time.sleep(0.05)
    raise MountUnavailableError(
        f"Системный диск {drive} не подтвердил безопасное отключение."
    )


def _drive_path_available(drive: str) -> bool:
    return Path(f"{drive}\\").exists()
