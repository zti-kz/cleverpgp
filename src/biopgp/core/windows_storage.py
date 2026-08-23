from __future__ import annotations

import base64
import json
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from biopgp.core.block_volume import LOGICAL_BLOCK_SIZE
from biopgp.core.disk_control import (
    DiskControlRecord,
    DiskControlStore,
)
from biopgp.core.disk_host import WinSpdHostManager
from biopgp.core.errors import MountUnavailableError
from biopgp.core.winspd import (
    MIN_WINDOWS_DISK_CAPACITY,
    WinSpdLibrary,
    create_windows_block_volume,
    open_windows_block_volume,
    resize_windows_block_volume,
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


@dataclass(frozen=True, slots=True)
class WindowsVolumeInfo:
    disk_number: int
    partition_number: int
    drive: str
    friendly_name: str
    serial_number: str
    unique_id: str
    bus_type: str
    disk_size: int
    partition_size: int
    partition_offset: int
    partition_style: str
    file_system: str
    data_partition_count: int
    is_boot: bool
    is_system: bool


@dataclass(frozen=True, slots=True)
class WindowsVolumeResizeResult:
    disk_size: int
    partition_size: int
    file_system: str


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


def inspect_windows_volume(drive: str) -> WindowsVolumeInfo:
    normalized_drive = _normalize_windows_drive(drive)
    drive_letter = normalized_drive[0]
    raw = _run_powershell(
        f"""
$ErrorActionPreference = 'Stop'
$partition = Get-Partition -DriveLetter '{drive_letter}'
if ($null -eq $partition) {{ throw 'Drive partition was not found.' }}
$disk = Get-Disk -Number $partition.DiskNumber
$volume = Get-Volume -DriveLetter '{drive_letter}'
$dataPartitions = @(Get-Partition -DiskNumber $disk.Number | Where-Object {{ $_.Type -ne 'Reserved' }})
[PSCustomObject]@{{
    DiskNumber = [Int32]$disk.Number
    PartitionNumber = [Int32]$partition.PartitionNumber
    DriveLetter = [String]$partition.DriveLetter
    FriendlyName = [String]$disk.FriendlyName
    SerialNumber = [String]$disk.SerialNumber
    UniqueId = [String]$disk.UniqueId
    BusType = [String]$disk.BusType
    DiskSize = [UInt64]$disk.Size
    PartitionSize = [UInt64]$partition.Size
    PartitionOffset = [UInt64]$partition.Offset
    PartitionStyle = [String]$disk.PartitionStyle
    FileSystem = [String]$volume.FileSystem
    DataPartitionCount = [Int32]$dataPartitions.Count
    IsBoot = [Boolean]$disk.IsBoot
    IsSystem = [Boolean]$disk.IsSystem
}} | ConvertTo-Json -Compress
"""
    )
    try:
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise TypeError("Windows volume information must be an object.")
        info = WindowsVolumeInfo(
            disk_number=int(decoded["DiskNumber"]),
            partition_number=int(decoded["PartitionNumber"]),
            drive=_normalize_windows_drive(str(decoded["DriveLetter"])),
            friendly_name=str(decoded.get("FriendlyName") or ""),
            serial_number=str(decoded.get("SerialNumber") or ""),
            unique_id=str(decoded.get("UniqueId") or ""),
            bus_type=str(decoded.get("BusType") or ""),
            disk_size=int(decoded["DiskSize"]),
            partition_size=int(decoded["PartitionSize"]),
            partition_offset=int(decoded["PartitionOffset"]),
            partition_style=str(decoded.get("PartitionStyle") or ""),
            file_system=str(decoded.get("FileSystem") or ""),
            data_partition_count=int(decoded["DataPartitionCount"]),
            is_boot=bool(decoded["IsBoot"]),
            is_system=bool(decoded["IsSystem"]),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise MountUnavailableError(
            "Windows вернула некорректные сведения о подключённом диске."
        ) from error
    if info.drive != normalized_drive:
        raise MountUnavailableError("Буква подключённого диска изменилась.")
    return info


def validate_cleverpgp_volume(
    info: WindowsVolumeInfo,
    *,
    expected_disk_size: int | None = None,
) -> None:
    if info.disk_number < 0 or info.partition_number <= 0:
        raise MountUnavailableError("Windows вернула некорректный номер раздела.")
    if expected_disk_size is not None and info.disk_size != expected_disk_size:
        raise MountUnavailableError("Размер системного диска Clever PGP изменился.")
    if not any(
        marker in info.friendly_name.casefold()
        for marker in ("cleverpgp", "winspd")
    ):
        raise MountUnavailableError("Выбранный диск не принадлежит Clever PGP.")
    if info.partition_style.upper() != "MBR":
        raise MountUnavailableError("Ожидалась таблица разделов MBR Clever PGP.")
    if info.is_boot or info.is_system:
        raise MountUnavailableError(
            "Системный или загрузочный диск Windows изменять запрещено."
        )
    if info.data_partition_count != 1:
        raise MountUnavailableError(
            "На диске Clever PGP ожидался ровно один раздел данных."
        )
    if info.partition_offset != 1024 * 1024:
        raise MountUnavailableError("Раздел Clever PGP имеет неожиданный отступ.")
    if (
        info.disk_size <= info.partition_offset
        or info.partition_size <= 0
        or info.partition_size > info.disk_size - info.partition_offset
    ):
        raise MountUnavailableError("Геометрия раздела Clever PGP некорректна.")


def validate_cleverpgp_ntfs_volume(
    info: WindowsVolumeInfo,
    *,
    expected_disk_size: int | None = None,
) -> None:
    validate_cleverpgp_volume(info, expected_disk_size=expected_disk_size)
    if info.file_system.upper() != "NTFS":
        raise MountUnavailableError(
            "Безопасное увеличение в Windows поддерживается только для NTFS. "
            "Диск exFAT можно использовать, но нельзя увеличивать без переформатирования."
        )


def extend_cleverpgp_ntfs_partition(
    info: WindowsVolumeInfo,
    *,
    expected_disk_size: int,
    expected_partition_size: int,
) -> WindowsVolumeResizeResult:
    """Extend only a revalidated Clever PGP NTFS partition to supported maximum."""

    validate_cleverpgp_ntfs_volume(info, expected_disk_size=expected_disk_size)
    if info.partition_size != expected_partition_size:
        raise MountUnavailableError("Размер раздела изменился до начала расширения.")
    if info.disk_size <= info.partition_offset + info.partition_size:
        raise MountUnavailableError("На диске нет подтверждённого свободного пространства.")

    encoded_identity = {
        name: base64.b64encode(value.encode("utf-8")).decode("ascii")
        for name, value in (
            ("friendly", info.friendly_name),
            ("serial", info.serial_number),
            ("unique", info.unique_id),
            ("bus", info.bus_type),
        )
    }
    drive_letter = info.drive[0]
    script = f"""
$ErrorActionPreference = 'Stop'
function Decode-Identity([String]$value) {{
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value))
}}
$expectedFriendly = Decode-Identity '{encoded_identity["friendly"]}'
$expectedSerial = Decode-Identity '{encoded_identity["serial"]}'
$expectedUnique = Decode-Identity '{encoded_identity["unique"]}'
$expectedBus = Decode-Identity '{encoded_identity["bus"]}'
$partition = Get-Partition -DriveLetter '{drive_letter}'
if ($null -eq $partition) {{ throw 'Drive partition was not found.' }}
if ([Int32]$partition.DiskNumber -ne [Int32]{info.disk_number}) {{ throw 'Disk number changed.' }}
if ([Int32]$partition.PartitionNumber -ne [Int32]{info.partition_number}) {{ throw 'Partition number changed.' }}
$disk = Get-Disk -Number {info.disk_number}
if ([UInt64]$disk.Size -ne [UInt64]{expected_disk_size}) {{ throw 'Disk size changed.' }}
if ([String]$disk.FriendlyName -ne $expectedFriendly) {{ throw 'Disk name changed.' }}
if ([String]$disk.SerialNumber -ne $expectedSerial) {{ throw 'Disk serial changed.' }}
if ([String]$disk.UniqueId -ne $expectedUnique) {{ throw 'Disk identity changed.' }}
if ([String]$disk.BusType -ne $expectedBus) {{ throw 'Disk bus changed.' }}
if ($disk.FriendlyName -notmatch 'CleverPGP|WinSpd') {{ throw 'Not a Clever PGP disk.' }}
if ($disk.PartitionStyle -ne 'MBR') {{ throw 'Expected an MBR disk.' }}
if ([Boolean]$disk.IsBoot -or [Boolean]$disk.IsSystem) {{ throw 'System disk is forbidden.' }}
$dataPartitions = @(Get-Partition -DiskNumber {info.disk_number} | Where-Object {{ $_.Type -ne 'Reserved' }})
if ($dataPartitions.Count -ne 1) {{ throw 'Expected exactly one data partition.' }}
if ([UInt64]$partition.Offset -ne [UInt64]{info.partition_offset}) {{ throw 'Partition offset changed.' }}
if ([UInt64]$partition.Size -ne [UInt64]{expected_partition_size}) {{ throw 'Partition size changed.' }}
$volume = Get-Volume -DriveLetter '{drive_letter}'
if ([String]$volume.FileSystem -ne 'NTFS') {{ throw 'Only NTFS can be extended safely.' }}
$supported = Get-PartitionSupportedSize -DiskNumber {info.disk_number} -PartitionNumber {info.partition_number}
if ([UInt64]$supported.SizeMax -le [UInt64]{expected_partition_size}) {{ throw 'No supported growth is available.' }}
if ([UInt64]$supported.SizeMax -gt ([UInt64]{expected_disk_size} - [UInt64]{info.partition_offset})) {{ throw 'Supported size exceeds disk geometry.' }}
Resize-Partition -DiskNumber {info.disk_number} -PartitionNumber {info.partition_number} -Size $supported.SizeMax -Confirm:$false
$updated = Get-Partition -DiskNumber {info.disk_number} -PartitionNumber {info.partition_number}
$updatedVolume = Get-Volume -DriveLetter '{drive_letter}'
if ([UInt64]$updated.Size -ne [UInt64]$supported.SizeMax) {{ throw 'Partition did not reach the supported size.' }}
if ([String]$updatedVolume.FileSystem -ne 'NTFS') {{ throw 'NTFS verification failed.' }}
[PSCustomObject]@{{
    DiskSize = [UInt64]$disk.Size
    PartitionSize = [UInt64]$updated.Size
    FileSystem = [String]$updatedVolume.FileSystem
}} | ConvertTo-Json -Compress
"""
    raw = _run_powershell(script, timeout=180.0)
    try:
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise TypeError("Resize result must be an object.")
        result = WindowsVolumeResizeResult(
            disk_size=int(decoded["DiskSize"]),
            partition_size=int(decoded["PartitionSize"]),
            file_system=str(decoded["FileSystem"]),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise MountUnavailableError(
            "Windows не подтвердила результат расширения раздела."
        ) from error
    if (
        result.disk_size != expected_disk_size
        or result.partition_size <= expected_partition_size
        or result.partition_size > expected_disk_size - info.partition_offset
        or result.file_system.upper() != "NTFS"
    ):
        raise MountUnavailableError(
            "Windows вернула противоречивый результат расширения раздела."
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
        self._container_path: Path | None = None
        self._context_menu_labels: tuple[str, ...] | None = None
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

    @property
    def mounted_container(self) -> Path | None:
        return self._container_path if self.mounted_drive is not None else None

    def inspect_mounted_disk(self) -> WindowsVolumeInfo:
        drive = self.mounted_drive
        record = self._control_record
        if drive is None or record is None:
            raise MountUnavailableError(
                "Активный системный диск Clever PGP не найден."
            )
        self._control_store.send(record, "ping", timeout=1.0)
        info = inspect_windows_volume(drive)
        validate_cleverpgp_volume(info, expected_disk_size=info.disk_size)
        return info

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
                container_path=container_path,
                context_menu_labels=context_menu_labels,
            )
        except Exception:
            self._process_manager.stop()
            wait_for_disk_removal(disk.number)
            raise
        self._disk = disk
        self._drive = drive
        self._container_path = Path(container_path).expanduser().resolve()
        self._control_record = control_record
        self._context_menu_labels = context_menu_labels
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
                container_path=container_path,
                context_menu_labels=context_menu_labels,
            )
        except Exception:
            self._process_manager.stop()
            wait_for_disk_removal(disk.number)
            raise
        self._disk = disk
        self._drive = drive
        self._container_path = Path(container_path).expanduser().resolve()
        self._control_record = control_record
        self._context_menu_labels = context_menu_labels
        if progress is not None:
            progress(100, "Системный диск подключён")
        return drive

    def resize_mounted_disk(
        self,
        master_key: bytes,
        *,
        logical_capacity: int,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
        elevated_extender: Callable[
            [DiskControlRecord, WindowsVolumeInfo], WindowsVolumeResizeResult
        ]
        | None = None,
    ) -> str:
        """Grow a mounted NTFS disk, remount it, then extend its Windows partition."""

        drive = self.mounted_drive
        record = self._control_record
        container_path = self._container_path
        if drive is None or record is None:
            raise MountUnavailableError(
                "Активный системный диск Clever PGP не найден."
            )
        if container_path is None or not container_path.is_file():
            raise MountUnavailableError(
                "Путь подключённого контейнера недоступен. Отключите и снова откройте диск."
            )
        if (
            not isinstance(logical_capacity, int)
            or logical_capacity < MIN_WINDOWS_DISK_CAPACITY
            or logical_capacity % LOGICAL_BLOCK_SIZE
        ):
            raise MountUnavailableError(
                "Новый размер диска должен быть не меньше 32 МБ и кратен 4096 байтам."
            )
        if progress is not None:
            progress(2, "Проверка подключённого диска")
        original = self.inspect_mounted_disk()
        validate_cleverpgp_ntfs_volume(
            original,
            expected_disk_size=original.disk_size,
        )
        if logical_capacity < original.disk_size:
            raise MountUnavailableError(
                "Уменьшение системного диска пока не поддерживается безопасно."
            )

        labels = context_menu_labels or self._context_menu_labels
        extender = elevated_extender
        if extender is None:
            from biopgp.core.windows_resize import run_elevated_ntfs_extension

            extender = lambda selected_record, selected_volume: (
                run_elevated_ntfs_extension(selected_record, selected_volume)
            )

        available_tail = (
            original.disk_size
            - original.partition_offset
            - original.partition_size
        )
        if logical_capacity == original.disk_size:
            if available_tail <= 0:
                if progress is not None:
                    progress(100, "Размер диска уже установлен")
                return drive
            if progress is not None:
                progress(85, "Ожидание разрешения Windows")
            result = extender(record, original)
            if (
                result.disk_size != logical_capacity
                or result.partition_size <= original.partition_size
                or result.file_system.upper() != "NTFS"
            ):
                raise MountUnavailableError(
                    "Windows не подтвердила новый размер раздела NTFS."
                )
            if progress is not None:
                progress(100, "Раздел NTFS расширен")
            return drive

        original_partition_size = original.partition_size
        original_offset = original.partition_offset
        original_unique_id = original.unique_id
        original_serial = original.serial_number
        if progress is not None:
            progress(5, "Безопасное отключение диска")
        self.unmount()

        def growth_progress(completed: int, total: int) -> None:
            if progress is not None:
                fraction = completed / total if total else 1.0
                progress(
                    10 + round(fraction * 55),
                    "Добавление зашифрованных блоков",
                )

        resize_windows_block_volume(
            container_path,
            master_key,
            logical_capacity=logical_capacity,
            progress=growth_progress,
        )
        if progress is not None:
            progress(68, "Повторное подключение увеличенного диска")
        remounted_drive = self.mount(
            container_path,
            master_key,
            context_menu_labels=labels,
            progress=(
                None
                if progress is None
                else lambda value, message: progress(
                    68 + round(value * 0.17),
                    message,
                )
            ),
        )
        resized_record = self._control_record
        if resized_record is None:
            raise MountUnavailableError(
                "Увеличенный диск не опубликовал защищённую запись управления."
            )
        resized = inspect_windows_volume(remounted_drive)
        validate_cleverpgp_ntfs_volume(
            resized,
            expected_disk_size=logical_capacity,
        )
        if resized.partition_size != original_partition_size:
            raise MountUnavailableError(
                "Размер раздела изменился до подтверждённого расширения Windows."
            )
        if resized.partition_offset != original_offset:
            raise MountUnavailableError("Отступ раздела изменился после подключения.")
        if original_unique_id and resized.unique_id != original_unique_id:
            raise MountUnavailableError(
                "Идентификатор диска изменился после подключения."
            )
        if original_serial and resized.serial_number != original_serial:
            raise MountUnavailableError(
                "Серийный номер диска изменился после подключения."
            )
        if progress is not None:
            progress(88, "Ожидание разрешения Windows")
        result = extender(resized_record, resized)
        if (
            result.disk_size != logical_capacity
            or result.partition_size <= original_partition_size
            or result.file_system.upper() != "NTFS"
        ):
            raise MountUnavailableError(
                "Windows не подтвердила новый размер раздела NTFS."
            )
        if progress is not None:
            progress(100, "Системный диск увеличен")
        return remounted_drive

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
        self._container_path = None
        self._context_menu_labels = None

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
            resolver = getattr(self._control_store, "container_path", None)
            if callable(resolver):
                try:
                    self._container_path = resolver(active[0])
                except MountUnavailableError:
                    self._container_path = None
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
        container_path: Path,
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
            container_path=container_path,
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
        self._container_path = None


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


def _normalize_windows_drive(drive: str) -> str:
    normalized = str(drive).strip().upper().rstrip("\\/")
    if len(normalized) == 1:
        normalized += ":"
    if (
        len(normalized) != 2
        or normalized[1] != ":"
        or not normalized[0].isalpha()
    ):
        raise ValueError("Invalid Windows drive letter.")
    return normalized
