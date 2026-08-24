from __future__ import annotations

import base64
import hmac
import json
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cleverpgp.core.block_volume import (
    LOGICAL_BLOCK_SIZE,
    BlockVolumeError,
    EncryptedBlockVolume,
)
from cleverpgp.core.disk_control import (
    DiskControlRecord,
    DiskControlStore,
)
from cleverpgp.core.disk_crypto import DEFAULT_DISK_ALGORITHM, require_disk_cipher
from cleverpgp.core.disk_host import WinSpdHostManager
from cleverpgp.core.errors import MountUnavailableError
from cleverpgp.core.opaque_volume_header import (
    OpaqueVolumeHeader,
    OpaqueVolumeHeaderStore,
)
from cleverpgp.core.volume_path import resolve_file_hosted_container_path
from cleverpgp.core.winspd import (
    HiddenWindowsVolumeHeaders,
    MIN_WINDOWS_DISK_CAPACITY,
    WINDOWS_BLOCK_STORAGE_FORMAT,
    WinSpdLibrary,
    create_hidden_windows_block_volume,
    create_windows_block_volume,
    convert_windows_block_volume_algorithm,
    open_windows_block_volume,
    resize_windows_block_volume,
)
from cleverpgp.core.windows_shell import WindowsDriveContextMenu


@dataclass(frozen=True, slots=True)
class WindowsDiskInfo:
    number: int
    friendly_name: str
    serial_number: str
    unique_id: str
    size: int
    partition_style: str
    bus_type: str = ""
    is_boot: bool = False
    is_system: bool = False


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
        "PartitionStyle,BusType,IsBoot,IsSystem | ConvertTo-Json -Compress"
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
                bus_type=str(record.get("BusType") or ""),
                is_boot=_strict_json_bool(record.get("IsBoot", False)),
                is_system=_strict_json_bool(record.get("IsSystem", False)),
            )
        )
    return result


def _strict_json_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise MountUnavailableError("Windows вернула некорректный признак диска.")
    return value


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
        raise MountUnavailableError("Размер виртуального диска Clever PGP изменился.")
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
        and not disk.is_boot
        and not disk.is_system
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
        "Временный виртуальный диск Clever PGP не появился."
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
    if disk.partition_style.upper() != "MBR":
        raise MountUnavailableError("Ожидалась таблица разделов MBR Clever PGP.")
    if disk.is_boot or disk.is_system:
        raise MountUnavailableError(
            "Системный или загрузочный диск Windows форматировать запрещено."
        )
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
    encoded_identity = {
        name: base64.b64encode(value.encode("utf-8")).decode("ascii")
        for name, value in (
            ("friendly", disk.friendly_name),
            ("serial", disk.serial_number),
            ("unique", disk.unique_id),
            ("bus", disk.bus_type),
        )
    }

    script = f"""
$ErrorActionPreference = 'Stop'
$label = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_label}'))
function Decode-Identity([String]$value) {{
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value))
}}
$expectedFriendly = Decode-Identity '{encoded_identity["friendly"]}'
$expectedSerial = Decode-Identity '{encoded_identity["serial"]}'
$expectedUnique = Decode-Identity '{encoded_identity["unique"]}'
$expectedBus = Decode-Identity '{encoded_identity["bus"]}'
$disk = Get-Disk -Number {disk.number}
if ([UInt64]$disk.Size -ne [UInt64]{expected_size}) {{ throw 'Disk size changed.' }}
if ([String]$disk.FriendlyName -ne $expectedFriendly) {{ throw 'Disk name changed.' }}
if ([String]$disk.SerialNumber -ne $expectedSerial) {{ throw 'Disk serial changed.' }}
if ([String]$disk.UniqueId -ne $expectedUnique) {{ throw 'Disk identity changed.' }}
if ([String]$disk.BusType -ne $expectedBus) {{ throw 'Disk bus changed.' }}
if ($disk.FriendlyName -notmatch 'CleverPGP|WinSpd') {{ throw 'Disk identity changed.' }}
if ($disk.PartitionStyle -ne 'MBR') {{ throw 'Expected an MBR test disk.' }}
if ([Boolean]$disk.IsBoot -or [Boolean]$disk.IsSystem) {{ throw 'System disk is forbidden.' }}
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
                "Виртуальный диск Clever PGP получил несколько букв."
            )
        time.sleep(0.2)
    raise MountUnavailableError(
        "Windows не назначила букву виртуальному диску. Возможно, он ещё не отформатирован."
    )


def wait_for_disk_removal(number: int, *, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(disk.number != number for disk in list_windows_disks()):
            return
        time.sleep(0.2)
    raise MountUnavailableError("Временный виртуальный диск не отключился.")


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
        self._prepared_library: WinSpdLibrary | None = None
        if recover_existing:
            self._recover_existing_control_record()

    def prepare_backend(self) -> None:
        """Load the native WinSpd bridge on the calling UI thread once."""

        if self._prepared_library is None:
            self._prepared_library = WinSpdLibrary()

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
                refreshed = self._refresh_control_record()
                if refreshed is not None:
                    return refreshed.drive
                # A host can be briefly busy while Windows flushes the volume.
                # Keep recoverable state while its assigned drive still exists.
                if self._drive_available(self._drive):
                    return self._drive
        self._clear_control_record()
        self._disk = None
        self._drive = None
        return None

    def _refresh_control_record(self) -> DiskControlRecord | None:
        drive = self._drive
        current = self._control_record
        finder = getattr(self._control_store, "find_by_drive", None)
        if drive is None or current is None or not callable(finder):
            return None
        try:
            candidate = finder(drive)
            if candidate is None or candidate == current:
                return None
            self._control_store.send(candidate, "ping", timeout=0.35)
            container_reader = getattr(self._control_store, "container_path", None)
            container_path = (
                container_reader(candidate)
                if callable(container_reader)
                else self._container_path
            )
        except (MountUnavailableError, OSError, TypeError, ValueError):
            return None
        self._control_record = candidate
        self._drive = candidate.drive
        self._container_path = container_path
        return candidate

    @property
    def mounted_container(self) -> Path | None:
        return self._container_path if self.mounted_drive is not None else None

    @property
    def mounted_algorithm(self) -> str | None:
        if self.mounted_drive is None or self._control_record is None:
            return None
        reader = getattr(self._control_store, "algorithm", None)
        return reader(self._control_record) if callable(reader) else None

    def inspect_mounted_disk(self) -> WindowsVolumeInfo:
        drive = self.mounted_drive
        record = self._control_record
        if drive is None or record is None:
            raise MountUnavailableError(
                "Активный виртуальный диск Clever PGP не найден."
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
        algorithm: str = DEFAULT_DISK_ALGORITHM,
        password: str | None = None,
        file_system: str = "NTFS",
        overwrite: bool = False,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> str:
        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый виртуальный диск Clever PGP."
            )
        if progress is not None:
            progress(3, "Проверка компонента виртуального диска")
        library = self._prepared_library or WinSpdLibrary()

        def creation_progress(completed: int, total: int) -> None:
            if progress is not None:
                fraction = completed / total if total else 1.0
                progress(
                    5 + round(fraction * 55),
                    "Подготовка зашифрованных блоков",
                )

        if progress is not None:
            progress(4, "Проверка параметров виртуального диска")
        volume = create_windows_block_volume(
            container_path,
            master_key,
            logical_capacity=logical_capacity,
            library=library,
            label=label,
            algorithm=algorithm,
            password=password,
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
            endpoint = getattr(self._process_manager, "control_endpoint", None)
            if endpoint is None:
                raise MountUnavailableError(
                    "Фоновый процесс не предоставил защищённый канал форматирования."
                )
            if progress is not None:
                progress(82, "Ожидание разрешения Windows")
            from cleverpgp.core.windows_format import run_elevated_windows_format

            drive = run_elevated_windows_format(
                endpoint,
                disk,
                file_system=file_system,
                label=label,
            )
            self._verify_host_health(
                "Виртуальный диск остановился во время форматирования."
            )
            if progress is not None:
                progress(95, "Форматирование виртуального диска завершено")
        except Exception:
            try:
                self._process_manager.stop()
            finally:
                # Until Windows confirms the first format, this newly created
                # image has no usable file system and cannot be reopened as a
                # disk. Roll the failed creation back instead of leaving a
                # large orphaned container that looks successful.
                Path(container_path).expanduser().resolve().unlink(missing_ok=True)
            raise
        try:
            control_record = self._publish_control_record(
                drive,
                container_path=container_path,
                algorithm=algorithm,
                context_menu_labels=context_menu_labels,
                supports_algorithm_change=password is None,
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
            progress(100, "Виртуальный диск готов")
        return drive

    def create_and_mount_isolated(
        self,
        container_path: Path,
        master_key: bytes,
        *,
        logical_capacity: int,
        label: str,
        algorithm: str = DEFAULT_DISK_ALGORITHM,
        password: str | None = None,
        file_system: str = "NTFS",
        overwrite: bool = False,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> str:
        """Create through a clean process so native password KDF never blocks Qt."""

        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый виртуальный диск Clever PGP."
            )
        from cleverpgp.core.disk_creation import create_windows_disk_isolated

        drive = create_windows_disk_isolated(
            container_path,
            master_key,
            logical_capacity=logical_capacity,
            label=label,
            algorithm=algorithm,
            password=password,
            file_system=file_system,
            overwrite=overwrite,
            context_menu_labels=context_menu_labels,
            progress=progress,
        )
        self._recover_existing_control_record()
        recovered = self.mounted_drive
        if recovered != drive:
            raise MountUnavailableError(
                "Созданный диск подключён, но приложение не получило канал управления."
            )
        return drive

    def create_hidden_and_mount(
        self,
        container_path: Path,
        outer_password: str,
        hidden_password: str,
        *,
        outer_capacity: int,
        hidden_capacity: int,
        outer_label: str,
        hidden_label: str,
        file_system: str = "NTFS",
        overwrite: bool = False,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
        header_store: OpaqueVolumeHeaderStore | None = None,
    ) -> str:
        """Create, format, and leave the hidden v4 projection mounted."""

        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый виртуальный диск Clever PGP."
            )
        library = self._prepared_library or WinSpdLibrary()
        if progress is not None:
            progress(2, "Проверка параметров скрытого диска")
        headers: HiddenWindowsVolumeHeaders = create_hidden_windows_block_volume(
            container_path,
            outer_password,
            hidden_password,
            outer_capacity=outer_capacity,
            hidden_capacity=hidden_capacity,
            library=library,
            outer_label=outer_label,
            hidden_label=hidden_label,
            overwrite=overwrite,
            header_store=header_store,
            progress=(
                None
                if progress is None
                else lambda completed, total: progress(
                    3 + round(completed / total * 49),
                    "Подготовка внешнего и скрытого дисков",
                )
            ),
        )
        target = resolve_file_hosted_container_path(container_path)
        active_disk: WindowsDiskInfo | None = None
        try:
            outer_before = list_windows_disks()
            self._process_manager.start(
                target,
                None,
                device_name=None,
                opaque_header=headers.outer,
                protection_header=headers.hidden,
                progress=(
                    None
                    if progress is None
                    else lambda value, message: progress(
                        52 + round(value * 0.1),
                        message,
                    )
                ),
            )
            active_disk = wait_for_new_cleverpgp_disk(
                outer_before,
                expected_size=outer_capacity,
            )
            endpoint = getattr(self._process_manager, "control_endpoint", None)
            if endpoint is None:
                raise MountUnavailableError(
                    "Фоновый процесс не предоставил защищённый канал форматирования."
                )
            if progress is not None:
                progress(64, "Форматирование внешнего диска с защитой")
            from cleverpgp.core.windows_format import run_elevated_windows_format

            run_elevated_windows_format(
                endpoint,
                active_disk,
                file_system=file_system,
                label=outer_label,
            )
            self._verify_host_health(
                "Защита скрытой области остановила форматирование внешнего диска."
            )
            if progress is not None:
                progress(74, "Отключение внешнего диска")
            outer_disk_number = active_disk.number
            self._process_manager.stop()
            wait_for_disk_removal(outer_disk_number)
            active_disk = None

            hidden_before = list_windows_disks()
            self._process_manager.start(
                target,
                None,
                device_name=None,
                opaque_header=headers.hidden,
                protection_header=None,
                progress=(
                    None
                    if progress is None
                    else lambda value, message: progress(
                        76 + round(value * 0.1),
                        message,
                    )
                ),
            )
            active_disk = wait_for_new_cleverpgp_disk(
                hidden_before,
                expected_size=hidden_capacity,
            )
            endpoint = getattr(self._process_manager, "control_endpoint", None)
            if endpoint is None:
                raise MountUnavailableError(
                    "Фоновый процесс скрытого диска не предоставил канал форматирования."
                )
            if progress is not None:
                progress(88, "Форматирование скрытого диска")
            drive = run_elevated_windows_format(
                endpoint,
                active_disk,
                file_system=file_system,
                label=hidden_label,
            )
            self._verify_host_health(
                "Скрытый диск остановился во время форматирования."
            )
            if progress is not None:
                progress(97, "Публикация скрытого диска")
            control_record = self._publish_control_record(
                drive,
                container_path=target,
                algorithm=DEFAULT_DISK_ALGORITHM,
                context_menu_labels=context_menu_labels,
            )
        except Exception:
            try:
                self._process_manager.stop()
                if active_disk is not None:
                    wait_for_disk_removal(active_disk.number)
            except Exception as cleanup_error:
                raise MountUnavailableError(
                    "Создание не завершено, но диск не удалось безопасно "
                    "отключить. Образ сохранён для предотвращения потери данных."
                ) from cleanup_error
            try:
                target.unlink(missing_ok=True)
            except OSError as cleanup_error:
                raise MountUnavailableError(
                    "Создание не завершено, но незавершённый образ не удалось "
                    "удалить. Закройте использующие его процессы."
                ) from cleanup_error
            raise

        self._disk = active_disk
        self._drive = drive
        self._container_path = target
        self._control_record = control_record
        self._context_menu_labels = context_menu_labels
        if progress is not None:
            progress(100, "Скрытый виртуальный диск готов")
        return drive

    def create_hidden_and_mount_isolated(
        self,
        container_path: Path,
        outer_password: str,
        hidden_password: str,
        *,
        outer_capacity: int,
        hidden_capacity: int,
        outer_label: str,
        hidden_label: str,
        file_system: str = "NTFS",
        overwrite: bool = False,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> str:
        """Create an outer/hidden pair outside the Qt process."""

        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый виртуальный диск Clever PGP."
            )
        from cleverpgp.core.disk_creation import create_hidden_windows_disk_isolated

        drive = create_hidden_windows_disk_isolated(
            container_path,
            outer_password,
            hidden_password,
            outer_capacity=outer_capacity,
            hidden_capacity=hidden_capacity,
            outer_label=outer_label,
            hidden_label=hidden_label,
            file_system=file_system,
            overwrite=overwrite,
            context_menu_labels=context_menu_labels,
            progress=progress,
        )
        self._recover_existing_control_record()
        recovered = self.mounted_drive
        if recovered != drive:
            raise MountUnavailableError(
                "Созданный скрытый диск подключён, но канал управления недоступен."
            )
        return drive

    def _verify_host_health(self, message: str) -> None:
        verifier = getattr(self._process_manager, "verify_healthy", None)
        try:
            if callable(verifier):
                verifier(timeout=1.0)
            elif not self._process_manager.running:
                raise MountUnavailableError(message)
        except MountUnavailableError as error:
            raise MountUnavailableError(message) from error

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
                "Сначала отключите уже открытый виртуальный диск Clever PGP."
            )
        volume = open_windows_block_volume(container_path, master_key)
        try:
            logical_capacity = volume.logical_capacity
            algorithm = volume.algorithm
            supports_algorithm_change = not volume.has_portable_password
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
                algorithm=algorithm,
                context_menu_labels=context_menu_labels,
                supports_algorithm_change=supports_algorithm_change,
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
            progress(100, "Виртуальный диск подключён")
        return drive

    def mount_opaque(
        self,
        container_path: Path,
        password: str,
        *,
        hidden_protection_password: str | None = None,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
        header_store: OpaqueVolumeHeaderStore | None = None,
    ) -> str:
        """Authenticate a portable v5 disk or an opaque v4 disk locally."""

        source = resolve_file_hosted_container_path(container_path)
        if not source.is_file():
            raise MountUnavailableError("Файл зашифрованного диска не найден.")
        try:
            portable_key = EncryptedBlockVolume.password_access_key(
                source,
                password,
            )
        except BlockVolumeError as portable_error:
            if "Неверный пароль" in str(portable_error):
                raise
        else:
            try:
                return self.mount(
                    source,
                    portable_key,
                    context_menu_labels=context_menu_labels,
                    progress=progress,
                )
            finally:
                del portable_key

        store = header_store or OpaqueVolumeHeaderStore()

        def unlock_progress(completed: int, total: int) -> None:
            if progress is not None:
                progress(
                    5 + round(completed / total * 35),
                    "Проверка пароля диска",
                )

        if progress is not None:
            progress(3, "Чтение защищённого заголовка")
        with source.open("rb") as stream:
            selected = store.unlock(
                stream,
                password,
                progress=unlock_progress,
            )
            protection = (
                store.unlock(stream, hidden_protection_password)
                if hidden_protection_password is not None
                else None
            )
        return self.mount_authenticated_opaque(
            source,
            selected,
            protection_header=protection,
            context_menu_labels=context_menu_labels,
            progress=(
                None
                if progress is None
                else lambda value, message: progress(
                    42 + round(value * 0.58),
                    message,
                )
            ),
        )

    def mount_authenticated_opaque(
        self,
        container_path: Path,
        selected_header: OpaqueVolumeHeader,
        *,
        protection_header: OpaqueVolumeHeader | None = None,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> str:
        if self.mounted_drive is not None:
            raise MountUnavailableError(
                "Сначала отключите уже открытый виртуальный диск Clever PGP."
            )
        source = resolve_file_hosted_container_path(container_path)
        if not source.is_file():
            raise MountUnavailableError("Файл зашифрованного диска не найден.")
        self._validate_opaque_mount_headers(selected_header, protection_header)
        if selected_header.storage_format != WINDOWS_BLOCK_STORAGE_FORMAT:
            raise MountUnavailableError(
                "Это не виртуальный зашифрованный диск Clever PGP."
            )
        if selected_header.role == "hidden":
            descriptor = selected_header.hidden_descriptor
            if descriptor is None:
                raise MountUnavailableError("Скрытый заголовок диска повреждён.")
            logical_capacity = descriptor.hidden_block_count * LOGICAL_BLOCK_SIZE
        else:
            logical_capacity = (
                selected_header.cover_block_count * LOGICAL_BLOCK_SIZE
            )

        before = list_windows_disks()
        try:
            self._process_manager.start(
                source,
                None,
                device_name=None,
                opaque_header=selected_header,
                protection_header=protection_header,
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
                container_path=source,
                algorithm=DEFAULT_DISK_ALGORITHM,
                context_menu_labels=context_menu_labels,
            )
        except Exception:
            self._process_manager.stop()
            wait_for_disk_removal(disk.number)
            raise
        self._disk = disk
        self._drive = drive
        self._container_path = source
        self._control_record = control_record
        self._context_menu_labels = context_menu_labels
        if progress is not None:
            progress(100, "Виртуальный диск подключён")
        return drive

    def change_opaque_password(
        self,
        current_password: str,
        new_password: str,
        *,
        progress: Callable[[int, str], None] | None = None,
        header_store: OpaqueVolumeHeaderStore | None = None,
    ) -> Path:
        """Safely detach an active portable or hidden disk and rotate access."""

        drive = self.mounted_drive
        record = self._control_record
        source = self._container_path
        if drive is None or record is None or source is None:
            raise MountUnavailableError(
                "Активный виртуальный диск Clever PGP не найден."
            )
        target = resolve_file_hosted_container_path(source)
        if not target.is_file():
            raise MountUnavailableError("Файл зашифрованного диска не найден.")
        try:
            portable_key = EncryptedBlockVolume.password_access_key(
                target,
                current_password,
            )
        except BlockVolumeError as portable_error:
            if "Неверный пароль" in str(portable_error):
                raise
        else:
            del portable_key
            if progress is not None:
                progress(30, "Безопасное отключение диска")
            self.unmount()
            EncryptedBlockVolume.change_password(
                target,
                current_password,
                new_password,
                progress=(
                    None
                    if progress is None
                    else lambda completed, total: progress(
                        35 + round(completed / total * 65),
                        "Обновление переносимого парольного доступа",
                    )
                ),
            )
            if progress is not None:
                progress(100, "Пароль диска успешно изменён")
            return target

        store = header_store or OpaqueVolumeHeaderStore()
        if progress is not None:
            progress(3, "Проверка текущего пароля диска")
        with target.open("rb") as stream:
            selected = store.validate_password_change(
                stream,
                current_password,
                new_password,
                expected_volume_id=record.volume_id,
                progress=(
                    None
                    if progress is None
                    else lambda completed, total: progress(
                        3 + round(completed / total * 27),
                        "Проверка нового пароля диска",
                    )
                ),
            )
        if selected.storage_format != WINDOWS_BLOCK_STORAGE_FORMAT:
            raise MountUnavailableError(
                "Смена пароля доступна только для диска "
                "со скрытой областью Clever PGP."
            )

        if progress is not None:
            progress(35, "Безопасное отключение диска")
        self.unmount()
        if progress is not None:
            progress(45, "Обновление защищённого заголовка")
        with target.open("r+b") as stream:
            store.change_password(
                stream,
                current_password,
                new_password,
                expected_volume_id=record.volume_id,
                progress=(
                    None
                    if progress is None
                    else lambda completed, total: progress(
                        45 + round(completed / total * 53),
                        "Обновление защищённого заголовка",
                    )
                ),
            )
        if progress is not None:
            progress(100, "Пароль диска успешно изменён")
        return target

    @staticmethod
    def _validate_opaque_mount_headers(
        selected: OpaqueVolumeHeader,
        protection: OpaqueVolumeHeader | None,
    ) -> None:
        if protection is None:
            return
        if (
            selected.role != "outer"
            or protection.role != "hidden"
            or protection.hidden_descriptor is None
            or selected.cover_volume_id != protection.cover_volume_id
            or selected.cover_block_count != protection.cover_block_count
            or not hmac.compare_digest(selected.cover_key, protection.cover_key)
        ):
            raise MountUnavailableError(
                "Пароль защиты скрытого диска не относится к внешнему диску."
            )

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
                "Активный виртуальный диск Clever PGP не найден."
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
                "Уменьшение виртуального диска пока не поддерживается безопасно."
            )

        labels = context_menu_labels or self._context_menu_labels
        extender = elevated_extender
        if extender is None:
            from cleverpgp.core.windows_resize import run_elevated_ntfs_extension

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
            progress(100, "Виртуальный диск увеличен")
        return remounted_drive

    def change_mounted_disk_algorithm(
        self,
        master_key: bytes,
        *,
        algorithm: str,
        context_menu_labels: tuple[str, ...] | None = None,
        progress: Callable[[int, str], None] | None = None,
    ) -> str:
        """Re-encrypt an active ordinary disk and restore its mounted state."""

        drive = self.mounted_drive
        source = self._container_path
        if drive is None or self._control_record is None:
            raise MountUnavailableError(
                "Активный виртуальный диск Clever PGP не найден."
            )
        if source is None or not source.is_file():
            raise MountUnavailableError(
                "Путь подключённого контейнера недоступен. "
                "Отключите и снова откройте диск."
            )
        selected_cipher = require_disk_cipher(algorithm)
        labels = context_menu_labels or self._context_menu_labels
        if progress is not None:
            progress(2, "Проверка подключённого диска")
        original = self.inspect_mounted_disk()
        validate_cleverpgp_volume(
            original,
            expected_disk_size=original.disk_size,
        )
        volume = open_windows_block_volume(source, master_key)
        try:
            current_algorithm = volume.algorithm
            if volume.logical_capacity != original.disk_size:
                raise MountUnavailableError(
                    "Размер контейнера не совпадает с подключённым диском."
                )
        finally:
            volume.close()
        if current_algorithm == selected_cipher.identifier:
            if progress is not None:
                progress(100, "Выбранный метод уже используется")
            return drive

        if progress is not None:
            progress(5, "Безопасное отключение диска")
        self.unmount()

        def conversion_progress(completed: int, total: int) -> None:
            if progress is not None:
                fraction = completed / total if total else 1.0
                progress(
                    8 + round(fraction * 72),
                    "Преобразование зашифрованных блоков",
                )

        try:
            convert_windows_block_volume_algorithm(
                source,
                master_key,
                algorithm=selected_cipher.identifier,
                progress=conversion_progress,
            )
            if progress is not None:
                progress(82, "Проверка и повторное подключение диска")
            remounted = self.mount(
                source,
                master_key,
                context_menu_labels=labels,
                progress=(
                    None
                    if progress is None
                    else lambda value, message: progress(
                        82 + round(value * 0.16),
                        message,
                    )
                ),
            )
        except Exception:
            if self.mounted_drive is None:
                try:
                    self.mount(
                        source,
                        master_key,
                        context_menu_labels=labels,
                    )
                except Exception as remount_error:
                    raise MountUnavailableError(
                        "Преобразование остановлено, и диск не удалось снова "
                        "подключить. Контейнер сохранён; откройте его повторно."
                    ) from remount_error
            raise

        converted = self.inspect_mounted_disk()
        validate_cleverpgp_volume(
            converted,
            expected_disk_size=original.disk_size,
        )
        if (
            converted.partition_size != original.partition_size
            or converted.partition_offset != original.partition_offset
        ):
            raise MountUnavailableError(
                "Разметка диска изменилась после преобразования."
            )
        if original.unique_id and converted.unique_id != original.unique_id:
            raise MountUnavailableError(
                "Идентификатор диска изменился после преобразования."
            )
        if (
            original.serial_number
            and converted.serial_number != original.serial_number
        ):
            raise MountUnavailableError(
                "Серийный номер диска изменился после преобразования."
            )
        if self.mounted_algorithm != selected_cipher.identifier:
            raise MountUnavailableError(
                "Не удалось подтвердить новый метод шифрования диска."
            )
        if progress is not None:
            progress(100, "Метод шифрования диска изменён")
        return remounted

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
        algorithm: str,
        context_menu_labels: tuple[str, ...] | None,
        supports_algorithm_change: bool = False,
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
            algorithm=algorithm,
        )
        if context_menu_labels is None:
            open_label = "Открыть зашифрованный диск"
            info_label = "Сведения о диске"
            settings_label = "Настройки доступа"
            resize_label = "Увеличить диск"
            password_label = None
            algorithm_label = (
                "Изменить метод шифрования"
                if supports_algorithm_change
                else None
            )
            unmount_label = "Отключить зашифрованный диск"
        elif len(context_menu_labels) == 2:
            open_label, unmount_label = context_menu_labels
            info_label = "Сведения о диске"
            settings_label = "Настройки доступа"
            resize_label = "Увеличить диск"
            password_label = None
            algorithm_label = None
        elif len(context_menu_labels) == 3:
            open_label, settings_label, unmount_label = context_menu_labels
            info_label = "Сведения о диске"
            resize_label = "Увеличить диск"
            password_label = None
            algorithm_label = None
        elif len(context_menu_labels) == 4:
            open_label, info_label, settings_label, unmount_label = (
                context_menu_labels
            )
            resize_label = "Увеличить диск"
            password_label = None
            algorithm_label = None
        elif len(context_menu_labels) == 5:
            open_label, info_label, settings_label, resize_label, unmount_label = (
                context_menu_labels
            )
            password_label = None
            algorithm_label = None
        elif len(context_menu_labels) == 6:
            (
                open_label,
                info_label,
                settings_label,
                password_label,
                resize_label,
                unmount_label,
            ) = context_menu_labels
            algorithm_label = None
        elif len(context_menu_labels) == 7:
            (
                open_label,
                info_label,
                settings_label,
                password_label,
                algorithm_label,
                resize_label,
                unmount_label,
            ) = context_menu_labels
        else:
            raise ValueError(
                "Virtual disk context menu requires two to seven labels."
            )
        if not supports_algorithm_change:
            algorithm_label = None
        try:
            self._context_menu.register(
                drive,
                open_label=open_label,
                info_label=info_label,
                settings_label=settings_label,
                resize_label=resize_label or None,
                unmount_label=unmount_label,
                password_label=password_label or None,
                algorithm_label=algorithm_label or None,
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
        f"Виртуальный диск {drive} не подтвердил безопасное отключение."
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
