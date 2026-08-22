from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass

from biopgp.core.errors import MountUnavailableError


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


def format_ephemeral_cleverpgp_disk(
    disk: WindowsDiskInfo,
    *,
    expected_size: int,
    file_system: str = "NTFS",
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

    script = f"""
$ErrorActionPreference = 'Stop'
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
$partition | Format-Volume -FileSystem {normalized_file_system} -NewFileSystemLabel 'CleverPGP Check' -AllocationUnitSize 4096 -Force -Confirm:$false | Out-Null
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


def wait_for_disk_removal(number: int, *, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(disk.number != number for disk in list_windows_disks()):
            return
        time.sleep(0.2)
    raise MountUnavailableError("Временный системный диск не отключился.")
