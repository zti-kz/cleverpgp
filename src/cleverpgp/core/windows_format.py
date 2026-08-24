from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable, Protocol

from cleverpgp.config import app_data_directory
from cleverpgp.core.disk_control import (
    DiskControlEndpoint,
    send_disk_control_command,
)
from cleverpgp.core.errors import MountUnavailableError
from cleverpgp.core.windows_shell import application_command_prefix
from cleverpgp.core.windows_storage import (
    WindowsDiskInfo,
    format_new_cleverpgp_disk,
    list_windows_disks,
)

FORMAT_PROTOCOL_VERSION = 1
_REQUEST_ID_BYTES = 16
_TOKEN_ENTROPY_PREFIX = b"Clever PGP Windows format request v1\0"
_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SEE_MASK_FLAG_NO_UI = 0x00000400
_SW_HIDE = 0
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102


class FormatSecretProtector(Protocol):
    def protect(self, plaintext: bytes, entropy: bytes) -> bytes: ...

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class FormatExchangePaths:
    request_id: str
    request_path: Path
    response_path: Path


@dataclass(frozen=True, slots=True)
class WindowsFormatRequest:
    request_id: str
    endpoint: DiskControlEndpoint
    disk: WindowsDiskInfo
    file_system: str
    label: str


class WindowsFormatExchange:
    """One-time authenticated request crossing only the Windows UAC boundary."""

    def __init__(
        self,
        directory: Path | None = None,
        protector: FormatSecretProtector | None = None,
    ) -> None:
        self.directory = (
            Path(directory).expanduser().resolve()
            if directory is not None
            else (app_data_directory() / "format-requests").resolve()
        )
        self._protector = protector

    def create(
        self,
        endpoint: DiskControlEndpoint,
        disk: WindowsDiskInfo,
        *,
        file_system: str,
        label: str,
    ) -> FormatExchangePaths:
        normalized_file_system = _normalize_file_system(file_system)
        normalized_label = _normalize_label(label)
        _validate_expected_disk(disk)
        request_id = secrets.token_hex(_REQUEST_ID_BYTES)
        paths = self.paths(request_id)
        authenticated = {
            "version": FORMAT_PROTOCOL_VERSION,
            "request_id": request_id,
            "volume_id": endpoint.volume_id.hex(),
            "port": endpoint.port,
            "disk": asdict(disk),
            "file_system": normalized_file_system,
            "label": normalized_label,
        }
        protected_token = self._secret_protector().protect(
            endpoint.token,
            _token_entropy(request_id, endpoint.volume_id),
        )
        payload = {
            **authenticated,
            "protected_token": base64.b64encode(protected_token).decode("ascii"),
            "request_mac": hmac.new(
                endpoint.token,
                _canonical_request(authenticated),
                hashlib.sha256,
            ).hexdigest(),
        }
        self.directory.mkdir(parents=True, exist_ok=True)
        self._write_json_atomic(paths.request_path, payload)
        return paths

    def consume_request(self, request_path: Path) -> WindowsFormatRequest:
        source = Path(request_path).expanduser().resolve()
        request_id = self._request_id_from_path(source)
        if source != self.paths(request_id).request_path:
            raise MountUnavailableError("Путь запроса форматирования недопустим.")
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("Format request must be an object.")
            required_fields = {
                "version",
                "request_id",
                "volume_id",
                "port",
                "disk",
                "file_system",
                "label",
                "protected_token",
                "request_mac",
            }
            if set(payload) != required_fields:
                raise ValueError("Format request fields are invalid.")
            if int(payload["version"]) != FORMAT_PROTOCOL_VERSION:
                raise ValueError("Format request version is unsupported.")
            if str(payload["request_id"]) != request_id:
                raise ValueError("Format request identity is invalid.")
            volume_id = bytes.fromhex(str(payload["volume_id"]))
            if len(volume_id) != 16:
                raise ValueError("Format volume id is invalid.")
            port = int(payload["port"])
            raw_disk = payload["disk"]
            if not isinstance(raw_disk, dict):
                raise TypeError("Format disk information must be an object.")
            if set(raw_disk) != {
                "number",
                "friendly_name",
                "serial_number",
                "unique_id",
                "size",
                "partition_style",
                "bus_type",
                "is_boot",
                "is_system",
            }:
                raise ValueError("Format disk fields are invalid.")
            disk = WindowsDiskInfo(
                number=int(raw_disk["number"]),
                friendly_name=str(raw_disk["friendly_name"]),
                serial_number=str(raw_disk["serial_number"]),
                unique_id=str(raw_disk["unique_id"]),
                size=int(raw_disk["size"]),
                partition_style=str(raw_disk["partition_style"]),
                bus_type=str(raw_disk["bus_type"]),
                is_boot=_strict_bool(raw_disk["is_boot"]),
                is_system=_strict_bool(raw_disk["is_system"]),
            )
            _validate_expected_disk(disk)
            file_system = _normalize_file_system(str(payload["file_system"]))
            label = _normalize_label(str(payload["label"]))
            protected_token = base64.b64decode(
                str(payload["protected_token"]),
                validate=True,
            )
            if not protected_token:
                raise ValueError("Protected format token is empty.")
            token = self._secret_protector().unprotect(
                protected_token,
                _token_entropy(request_id, volume_id),
            )
            endpoint = DiskControlEndpoint(volume_id, port, token)
            authenticated = {
                "version": FORMAT_PROTOCOL_VERSION,
                "request_id": request_id,
                "volume_id": volume_id.hex(),
                "port": port,
                "disk": asdict(disk),
                "file_system": file_system,
                "label": label,
            }
            expected_mac = hmac.new(
                endpoint.token,
                _canonical_request(authenticated),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(str(payload["request_mac"]), expected_mac):
                raise ValueError("Format request authentication failed.")
        except MountUnavailableError:
            raise
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise MountUnavailableError(
                "Запрос форматирования виртуального диска повреждён."
            ) from error
        finally:
            try:
                source.unlink()
            except FileNotFoundError:
                pass
        return WindowsFormatRequest(
            request_id,
            endpoint,
            disk,
            file_system,
            label,
        )

    def write_success(
        self,
        response_path: Path,
        request_id: str,
        drive: str,
    ) -> None:
        normalized_drive = _normalize_drive(drive)
        self._write_json_atomic(
            self._validated_response_path(response_path, request_id),
            {
                "version": FORMAT_PROTOCOL_VERSION,
                "request_id": request_id,
                "status": "ok",
                "drive": normalized_drive,
            },
        )

    def write_error(
        self,
        response_path: Path,
        request_id: str,
        message: str,
    ) -> None:
        self._write_json_atomic(
            self._validated_response_path(response_path, request_id),
            {
                "version": FORMAT_PROTOCOL_VERSION,
                "request_id": request_id,
                "status": "error",
                "error": str(message)[:4000],
            },
        )

    def consume_response(self, paths: FormatExchangePaths) -> str:
        try:
            payload = json.loads(paths.response_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("Format response must be an object.")
            if int(payload.get("version", -1)) != FORMAT_PROTOCOL_VERSION:
                raise ValueError("Format response version is unsupported.")
            if str(payload.get("request_id")) != paths.request_id:
                raise ValueError("Format response identity is invalid.")
            if payload.get("status") == "error":
                raise MountUnavailableError(
                    str(payload.get("error") or "Windows не отформатировала диск.")
                )
            if payload.get("status") != "ok":
                raise ValueError("Format response status is invalid.")
            return _normalize_drive(str(payload["drive"]))
        except MountUnavailableError:
            raise
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise MountUnavailableError(
                "Процесс Windows не подтвердил форматирование диска."
            ) from error

    def cleanup(self, paths: FormatExchangePaths) -> None:
        for path in (paths.request_path, paths.response_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def paths(self, request_id: str) -> FormatExchangePaths:
        _validate_request_id(request_id)
        return FormatExchangePaths(
            request_id,
            self.directory / f"request-{request_id}.json",
            self.directory / f"response-{request_id}.json",
        )

    def _request_id_from_path(self, path: Path) -> str:
        request_id = _request_id_from_name(path.name)
        _validate_request_id(request_id)
        return request_id

    def _validated_response_path(self, path: Path, request_id: str) -> Path:
        destination = Path(path).expanduser().resolve()
        if destination != self.paths(request_id).response_path:
            raise MountUnavailableError("Путь ответа форматирования недопустим.")
        return destination

    @staticmethod
    def _write_json_atomic(destination: Path, payload: dict[str, object]) -> None:
        temporary = destination.with_name(
            f".{destination.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
        )
        try:
            temporary.write_text(
                json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
                encoding="utf-8",
            )
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            os.replace(temporary, destination)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _secret_protector(self) -> FormatSecretProtector:
        if self._protector is None:
            if sys.platform != "win32":
                raise MountUnavailableError(
                    "Форматирование виртуального диска доступно только в Windows."
                )
            from cleverpgp.biometrics.key_protection import WindowsDpapiProtector

            self._protector = WindowsDpapiProtector()
        return self._protector


def run_elevated_windows_format(
    endpoint: DiskControlEndpoint,
    disk: WindowsDiskInfo,
    *,
    file_system: str,
    label: str,
    exchange: WindowsFormatExchange | None = None,
    command_prefix: Iterable[str] | None = None,
    launcher: Callable[[list[str], float], int] | None = None,
    timeout: float = 300.0,
) -> str:
    selected_exchange = exchange or WindowsFormatExchange()
    paths = selected_exchange.create(
        endpoint,
        disk,
        file_system=file_system,
        label=label,
    )
    prefix = tuple(command_prefix or application_command_prefix())
    if not prefix:
        selected_exchange.cleanup(paths)
        raise MountUnavailableError("Команда Clever PGP для UAC не найдена.")
    command = [
        *prefix,
        "--windows-format-helper",
        str(paths.request_path),
        str(paths.response_path),
    ]
    selected_launcher = launcher or _launch_elevated
    try:
        exit_code = selected_launcher(command, timeout)
        if paths.response_path.is_file():
            return selected_exchange.consume_response(paths)
        if exit_code != 0:
            raise MountUnavailableError(
                "Windows не разрешила форматирование диска Clever PGP."
            )
        raise MountUnavailableError(
            "Процесс Windows завершился без подтверждения форматирования диска."
        )
    finally:
        selected_exchange.cleanup(paths)


def run_windows_format_helper(
    request_path: Path,
    response_path: Path,
    *,
    exchange: WindowsFormatExchange | None = None,
    disk_lister: Callable[[], list[WindowsDiskInfo]] = list_windows_disks,
    formatter: Callable[..., str] = format_new_cleverpgp_disk,
    control_sender: Callable[..., None] = send_disk_control_command,
    administrator_check: Callable[[], bool] | None = None,
) -> int:
    selected_exchange = exchange or WindowsFormatExchange()
    request_id = _request_id_from_untrusted_path(request_path)
    try:
        selected_administrator_check = administrator_check or _is_user_admin
        if not selected_administrator_check():
            raise MountUnavailableError(
                "Форматирование не получило разрешение администратора Windows."
            )
        request = selected_exchange.consume_request(request_path)
        if request.request_id != request_id:
            raise MountUnavailableError(
                "Идентификатор запроса форматирования изменился."
            )
        control_sender(request.endpoint, "ping", timeout=1.0)
        current = next(
            (disk for disk in disk_lister() if disk.number == request.disk.number),
            None,
        )
        if current != request.disk:
            raise MountUnavailableError(
                "Параметры нового диска изменились до форматирования."
            )
        control_sender(request.endpoint, "ping", timeout=1.0)
        drive = formatter(
            current,
            expected_size=request.disk.size,
            file_system=request.file_system,
            label=request.label,
        )
        selected_exchange.write_success(response_path, request_id, drive)
        return 0
    except Exception as error:
        try:
            selected_exchange.write_error(response_path, request_id, str(error))
        except Exception:
            pass
        return 1


def _launch_elevated(command: list[str], timeout: float) -> int:
    if sys.platform != "win32":
        raise MountUnavailableError(
            "Форматирование виртуального диска доступно только в Windows."
        )
    if not command:
        raise ValueError("Elevated command must not be empty.")
    from ctypes import wintypes

    class ShellExecuteInfo(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", wintypes.ULONG),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIconOrMonitor", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell_execute = shell32.ShellExecuteExW
    shell_execute.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
    shell_execute.restype = wintypes.BOOL
    wait_for_single_object = kernel32.WaitForSingleObject
    wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    wait_for_single_object.restype = wintypes.DWORD
    get_exit_code = kernel32.GetExitCodeProcess
    get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    get_exit_code.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    info = ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(ShellExecuteInfo)
    info.fMask = _SEE_MASK_NOCLOSEPROCESS | _SEE_MASK_FLAG_NO_UI
    info.lpVerb = "runas"
    info.lpFile = str(Path(command[0]).resolve())
    info.lpParameters = subprocess.list2cmdline(command[1:])
    info.nShow = _SW_HIDE
    if not shell_execute(ctypes.byref(info)):
        code = ctypes.get_last_error()
        if code == 1223:
            raise MountUnavailableError(
                "Форматирование отменено пользователем в запросе Windows."
            )
        raise MountUnavailableError(
            f"Windows не запустила форматирование диска (код {code})."
        )
    if not info.hProcess:
        raise MountUnavailableError(
            "Windows не вернула процесс форматирования диска."
        )
    try:
        timeout_ms = max(1, min(round(timeout * 1000), 0xFFFFFFFE))
        wait_result = wait_for_single_object(info.hProcess, timeout_ms)
        if wait_result == _WAIT_TIMEOUT:
            raise MountUnavailableError(
                "Windows не завершила форматирование диска вовремя."
            )
        if wait_result != _WAIT_OBJECT_0:
            raise MountUnavailableError(
                f"Ожидание процесса Windows завершилось с кодом {wait_result}."
            )
        exit_code = wintypes.DWORD()
        if not get_exit_code(info.hProcess, ctypes.byref(exit_code)):
            raise MountUnavailableError(
                "Windows не сообщила результат форматирования диска."
            )
        return int(exit_code.value)
    finally:
        close_handle(info.hProcess)


def _validate_expected_disk(disk: WindowsDiskInfo) -> None:
    if disk.number < 0 or disk.size <= 0:
        raise MountUnavailableError("Параметры нового диска некорректны.")
    if disk.partition_style.upper() not in ("RAW", "MBR"):
        raise MountUnavailableError(
            "Ожидался новый или подготовленный диск Clever PGP."
        )
    if disk.is_boot or disk.is_system:
        raise MountUnavailableError(
            "Системный или загрузочный диск Windows форматировать запрещено."
        )
    if not any(
        marker in disk.friendly_name.casefold()
        for marker in ("cleverpgp", "winspd")
    ):
        raise MountUnavailableError("Выбранный диск не принадлежит Clever PGP.")


def _is_user_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _normalize_file_system(value: str) -> str:
    normalized = str(value).upper()
    if normalized not in ("NTFS", "EXFAT"):
        raise MountUnavailableError("Файловая система должна быть NTFS или exFAT.")
    return normalized


def _strict_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError("Boolean format field has an invalid type.")
    return value


def _normalize_label(value: str) -> str:
    normalized = str(value).strip() or "Clever PGP"
    if len(normalized) > 32 or any(ord(character) < 32 for character in normalized):
        raise MountUnavailableError("Название диска содержит недопустимые символы.")
    return normalized


def _normalize_drive(value: str) -> str:
    normalized = str(value).strip().upper().rstrip("\\/")
    if len(normalized) == 1 and normalized.isalpha():
        normalized += ":"
    if len(normalized) != 2 or normalized[1] != ":" or not normalized[0].isalpha():
        raise ValueError("Windows drive letter is invalid.")
    return normalized


def _canonical_request(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _token_entropy(request_id: str, volume_id: bytes) -> bytes:
    _validate_request_id(request_id)
    if len(volume_id) != 16:
        raise ValueError("Format volume id must contain 16 bytes.")
    return _TOKEN_ENTROPY_PREFIX + bytes.fromhex(request_id) + volume_id


def _validate_request_id(request_id: str) -> None:
    if len(request_id) != _REQUEST_ID_BYTES * 2 or any(
        character not in "0123456789abcdef" for character in request_id
    ):
        raise MountUnavailableError(
            "Идентификатор запроса форматирования недопустим."
        )


def _request_id_from_name(name: str) -> str:
    if not name.startswith("request-") or not name.endswith(".json"):
        raise MountUnavailableError(
            "Имя запроса форматирования диска недопустимо."
        )
    return name[len("request-") : -len(".json")]


def _request_id_from_untrusted_path(path: Path) -> str:
    try:
        request_id = _request_id_from_name(Path(path).name)
        _validate_request_id(request_id)
        return request_id
    except MountUnavailableError:
        return "0" * (_REQUEST_ID_BYTES * 2)
