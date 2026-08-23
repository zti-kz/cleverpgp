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
from typing import Any, Callable, Iterable, Protocol

from biopgp.config import app_data_directory
from biopgp.core.disk_control import DiskControlRecord, DiskControlStore
from biopgp.core.errors import MountUnavailableError
from biopgp.core.windows_shell import application_command_prefix
from biopgp.core.windows_storage import (
    WindowsVolumeInfo,
    WindowsVolumeResizeResult,
    extend_cleverpgp_ntfs_partition,
    inspect_windows_volume,
)

RESIZE_PROTOCOL_VERSION = 1
_REQUEST_ID_BYTES = 16
_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SEE_MASK_FLAG_NO_UI = 0x00000400
_SW_HIDE = 0
_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_TOKEN_SIZE = 32
_TOKEN_ENTROPY_PREFIX = b"Clever PGP Windows resize request v1\0"


class ResizeSecretProtector(Protocol):
    def protect(self, plaintext: bytes, entropy: bytes) -> bytes: ...

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class WindowsResizeRequest:
    request_id: str
    record_path: Path
    volume_id: bytes
    volume: WindowsVolumeInfo


@dataclass(frozen=True, slots=True)
class ResizeExchangePaths:
    request_id: str
    request_path: Path
    response_path: Path


class WindowsResizeExchange:
    """One-time authenticated request crossing only the Windows UAC boundary."""

    def __init__(
        self,
        directory: Path | None = None,
        protector: ResizeSecretProtector | None = None,
    ) -> None:
        self.directory = (
            Path(directory).expanduser().resolve()
            if directory is not None
            else (app_data_directory() / "resize-requests").resolve()
        )
        self._protector = protector

    def create(
        self,
        record: DiskControlRecord,
        volume: WindowsVolumeInfo,
    ) -> ResizeExchangePaths:
        request_id = secrets.token_hex(_REQUEST_ID_BYTES)
        paths = self.paths(request_id)
        authenticated = {
            "version": RESIZE_PROTOCOL_VERSION,
            "request_id": request_id,
            "record_path": str(record.path.expanduser().resolve()),
            "volume_id": record.volume_id.hex(),
            "volume": asdict(volume),
        }
        request_token = secrets.token_bytes(_TOKEN_SIZE)
        protected_token = self._secret_protector().protect(
            request_token,
            _token_entropy(request_id, record.volume_id),
        )
        payload = {
            **authenticated,
            "protected_token": base64.b64encode(protected_token).decode("ascii"),
            "request_mac": hmac.new(
                request_token,
                _canonical_request(authenticated),
                hashlib.sha256,
            ).hexdigest(),
        }
        self.directory.mkdir(parents=True, exist_ok=True)
        self._write_json_atomic(paths.request_path, payload)
        return paths

    def read(self, request_path: Path) -> WindowsResizeRequest:
        source = Path(request_path).expanduser().resolve()
        request_id = self._request_id_from_path(source)
        expected = self.paths(request_id).request_path
        if source != expected:
            raise MountUnavailableError("Путь запроса расширения диска недопустим.")
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("Resize request must be an object.")
            if set(payload) != {
                "version",
                "request_id",
                "record_path",
                "volume_id",
                "volume",
                "protected_token",
                "request_mac",
            }:
                raise ValueError("Resize request fields are invalid.")
            if int(payload.get("version", -1)) != RESIZE_PROTOCOL_VERSION:
                raise ValueError("Resize request version is unsupported.")
            if str(payload.get("request_id")) != request_id:
                raise ValueError("Resize request identity is invalid.")
            volume_id = bytes.fromhex(str(payload["volume_id"]))
            if len(volume_id) != 16:
                raise ValueError("Resize volume id is invalid.")
            record_path = Path(str(payload["record_path"])).expanduser().resolve()
            raw_volume = payload["volume"]
            if not isinstance(raw_volume, dict):
                raise TypeError("Resize volume information must be an object.")
            if set(raw_volume) != {
                "disk_number",
                "partition_number",
                "drive",
                "friendly_name",
                "serial_number",
                "unique_id",
                "bus_type",
                "disk_size",
                "partition_size",
                "partition_offset",
                "partition_style",
                "file_system",
                "data_partition_count",
                "is_boot",
                "is_system",
            }:
                raise ValueError("Resize volume fields are invalid.")
            volume = WindowsVolumeInfo(
                disk_number=int(raw_volume["disk_number"]),
                partition_number=int(raw_volume["partition_number"]),
                drive=str(raw_volume["drive"]),
                friendly_name=str(raw_volume["friendly_name"]),
                serial_number=str(raw_volume["serial_number"]),
                unique_id=str(raw_volume["unique_id"]),
                bus_type=str(raw_volume["bus_type"]),
                disk_size=int(raw_volume["disk_size"]),
                partition_size=int(raw_volume["partition_size"]),
                partition_offset=int(raw_volume["partition_offset"]),
                partition_style=str(raw_volume["partition_style"]),
                file_system=str(raw_volume["file_system"]),
                data_partition_count=int(raw_volume["data_partition_count"]),
                is_boot=_strict_bool(raw_volume["is_boot"]),
                is_system=_strict_bool(raw_volume["is_system"]),
            )
            protected_token = base64.b64decode(
                str(payload["protected_token"]),
                validate=True,
            )
            if not protected_token:
                raise ValueError("Protected resize token is empty.")
            request_token = self._secret_protector().unprotect(
                protected_token,
                _token_entropy(request_id, volume_id),
            )
            if len(request_token) != _TOKEN_SIZE:
                raise ValueError("Resize token has an invalid length.")
            authenticated = {
                "version": RESIZE_PROTOCOL_VERSION,
                "request_id": request_id,
                "record_path": str(record_path),
                "volume_id": volume_id.hex(),
                "volume": asdict(volume),
            }
            expected_mac = hmac.new(
                request_token,
                _canonical_request(authenticated),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(str(payload["request_mac"]), expected_mac):
                raise ValueError("Resize request authentication failed.")
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
                "Запрос расширения системного диска повреждён."
            ) from error
        finally:
            try:
                source.unlink()
            except FileNotFoundError:
                pass
        return WindowsResizeRequest(request_id, record_path, volume_id, volume)

    def write_success(
        self,
        response_path: Path,
        request_id: str,
        result: WindowsVolumeResizeResult,
    ) -> None:
        destination = self._validated_response_path(response_path, request_id)
        self._write_json_atomic(
            destination,
            {
                "version": RESIZE_PROTOCOL_VERSION,
                "request_id": request_id,
                "status": "ok",
                "disk_size": result.disk_size,
                "partition_size": result.partition_size,
                "file_system": result.file_system,
            },
        )

    def write_error(
        self,
        response_path: Path,
        request_id: str,
        message: str,
    ) -> None:
        destination = self._validated_response_path(response_path, request_id)
        self._write_json_atomic(
            destination,
            {
                "version": RESIZE_PROTOCOL_VERSION,
                "request_id": request_id,
                "status": "error",
                "error": str(message)[:4000],
            },
        )

    def consume(self, paths: ResizeExchangePaths) -> WindowsVolumeResizeResult:
        try:
            payload = json.loads(paths.response_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("Resize response must be an object.")
            if int(payload.get("version", -1)) != RESIZE_PROTOCOL_VERSION:
                raise ValueError("Resize response version is unsupported.")
            if str(payload.get("request_id")) != paths.request_id:
                raise ValueError("Resize response identity is invalid.")
            if payload.get("status") == "error":
                raise MountUnavailableError(
                    str(payload.get("error") or "Windows не расширила раздел.")
                )
            if payload.get("status") != "ok":
                raise ValueError("Resize response status is invalid.")
            result = WindowsVolumeResizeResult(
                disk_size=int(payload["disk_size"]),
                partition_size=int(payload["partition_size"]),
                file_system=str(payload["file_system"]),
            )
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
                "Процесс Windows не подтвердил расширение раздела."
            ) from error
        return result

    def cleanup(self, paths: ResizeExchangePaths) -> None:
        for path in (paths.request_path, paths.response_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def paths(self, request_id: str) -> ResizeExchangePaths:
        _validate_request_id(request_id)
        return ResizeExchangePaths(
            request_id,
            self.directory / f"request-{request_id}.json",
            self.directory / f"response-{request_id}.json",
        )

    def _request_id_from_path(self, path: Path) -> str:
        name = path.name
        if not name.startswith("request-") or not name.endswith(".json"):
            raise MountUnavailableError("Имя запроса расширения диска недопустимо.")
        request_id = name[len("request-") : -len(".json")]
        _validate_request_id(request_id)
        return request_id

    def _validated_response_path(self, path: Path, request_id: str) -> Path:
        destination = Path(path).expanduser().resolve()
        if destination != self.paths(request_id).response_path:
            raise MountUnavailableError("Путь ответа расширения диска недопустим.")
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

    def _secret_protector(self) -> ResizeSecretProtector:
        if self._protector is None:
            if sys.platform != "win32":
                raise MountUnavailableError(
                    "Расширение системного диска доступно только в Windows."
                )
            from biopgp.biometrics.key_protection import WindowsDpapiProtector

            self._protector = WindowsDpapiProtector()
        return self._protector


def run_elevated_ntfs_extension(
    record: DiskControlRecord,
    volume: WindowsVolumeInfo,
    *,
    exchange: WindowsResizeExchange | None = None,
    command_prefix: Iterable[str] | None = None,
    launcher: Callable[..., int] | None = None,
    timeout: float = 300.0,
) -> WindowsVolumeResizeResult:
    selected_exchange = exchange or WindowsResizeExchange()
    paths = selected_exchange.create(record, volume)
    prefix = tuple(command_prefix or application_command_prefix())
    if not prefix:
        selected_exchange.cleanup(paths)
        raise MountUnavailableError("Команда Clever PGP для UAC не найдена.")
    command = [
        *prefix,
        "--windows-resize-helper",
        str(paths.request_path),
        str(paths.response_path),
    ]
    selected_launcher = launcher or _launch_elevated
    try:
        exit_code = selected_launcher(command, timeout=timeout)
        if paths.response_path.is_file():
            return selected_exchange.consume(paths)
        if exit_code != 0:
            raise MountUnavailableError(
                "Windows не разрешила расширение раздела Clever PGP."
            )
        raise MountUnavailableError(
            "Процесс Windows завершился без подтверждения расширения раздела."
        )
    finally:
        selected_exchange.cleanup(paths)


def run_windows_resize_helper(
    request_path: Path,
    response_path: Path,
    *,
    exchange: WindowsResizeExchange | None = None,
    control_store: DiskControlStore | None = None,
    administrator_check: Callable[[], bool] | None = None,
) -> int:
    selected_exchange = exchange or WindowsResizeExchange()
    request_id = _request_id_from_untrusted_path(request_path)
    try:
        selected_administrator_check = administrator_check or _is_user_admin
        if not selected_administrator_check():
            raise MountUnavailableError(
                "Расширение не получило разрешение администратора Windows."
            )
        request = selected_exchange.read(request_path)
        if request.request_id != request_id:
            raise MountUnavailableError("Идентификатор запроса расширения изменился.")
        store = control_store or DiskControlStore()
        expected_record_path = (
            store.directory / f"mount-{request.volume_id.hex()}.json"
        ).resolve()
        if request.record_path != expected_record_path:
            raise MountUnavailableError(
                "Запрос не относится к активному диску Clever PGP."
            )
        record = next(
            (
                candidate
                for candidate in store.records()
                if candidate.path.resolve() == expected_record_path
                and candidate.volume_id == request.volume_id
                and candidate.drive == request.volume.drive
            ),
            None,
        )
        if record is None:
            raise MountUnavailableError(
                "Защищённая запись активного диска Clever PGP не найдена."
            )
        store.send(record, "ping", timeout=1.0)
        current = inspect_windows_volume(request.volume.drive)
        if current != request.volume:
            raise MountUnavailableError(
                "Параметры диска изменились после подтверждения операции."
            )
        store.send(record, "ping", timeout=1.0)
        result = extend_cleverpgp_ntfs_partition(
            current,
            expected_disk_size=request.volume.disk_size,
            expected_partition_size=request.volume.partition_size,
        )
        selected_exchange.write_success(response_path, request_id, result)
        return 0
    except Exception as error:
        try:
            selected_exchange.write_error(response_path, request_id, str(error))
        except Exception:
            pass
        return 1


def _launch_elevated(command: list[str], *, timeout: float) -> int:
    if sys.platform != "win32":
        raise MountUnavailableError(
            "Расширение системного диска доступно только в Windows."
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
                "Расширение отменено пользователем в запросе Windows."
            )
        raise MountUnavailableError(
            f"Windows не запустила защищённую операцию (код {code})."
        )
    if not info.hProcess:
        raise MountUnavailableError("Windows не вернула процесс расширения диска.")
    try:
        timeout_ms = max(1, min(round(timeout * 1000), 0xFFFFFFFE))
        wait_result = wait_for_single_object(info.hProcess, timeout_ms)
        if wait_result == _WAIT_TIMEOUT:
            raise MountUnavailableError(
                "Windows не завершила расширение раздела вовремя."
            )
        if wait_result != _WAIT_OBJECT_0:
            raise MountUnavailableError(
                f"Ожидание процесса Windows завершилось с кодом {wait_result}."
            )
        exit_code = wintypes.DWORD()
        if not get_exit_code(info.hProcess, ctypes.byref(exit_code)):
            raise MountUnavailableError(
                "Windows не сообщила результат расширения раздела."
            )
        return int(exit_code.value)
    finally:
        close_handle(info.hProcess)


def _strict_bool(value: Any) -> bool:
    if not isinstance(value, bool):
        raise TypeError("Boolean resize field has an invalid type.")
    return value


def _is_user_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


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
        raise ValueError("Resize volume id must contain 16 bytes.")
    return _TOKEN_ENTROPY_PREFIX + bytes.fromhex(request_id) + volume_id


def _validate_request_id(request_id: str) -> None:
    if len(request_id) != _REQUEST_ID_BYTES * 2 or any(
        character not in "0123456789abcdef" for character in request_id
    ):
        raise MountUnavailableError("Идентификатор запроса расширения недопустим.")


def _request_id_from_untrusted_path(path: Path) -> str:
    name = Path(path).name
    if not name.startswith("request-") or not name.endswith(".json"):
        return "0" * (_REQUEST_ID_BYTES * 2)
    request_id = name[len("request-") : -len(".json")]
    try:
        _validate_request_id(request_id)
    except MountUnavailableError:
        return "0" * (_REQUEST_ID_BYTES * 2)
    return request_id
