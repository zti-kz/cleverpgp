from __future__ import annotations

import base64
import ctypes
import hmac
import json
import os
import secrets
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cleverpgp.config import app_data_directory
from cleverpgp.core.block_volume import BlockVolumeError
from cleverpgp.core.disk_control import (
    DiskControlEndpoint,
    DiskControlServer,
    send_disk_control_command,
)
from cleverpgp.core.errors import MountUnavailableError, ValidationError
from cleverpgp.core.hidden_volume import HiddenVolumeDescriptor
from cleverpgp.core.opaque_block_volume import OpaqueBlockVolume
from cleverpgp.core.volume_path import resolve_file_hosted_container_path
from cleverpgp.core.opaque_volume_header import (
    PROTECTED_TRANSFER_SIZE,
    OpaqueVolumeHeader,
    OpaqueVolumeHeaderStore,
)
from cleverpgp.core.winspd import (
    WINDOWS_BLOCK_STORAGE_FORMAT,
    WinSpdBlockDevice,
    WinSpdError,
    WinSpdLibrary,
    open_windows_block_volume,
)
from cleverpgp.core.windows_shell import application_command_prefix

HOST_PROTOCOL_VERSION = 2
LEGACY_HOST_PROTOCOL_VERSION = 1
_REQUEST_ENTROPY_PREFIX = b"Clever PGP detached disk host request v1\0"
_RESPONSE_ENTROPY_PREFIX = b"Clever PGP detached disk host response v1\0"
_OPAQUE_ACCESS_PREFIX = struct.Struct(">8sB")
_OPAQUE_ACCESS_MAGIC = b"CPGPHST1"
_ACCESS_MODE_LEGACY = "legacy_master_key"
_ACCESS_MODE_OPAQUE = "opaque_header"


class HostSecretProtector(Protocol):
    def protect(self, plaintext: bytes, entropy: bytes) -> bytes: ...

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes: ...


class HostProcess(Protocol):
    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


@dataclass(frozen=True, slots=True)
class DiskHostRequest:
    request_id: str
    request_path: Path
    response_path: Path


@dataclass(frozen=True, slots=True)
class DecodedDiskHostRequest:
    request_id: str
    response_path: Path
    container_path: Path
    master_key: bytes
    device_name: str | None
    dll_path: Path | None
    opaque_header: OpaqueVolumeHeader | None = None
    protection_header: OpaqueVolumeHeader | None = None


class DiskHostExchange:
    """One-time DPAPI-protected bootstrap between the GUI and detached host."""

    def __init__(
        self,
        directory: Path | None = None,
        protector: HostSecretProtector | None = None,
    ) -> None:
        self.directory = (
            Path(directory).expanduser().resolve()
            if directory is not None
            else app_data_directory() / "disk-host"
        )
        self._protector = protector

    def create_request(
        self,
        container_path: Path,
        master_key: bytes | None,
        *,
        device_name: str | None,
        dll_path: Path | None,
        opaque_header: OpaqueVolumeHeader | None = None,
        protection_header: OpaqueVolumeHeader | None = None,
    ) -> DiskHostRequest:
        if opaque_header is None:
            if not master_key or protection_header is not None:
                raise ValueError("Disk host master key must not be empty.")
            access_mode = _ACCESS_MODE_LEGACY
            access_material = bytes(master_key)
        else:
            if master_key not in (None, b""):
                raise ValueError("Only one disk host access mode can be used.")
            access_mode = _ACCESS_MODE_OPAQUE
            access_material = _encode_opaque_access(
                opaque_header,
                protection_header,
            )
        request_id = secrets.token_hex(16)
        request_path = self.directory / f"request-{request_id}.json"
        response_path = self.directory / f"response-{request_id}.json"
        protected_access = self._secret_protector().protect(
            access_material,
            _request_entropy(request_id),
        )
        payload = {
            "version": HOST_PROTOCOL_VERSION,
            "request_id": request_id,
            "container_path": str(Path(container_path).expanduser().resolve()),
            "access_mode": access_mode,
            "protected_access_material": base64.b64encode(
                protected_access
            ).decode("ascii"),
            "device_name": device_name,
            "dll_path": (
                str(Path(dll_path).expanduser().resolve())
                if dll_path is not None
                else None
            ),
        }
        self.directory.mkdir(parents=True, exist_ok=True)
        self._write_json_atomic(request_path, payload)
        return DiskHostRequest(request_id, request_path, response_path)

    def consume_request(self, request_path: Path) -> DecodedDiskHostRequest:
        source = Path(request_path).expanduser().resolve()
        request_id = _request_id_from_path(source)
        response_path = source.parent / f"response-{request_id}.json"
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Disk host request must be an object.")
            version = int(payload.get("version", -1))
            if version not in (
                LEGACY_HOST_PROTOCOL_VERSION,
                HOST_PROTOCOL_VERSION,
            ):
                raise ValueError("Disk host request version is unsupported.")
            if str(payload.get("request_id")) != request_id:
                raise ValueError("Disk host request identity does not match its path.")
            container_path = Path(str(payload["container_path"])).resolve()
            access_mode = (
                _ACCESS_MODE_LEGACY
                if version == LEGACY_HOST_PROTOCOL_VERSION
                else str(payload.get("access_mode"))
            )
            protected_field = (
                "protected_master_key"
                if version == LEGACY_HOST_PROTOCOL_VERSION
                else "protected_access_material"
            )
            protected_access = base64.b64decode(
                str(payload[protected_field]),
                validate=True,
            )
            device_value = payload.get("device_name")
            device_name = str(device_value) if device_value is not None else None
            dll_value = payload.get("dll_path")
            dll_path = Path(str(dll_value)).resolve() if dll_value else None
            access_material = self._secret_protector().unprotect(
                protected_access,
                _request_entropy(request_id),
            )
        finally:
            try:
                source.unlink()
            except FileNotFoundError:
                pass
        if access_mode == _ACCESS_MODE_LEGACY:
            if not access_material:
                raise ValueError("Disk host master key is empty.")
            master_key = access_material
            opaque_header = None
            protection_header = None
        elif access_mode == _ACCESS_MODE_OPAQUE:
            master_key = b""
            opaque_header, protection_header = _decode_opaque_access(
                access_material
            )
        else:
            raise ValueError("Disk host access mode is unsupported.")
        return DecodedDiskHostRequest(
            request_id,
            response_path,
            container_path,
            master_key,
            device_name,
            dll_path,
            opaque_header,
            protection_header,
        )

    def write_ready(
        self,
        request: DecodedDiskHostRequest,
        endpoint: DiskControlEndpoint,
    ) -> None:
        protected_token = self._secret_protector().protect(
            endpoint.token,
            _response_entropy(request.request_id),
        )
        self._write_json_atomic(
            request.response_path,
            {
                "version": HOST_PROTOCOL_VERSION,
                "status": "ready",
                "request_id": request.request_id,
                "process_id": os.getpid(),
                "volume_id": endpoint.volume_id.hex(),
                "port": endpoint.port,
                "protected_token": base64.b64encode(protected_token).decode("ascii"),
            },
        )

    def write_error(self, response_path: Path, request_id: str, error: str) -> None:
        self._write_json_atomic(
            response_path,
            {
                "version": HOST_PROTOCOL_VERSION,
                "status": "error",
                "request_id": request_id,
                "error": str(error),
            },
        )

    def wait_response(
        self,
        request: DiskHostRequest,
        *,
        timeout: float,
        process: HostProcess,
    ) -> tuple[DiskControlEndpoint, int]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if request.response_path.is_file():
                return self._consume_response(request)
            if process.poll() is not None:
                break
            time.sleep(0.05)
        if request.response_path.is_file():
            return self._consume_response(request)
        raise MountUnavailableError(
            "Самостоятельный процесс виртуального диска не ответил вовремя."
        )

    def cleanup(self, request: DiskHostRequest) -> None:
        for path in (request.request_path, request.response_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _consume_response(
        self,
        request: DiskHostRequest,
    ) -> tuple[DiskControlEndpoint, int]:
        try:
            payload = json.loads(request.response_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Disk host response must be an object.")
            if int(payload.get("version", -1)) != HOST_PROTOCOL_VERSION:
                raise ValueError("Disk host response version is unsupported.")
            if str(payload.get("request_id")) != request.request_id:
                raise ValueError("Disk host response identity is invalid.")
            if payload.get("status") == "error":
                raise MountUnavailableError(
                    str(payload.get("error") or "Не удалось запустить виртуальный диск.")
                )
            if payload.get("status") != "ready":
                raise ValueError("Disk host response status is invalid.")
            process_id = int(payload["process_id"])
            volume_id = bytes.fromhex(str(payload["volume_id"]))
            port = int(payload["port"])
            protected_token = base64.b64decode(
                str(payload["protected_token"]),
                validate=True,
            )
            token = self._secret_protector().unprotect(
                protected_token,
                _response_entropy(request.request_id),
            )
            if process_id <= 0:
                raise ValueError("Disk host process id is invalid.")
            endpoint = DiskControlEndpoint(volume_id, port, token)
        except MountUnavailableError:
            raise
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
            raise MountUnavailableError(
                "Самостоятельный процесс вернул некорректный ответ."
            ) from error
        finally:
            try:
                request.response_path.unlink()
            except FileNotFoundError:
                pass
        return endpoint, process_id

    def _write_json_atomic(self, destination: Path, payload: dict[str, object]) -> None:
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

    def _secret_protector(self) -> HostSecretProtector:
        if self._protector is None:
            if sys.platform != "win32":
                raise MountUnavailableError(
                    "Самостоятельный виртуальный диск доступен только в Windows."
                )
            from cleverpgp.biometrics.key_protection import WindowsDpapiProtector

            self._protector = WindowsDpapiProtector()
        return self._protector


class WinSpdHostManager:
    """Launch a detached Clever PGP disk host that outlives the GUI process."""

    def __init__(
        self,
        exchange: DiskHostExchange | None = None,
        *,
        command_prefix: tuple[str, ...] | None = None,
    ) -> None:
        self._exchange = exchange or DiskHostExchange()
        self._command_prefix = command_prefix or application_command_prefix()
        self._process: HostProcess | None = None
        self._control_endpoint: DiskControlEndpoint | None = None
        self._process_id: int | None = None
        self._device_name: str | None = None

    @property
    def running(self) -> bool:
        endpoint = self._control_endpoint
        if endpoint is None:
            return False
        try:
            send_disk_control_command(endpoint, "ping", timeout=0.5)
            return True
        except MountUnavailableError:
            process = self._process
            if process is not None and process.poll() is None:
                return True
            self._clear_state()
            return False

    @property
    def control_endpoint(self) -> DiskControlEndpoint | None:
        return self._control_endpoint if self.running else None

    @property
    def process_id(self) -> int | None:
        return self._process_id if self.running else None

    @property
    def device_name(self) -> str | None:
        return self._device_name if self.running else None

    def start(
        self,
        container_path: Path,
        master_key: bytes | None,
        *,
        device_name: str | None = None,
        dll_path: Path | None = None,
        opaque_header: OpaqueVolumeHeader | None = None,
        protection_header: OpaqueVolumeHeader | None = None,
        progress: Any = None,
        timeout: float = 20.0,
    ) -> str | None:
        if self.running:
            raise MountUnavailableError(
                "Сначала отключите уже открытый виртуальный диск Clever PGP."
            )
        if progress is not None:
            progress(10, "Защита одноразового запроса диска")
        request = self._exchange.create_request(
            container_path,
            bytes(master_key) if master_key is not None else None,
            device_name=device_name,
            dll_path=dll_path,
            opaque_header=opaque_header,
            protection_header=protection_header,
        )
        command = [*self._command_prefix, "--winspd-host", str(request.request_path)]
        try:
            process = _launch_host_process(
                command,
                elevate=(
                    sys.platform == "win32"
                    and device_name is None
                    and not _is_user_admin()
                ),
            )
        except Exception:
            self._exchange.cleanup(request)
            raise
        if progress is not None:
            progress(35, "Запуск самостоятельного процесса диска")
        try:
            endpoint, process_id = self._exchange.wait_response(
                request,
                timeout=timeout,
                process=process,
            )
            send_disk_control_command(endpoint, "ping")
        except Exception:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(3)
                except subprocess.TimeoutExpired:
                    process.kill()
            close_process = getattr(process, "close", None)
            if callable(close_process):
                close_process()
            self._exchange.cleanup(request)
            raise
        self._process = process
        self._control_endpoint = endpoint
        self._process_id = process_id
        self._device_name = device_name
        if progress is not None:
            progress(100, "Самостоятельный виртуальный диск подключён")
        return device_name

    def stop(self, *, timeout: float = 12.0) -> None:
        endpoint = self._control_endpoint
        if endpoint is None:
            self._clear_state()
            return
        try:
            send_disk_control_command(endpoint, "stop")
        except MountUnavailableError:
            pass
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                send_disk_control_command(endpoint, "ping", timeout=0.25)
            except MountUnavailableError:
                self._clear_state()
                return
            time.sleep(0.05)
        raise MountUnavailableError(
            "Виртуальный диск не подтвердил безопасное отключение. "
            "Повторите попытку после завершения операций с файлами."
        )

    def verify_healthy(self, *, timeout: float = 1.0) -> None:
        endpoint = self._control_endpoint
        if endpoint is None:
            raise MountUnavailableError(
                "Виртуальный диск не предоставил канал проверки состояния."
            )
        send_disk_control_command(endpoint, "ping", timeout=timeout)

    def _clear_state(self) -> None:
        process = self._process
        close_process = getattr(process, "close", None)
        if callable(close_process):
            close_process()
        self._process = None
        self._control_endpoint = None
        self._process_id = None
        self._device_name = None


def _is_user_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _launch_host_process(
    command: list[str],
    *,
    elevate: bool,
) -> HostProcess:
    if elevate:
        return _launch_elevated_windows_process(command)
    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0,
        )
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creation_flags,
    )


class _ElevatedWindowsProcess:
    """Small Popen-compatible owner for a ShellExecuteEx process handle."""

    def __init__(self, handle: int, process_id: int) -> None:
        self._handle = handle
        self.pid = process_id
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if not self._handle:
            return self.returncode
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if kernel32.WaitForSingleObject(ctypes.c_void_p(self._handle), 0) == 258:
            return None
        exit_code = ctypes.c_uint32()
        if not kernel32.GetExitCodeProcess(
            ctypes.c_void_p(self._handle),
            ctypes.byref(exit_code),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        self.returncode = int(exit_code.value)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if not self._handle:
            return int(self.returncode or 0)
        milliseconds = (
            0xFFFFFFFF
            if timeout is None
            else max(0, round(timeout * 1000))
        )
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        result = kernel32.WaitForSingleObject(
            ctypes.c_void_p(self._handle),
            milliseconds,
        )
        if result == 258:
            raise subprocess.TimeoutExpired(
                "elevated Clever PGP disk host",
                timeout,
            )
        if result == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        return int(self.poll() or 0)

    def terminate(self) -> None:
        if not self._handle or self.poll() is not None:
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if not kernel32.TerminateProcess(ctypes.c_void_p(self._handle), 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def kill(self) -> None:
        self.terminate()

    def close(self) -> None:
        if not self._handle:
            return
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(
            ctypes.c_void_p(self._handle)
        )
        self._handle = 0

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _launch_elevated_windows_process(command: list[str]) -> HostProcess:
    if sys.platform != "win32" or not command:
        raise MountUnavailableError(
            "Повышенный запуск виртуального диска доступен только в Windows."
        )
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
            ("lpIDList", wintypes.LPVOID),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIcon", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    info = ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = command[0]
    info.lpParameters = subprocess.list2cmdline(command[1:])
    info.lpDirectory = str(Path(command[0]).resolve().parent)
    info.nShow = 0
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        error_code = ctypes.get_last_error()
        if error_code == 1223:
            raise MountUnavailableError(
                "Подключение диска отменено: Windows не получила разрешение."
            )
        raise MountUnavailableError(
            f"Windows не запустила компонент виртуального диска (код {error_code})."
        )
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel32.GetProcessId.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    process_id = int(kernel32.GetProcessId(info.hProcess))
    if process_id <= 0:
        kernel32.CloseHandle(info.hProcess)
        raise MountUnavailableError(
            "Windows не подтвердила запуск компонента виртуального диска."
        )
    return _ElevatedWindowsProcess(int(info.hProcess), process_id)


def run_disk_host(request_path: Path) -> int:
    exchange = DiskHostExchange(Path(request_path).expanduser().resolve().parent)
    request_id = _request_id_from_path(Path(request_path).expanduser().resolve())
    response_path = exchange.directory / f"response-{request_id}.json"
    request: DecodedDiskHostRequest | None = None
    volume: Any = None
    device: WinSpdBlockDevice | None = None
    server: DiskControlServer | None = None
    try:
        request = exchange.consume_request(request_path)
        if request.opaque_header is None:
            volume = open_windows_block_volume(
                request.container_path,
                request.master_key,
            )
        else:
            protected_descriptor = _validated_protection_descriptor(request)
            container_path = resolve_file_hosted_container_path(
                request.container_path
            )
            volume = OpaqueBlockVolume.open_with_header(
                container_path,
                request.opaque_header,
                protected_hidden_descriptor=protected_descriptor,
            )
            if volume.storage_format != WINDOWS_BLOCK_STORAGE_FORMAT:
                volume.close()
                volume = None
                raise WinSpdError(
                    "Это не виртуальный зашифрованный диск Clever PGP."
                )
        mapped_io = getattr(volume, "enable_mapped_io", None)
        if callable(mapped_io):
            mapped_io()
        server = DiskControlServer()
        device = WinSpdBlockDevice(
            volume,
            library=WinSpdLibrary(request.dll_path),
            pipe_name=request.device_name,
        )
        device.start()
        endpoint = DiskControlEndpoint(volume.volume_id, server.port, server.token)
        exchange.write_ready(request, endpoint)
        request = DecodedDiskHostRequest(
            request.request_id,
            request.response_path,
            request.container_path,
            b"",
            request.device_name,
            request.dll_path,
        )
        while True:
            if server.poll(
                timeout=0.2,
                accept=lambda: device.last_error is None,
            ) == "stop":
                break
            if device.last_error is not None:
                break
        return 0
    except (
        OSError,
        ValueError,
        BlockVolumeError,
        ValidationError,
        WinSpdError,
        MountUnavailableError,
    ) as error:
        exchange.write_error(response_path, request_id, str(error))
        return 1
    finally:
        if server is not None:
            server.close()
        if device is not None:
            device.stop()
        if volume is not None:
            volume.close()
        if request is not None:
            request = DecodedDiskHostRequest(
                request.request_id,
                request.response_path,
                request.container_path,
                b"",
                request.device_name,
                request.dll_path,
            )


def _request_id_from_path(path: Path) -> str:
    name = Path(path).name
    if not name.startswith("request-") or not name.endswith(".json"):
        raise ValueError("Disk host request path is invalid.")
    request_id = name[len("request-") : -len(".json")]
    if len(request_id) != 32 or any(
        character not in "0123456789abcdef" for character in request_id
    ):
        raise ValueError("Disk host request identity is invalid.")
    return request_id


def _request_entropy(request_id: str) -> bytes:
    return _REQUEST_ENTROPY_PREFIX + bytes.fromhex(request_id)


def _response_entropy(request_id: str) -> bytes:
    return _RESPONSE_ENTROPY_PREFIX + bytes.fromhex(request_id)


def _encode_opaque_access(
    selected_header: OpaqueVolumeHeader,
    protection_header: OpaqueVolumeHeader | None,
) -> bytes:
    if protection_header is not None:
        _validate_opaque_protection_headers(selected_header, protection_header)
    headers = [selected_header]
    if protection_header is not None:
        headers.append(protection_header)
    return _OPAQUE_ACCESS_PREFIX.pack(_OPAQUE_ACCESS_MAGIC, len(headers)) + b"".join(
        OpaqueVolumeHeaderStore.serialize_for_protected_transfer(header)
        for header in headers
    )


def _decode_opaque_access(
    payload: bytes,
) -> tuple[OpaqueVolumeHeader, OpaqueVolumeHeader | None]:
    if len(payload) < _OPAQUE_ACCESS_PREFIX.size:
        raise ValueError("Opaque disk host material is truncated.")
    magic, count = _OPAQUE_ACCESS_PREFIX.unpack(
        payload[: _OPAQUE_ACCESS_PREFIX.size]
    )
    if magic != _OPAQUE_ACCESS_MAGIC or count not in (1, 2):
        raise ValueError("Opaque disk host material is invalid.")
    expected_size = _OPAQUE_ACCESS_PREFIX.size + count * PROTECTED_TRANSFER_SIZE
    if len(payload) != expected_size:
        raise ValueError("Opaque disk host material has an invalid length.")
    headers: list[OpaqueVolumeHeader] = []
    cursor = _OPAQUE_ACCESS_PREFIX.size
    for _ in range(count):
        headers.append(
            OpaqueVolumeHeaderStore.deserialize_protected_transfer(
                payload[cursor : cursor + PROTECTED_TRANSFER_SIZE]
            )
        )
        cursor += PROTECTED_TRANSFER_SIZE
    selected = headers[0]
    protection = headers[1] if len(headers) == 2 else None
    if protection is not None:
        _validate_opaque_protection_headers(selected, protection)
    return selected, protection


def _validate_opaque_protection_headers(
    selected_header: OpaqueVolumeHeader,
    protection_header: OpaqueVolumeHeader,
) -> None:
    if (
        selected_header.role != "outer"
        or protection_header.role != "hidden"
        or protection_header.hidden_descriptor is None
        or selected_header.cover_volume_id != protection_header.cover_volume_id
        or selected_header.cover_block_count != protection_header.cover_block_count
        or not hmac.compare_digest(
            selected_header.cover_key,
            protection_header.cover_key,
        )
    ):
        raise ValueError("Hidden protection material does not match the outer disk.")


def _validated_protection_descriptor(
    request: DecodedDiskHostRequest,
) -> HiddenVolumeDescriptor | None:
    protection = request.protection_header
    if protection is None:
        return None
    selected = request.opaque_header
    if selected is None:
        raise ValueError("Opaque protection requires an opaque selected header.")
    _validate_opaque_protection_headers(selected, protection)
    return protection.hidden_descriptor
