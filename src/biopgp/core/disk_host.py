from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from biopgp.config import app_data_directory
from biopgp.core.disk_control import (
    DiskControlEndpoint,
    DiskControlServer,
    send_disk_control_command,
)
from biopgp.core.errors import MountUnavailableError
from biopgp.core.winspd import (
    WinSpdBlockDevice,
    WinSpdError,
    WinSpdLibrary,
    open_windows_block_volume,
)
from biopgp.core.windows_shell import application_command_prefix

HOST_PROTOCOL_VERSION = 1
_REQUEST_ENTROPY_PREFIX = b"Clever PGP detached disk host request v1\0"
_RESPONSE_ENTROPY_PREFIX = b"Clever PGP detached disk host response v1\0"


class HostSecretProtector(Protocol):
    def protect(self, plaintext: bytes, entropy: bytes) -> bytes: ...

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes: ...


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
        master_key: bytes,
        *,
        device_name: str | None,
        dll_path: Path | None,
    ) -> DiskHostRequest:
        if not master_key:
            raise ValueError("Disk host master key must not be empty.")
        request_id = secrets.token_hex(16)
        request_path = self.directory / f"request-{request_id}.json"
        response_path = self.directory / f"response-{request_id}.json"
        protected_key = self._secret_protector().protect(
            master_key,
            _request_entropy(request_id),
        )
        payload = {
            "version": HOST_PROTOCOL_VERSION,
            "request_id": request_id,
            "container_path": str(Path(container_path).expanduser().resolve()),
            "protected_master_key": base64.b64encode(protected_key).decode("ascii"),
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
            if int(payload.get("version", -1)) != HOST_PROTOCOL_VERSION:
                raise ValueError("Disk host request version is unsupported.")
            if str(payload.get("request_id")) != request_id:
                raise ValueError("Disk host request identity does not match its path.")
            container_path = Path(str(payload["container_path"])).resolve()
            protected_key = base64.b64decode(
                str(payload["protected_master_key"]),
                validate=True,
            )
            device_value = payload.get("device_name")
            device_name = str(device_value) if device_value is not None else None
            dll_value = payload.get("dll_path")
            dll_path = Path(str(dll_value)).resolve() if dll_value else None
            master_key = self._secret_protector().unprotect(
                protected_key,
                _request_entropy(request_id),
            )
        finally:
            try:
                source.unlink()
            except FileNotFoundError:
                pass
        return DecodedDiskHostRequest(
            request_id,
            response_path,
            container_path,
            master_key,
            device_name,
            dll_path,
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
        process: subprocess.Popen[Any],
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
            "Самостоятельный процесс системного диска не ответил вовремя."
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
                    str(payload.get("error") or "Не удалось запустить системный диск.")
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
                    "Самостоятельный системный диск доступен только в Windows."
                )
            from biopgp.biometrics.key_protection import WindowsDpapiProtector

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
        self._process: subprocess.Popen[Any] | None = None
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
        master_key: bytes,
        *,
        device_name: str | None = None,
        dll_path: Path | None = None,
        progress: Any = None,
        timeout: float = 20.0,
    ) -> str | None:
        if self.running:
            raise MountUnavailableError(
                "Сначала отключите уже открытый системный диск Clever PGP."
            )
        if progress is not None:
            progress(10, "Защита одноразового запроса диска")
        request = self._exchange.create_request(
            container_path,
            bytes(master_key),
            device_name=device_name,
            dll_path=dll_path,
        )
        command = [*self._command_prefix, "--winspd-host", str(request.request_path)]
        creation_flags = 0
        if sys.platform == "win32":
            creation_flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0,
            )
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=creation_flags,
            )
        except OSError:
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
            self._exchange.cleanup(request)
            raise
        self._process = process
        self._control_endpoint = endpoint
        self._process_id = process_id
        self._device_name = device_name
        if progress is not None:
            progress(100, "Самостоятельный системный диск подключён")
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
            "Системный диск не подтвердил безопасное отключение. "
            "Повторите попытку после завершения операций с файлами."
        )

    def _clear_state(self) -> None:
        self._process = None
        self._control_endpoint = None
        self._process_id = None
        self._device_name = None


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
        volume = open_windows_block_volume(request.container_path, request.master_key)
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
            if server.poll(timeout=0.2) == "stop":
                break
            if device.last_error is not None:
                break
        return 0
    except (OSError, ValueError, WinSpdError, MountUnavailableError) as error:
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
