from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from biopgp.config import app_data_directory
from biopgp.core.errors import BioPGPError, MountUnavailableError

CONTROL_PROTOCOL_VERSION = 1
CONTROL_TOKEN_SIZE = 32
_CONTROL_MAGIC = b"CPGC\x01"
_CONTROL_COMMANDS = {"ping": b"P", "stop": b"S"}
_CONTROL_RESPONSES = {True: b"OK", False: b"NO"}
_CONTROL_ENTROPY_PREFIX = b"Clever PGP disk control state v1\0"
_CONTAINER_PATH_ENTROPY_PREFIX = b"Clever PGP mounted container path v1\0"


class SecretProtector(Protocol):
    def protect(self, plaintext: bytes, entropy: bytes) -> bytes: ...

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class DiskControlEndpoint:
    volume_id: bytes
    port: int
    token: bytes

    def __post_init__(self) -> None:
        if len(self.volume_id) != 16:
            raise ValueError("Disk control volume id must contain 16 bytes.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Disk control port is invalid.")
        if len(self.token) != CONTROL_TOKEN_SIZE:
            raise ValueError("Disk control token has an invalid length.")


@dataclass(frozen=True, slots=True)
class DiskControlRecord:
    volume_id: bytes
    drive: str
    port: int
    process_id: int
    protected_token: bytes
    path: Path
    protected_container_path: bytes | None = None


class DiskControlServer:
    """Authenticated loopback control endpoint owned by the disk host process."""

    def __init__(self, *, token: bytes | None = None) -> None:
        selected_token = token or secrets.token_bytes(CONTROL_TOKEN_SIZE)
        if len(selected_token) != CONTROL_TOKEN_SIZE:
            raise ValueError("Disk control token has an invalid length.")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            server.bind(("127.0.0.1", 0))
            server.listen(4)
        except Exception:
            server.close()
            raise
        self._server = server
        self.token = bytes(selected_token)
        self.port = int(server.getsockname()[1])

    def poll(self, *, timeout: float = 0.2) -> str | None:
        self._server.settimeout(max(0.0, timeout))
        try:
            connection, _address = self._server.accept()
        except TimeoutError:
            return None
        with connection:
            connection.settimeout(0.75)
            try:
                request = _receive_exact(
                    connection,
                    len(_CONTROL_MAGIC) + CONTROL_TOKEN_SIZE + 1,
                )
            except (OSError, ConnectionError, TimeoutError):
                return None
            command_byte = request[-1:]
            command = next(
                (
                    name
                    for name, encoded in _CONTROL_COMMANDS.items()
                    if encoded == command_byte
                ),
                None,
            )
            accepted = (
                request.startswith(_CONTROL_MAGIC)
                and secrets.compare_digest(
                    request[len(_CONTROL_MAGIC) : -1],
                    self.token,
                )
                and command is not None
            )
            try:
                connection.sendall(_CONTROL_RESPONSES[accepted])
            except OSError:
                return None
            return command if accepted else None

    def close(self) -> None:
        self._server.close()

    def __enter__(self) -> DiskControlServer:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def send_disk_control_command(
    endpoint: DiskControlEndpoint,
    command: str,
    *,
    timeout: float = 3.0,
) -> None:
    command_byte = _CONTROL_COMMANDS.get(command)
    if command_byte is None:
        raise ValueError("Unknown disk control command.")
    try:
        with socket.create_connection(
            ("127.0.0.1", endpoint.port),
            timeout=max(0.1, timeout),
        ) as connection:
            connection.settimeout(max(0.1, timeout))
            connection.sendall(_CONTROL_MAGIC + endpoint.token + command_byte)
            response = _receive_exact(connection, 2)
    except (OSError, TimeoutError) as error:
        raise MountUnavailableError(
            "Фоновый процесс системного диска Clever PGP не отвечает."
        ) from error
    if response != _CONTROL_RESPONSES[True]:
        raise MountUnavailableError(
            "Фоновый процесс отклонил команду управления диском."
        )


class DiskControlStore:
    """Current-user state used by Explorer commands to find a mounted disk."""

    def __init__(
        self,
        directory: Path | None = None,
        protector: SecretProtector | None = None,
    ) -> None:
        self.directory = (
            Path(directory).expanduser().resolve()
            if directory is not None
            else app_data_directory() / "mounted-disks"
        )
        self._protector = protector

    def publish(
        self,
        endpoint: DiskControlEndpoint,
        *,
        drive: str,
        process_id: int,
        container_path: Path | None = None,
    ) -> DiskControlRecord:
        normalized_drive = _normalize_drive(drive)
        if process_id <= 0:
            raise ValueError("Disk host process id must be positive.")
        protected_token = self._secret_protector().protect(
            endpoint.token,
            _control_entropy(endpoint.volume_id),
        )
        protected_container_path: bytes | None = None
        if container_path is not None:
            resolved_container = Path(container_path).expanduser().resolve()
            encoded_container = str(resolved_container).encode("utf-8")
            if not encoded_container or len(encoded_container) > 32 * 1024:
                raise ValueError("Mounted container path has an invalid length.")
            protected_container_path = self._secret_protector().protect(
                encoded_container,
                _container_path_entropy(endpoint.volume_id),
            )
        payload = {
            "version": CONTROL_PROTOCOL_VERSION,
            "volume_id": endpoint.volume_id.hex(),
            "drive": normalized_drive,
            "port": endpoint.port,
            "process_id": process_id,
            "protected_token": base64.b64encode(protected_token).decode("ascii"),
        }
        if protected_container_path is not None:
            payload["protected_container_path"] = base64.b64encode(
                protected_container_path
            ).decode("ascii")
        self.directory.mkdir(parents=True, exist_ok=True)
        destination = self._record_path(endpoint.volume_id)
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
        return DiskControlRecord(
            volume_id=endpoint.volume_id,
            drive=normalized_drive,
            port=endpoint.port,
            process_id=process_id,
            protected_token=protected_token,
            path=destination,
            protected_container_path=protected_container_path,
        )

    def find_by_drive(self, drive: str) -> DiskControlRecord | None:
        normalized_drive = _normalize_drive(drive)
        for record in self.records():
            if record.drive == normalized_drive:
                return record
        return None

    def records(self) -> tuple[DiskControlRecord, ...]:
        """Return only structurally valid current-user mount records."""

        records: list[DiskControlRecord] = []
        for path in self._state_paths():
            record = self._read_record(path)
            if record is not None:
                records.append(record)
        return tuple(records)

    def endpoint(self, record: DiskControlRecord) -> DiskControlEndpoint:
        token = self._secret_protector().unprotect(
            record.protected_token,
            _control_entropy(record.volume_id),
        )
        return DiskControlEndpoint(record.volume_id, record.port, token)

    def container_path(self, record: DiskControlRecord) -> Path | None:
        protected = record.protected_container_path
        if protected is None:
            return None
        try:
            encoded = self._secret_protector().unprotect(
                protected,
                _container_path_entropy(record.volume_id),
            )
            decoded = encoded.decode("utf-8")
            if not decoded or "\x00" in decoded:
                raise ValueError("Mounted container path is invalid.")
            return Path(decoded).expanduser().resolve()
        except (BioPGPError, OSError, UnicodeError, ValueError) as error:
            raise MountUnavailableError(
                "Защищённый путь системного диска повреждён или недоступен."
            ) from error

    def send(
        self,
        record: DiskControlRecord,
        command: str,
        *,
        timeout: float = 3.0,
    ) -> None:
        try:
            endpoint = self.endpoint(record)
        except (BioPGPError, OSError, ValueError) as error:
            raise MountUnavailableError(
                "Защищённая запись системного диска повреждена или недоступна."
            ) from error
        send_disk_control_command(endpoint, command, timeout=timeout)

    @staticmethod
    def remove(record: DiskControlRecord | None) -> None:
        if record is None:
            return
        try:
            record.path.unlink()
        except FileNotFoundError:
            pass

    def _read_record(self, path: Path) -> DiskControlRecord | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                return None
            if int(payload.get("version", -1)) != CONTROL_PROTOCOL_VERSION:
                return None
            volume_id = bytes.fromhex(str(payload["volume_id"]))
            drive = _normalize_drive(str(payload["drive"]))
            port = int(payload["port"])
            process_id = int(payload["process_id"])
            protected_token = base64.b64decode(
                str(payload["protected_token"]),
                validate=True,
            )
            encoded_container_path = payload.get("protected_container_path")
            protected_container_path = (
                None
                if encoded_container_path is None
                else base64.b64decode(
                    str(encoded_container_path),
                    validate=True,
                )
            )
            if len(volume_id) != 16 or not 1 <= port <= 65535 or process_id <= 0:
                return None
            if not protected_token:
                return None
            if protected_container_path == b"":
                return None
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            return None
        return DiskControlRecord(
            volume_id,
            drive,
            port,
            process_id,
            protected_token,
            path,
            protected_container_path,
        )

    def _state_paths(self) -> tuple[Path, ...]:
        try:
            return tuple(sorted(self.directory.glob("mount-*.json")))
        except OSError:
            return ()

    def _record_path(self, volume_id: bytes) -> Path:
        return self.directory / f"mount-{volume_id.hex()}.json"

    def _secret_protector(self) -> SecretProtector:
        if self._protector is None:
            if sys.platform != "win32":
                raise MountUnavailableError(
                    "Управление системным диском доступно только в Windows."
                )
            from biopgp.biometrics.key_protection import WindowsDpapiProtector

            self._protector = WindowsDpapiProtector()
        return self._protector


def _control_entropy(volume_id: bytes) -> bytes:
    if len(volume_id) != 16:
        raise ValueError("Disk control volume id must contain 16 bytes.")
    return _CONTROL_ENTROPY_PREFIX + volume_id


def _container_path_entropy(volume_id: bytes) -> bytes:
    if len(volume_id) != 16:
        raise ValueError("Disk control volume id must contain 16 bytes.")
    return _CONTAINER_PATH_ENTROPY_PREFIX + volume_id


def _normalize_drive(drive: str) -> str:
    normalized = str(drive).strip().upper().rstrip("\\/")
    if len(normalized) == 1:
        normalized += ":"
    if (
        len(normalized) != 2
        or normalized[1] != ":"
        or not normalized[0].isalpha()
    ):
        raise ValueError("Invalid disk drive letter.")
    return normalized


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    payload = bytearray()
    while len(payload) < size:
        chunk = connection.recv(size - len(payload))
        if not chunk:
            raise ConnectionError("Disk control connection closed unexpectedly.")
        payload.extend(chunk)
    return bytes(payload)
