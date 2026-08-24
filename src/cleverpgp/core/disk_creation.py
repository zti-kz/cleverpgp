from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Protocol

from cleverpgp.config import app_data_directory
from cleverpgp.core.errors import MountUnavailableError
from cleverpgp.core.windows_shell import application_command_prefix

CREATION_PROTOCOL_VERSION = 1
_REQUEST_ID_BYTES = 16
_RESPONSE_TOKEN_BYTES = 32
_REQUEST_ENTROPY_PREFIX = b"Clever PGP disk creation request v1\0"
_ORDINARY = "ordinary"
_HIDDEN = "hidden"


class CreationSecretProtector(Protocol):
    def protect(self, plaintext: bytes, entropy: bytes) -> bytes: ...

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class DiskCreationPaths:
    request_id: str
    request_path: Path
    progress_path: Path
    response_path: Path
    response_token: bytes


@dataclass(frozen=True, slots=True)
class DiskCreationRequest:
    request_id: str
    progress_path: Path
    response_path: Path
    response_token: bytes
    kind: str
    container_path: Path
    master_key: bytes | None
    password: str | None
    logical_capacity: int | None
    label: str | None
    algorithm: str | None
    file_system: str
    overwrite: bool
    context_menu_labels: tuple[str, ...] | None
    outer_password: str | None = None
    hidden_password: str | None = None
    outer_capacity: int | None = None
    hidden_capacity: int | None = None
    outer_label: str | None = None
    hidden_label: str | None = None


class DiskCreationExchange:
    """Protected one-time IPC for disk creation outside the Qt process.

    The request contains both the profile key and optional portable passwords,
    so the complete payload is protected with current-user DPAPI. A random
    response token authenticates progress and the final result.
    """

    def __init__(
        self,
        directory: Path | None = None,
        protector: CreationSecretProtector | None = None,
    ) -> None:
        self.directory = (
            Path(directory).expanduser().resolve()
            if directory is not None
            else (app_data_directory() / "operations").resolve()
        )
        self._protector = protector

    def create_ordinary(
        self,
        container_path: Path,
        master_key: bytes,
        *,
        logical_capacity: int,
        label: str,
        algorithm: str,
        password: str | None,
        file_system: str,
        overwrite: bool,
        context_menu_labels: tuple[str, ...] | None,
    ) -> DiskCreationPaths:
        if not master_key:
            raise ValueError("Disk creation master key must not be empty.")
        return self._create(
            {
                "kind": _ORDINARY,
                "container_path": str(Path(container_path).expanduser().resolve()),
                "master_key": base64.b64encode(bytes(master_key)).decode("ascii"),
                "password": password,
                "logical_capacity": int(logical_capacity),
                "label": str(label),
                "algorithm": str(algorithm),
                "file_system": str(file_system),
                "overwrite": bool(overwrite),
                "context_menu_labels": _encode_labels(context_menu_labels),
            }
        )

    def create_hidden(
        self,
        container_path: Path,
        outer_password: str,
        hidden_password: str,
        *,
        outer_capacity: int,
        hidden_capacity: int,
        outer_label: str,
        hidden_label: str,
        file_system: str,
        overwrite: bool,
        context_menu_labels: tuple[str, ...] | None,
    ) -> DiskCreationPaths:
        return self._create(
            {
                "kind": _HIDDEN,
                "container_path": str(Path(container_path).expanduser().resolve()),
                "outer_password": str(outer_password),
                "hidden_password": str(hidden_password),
                "outer_capacity": int(outer_capacity),
                "hidden_capacity": int(hidden_capacity),
                "outer_label": str(outer_label),
                "hidden_label": str(hidden_label),
                "file_system": str(file_system),
                "overwrite": bool(overwrite),
                "context_menu_labels": _encode_labels(context_menu_labels),
            }
        )

    def _create(self, payload: dict[str, object]) -> DiskCreationPaths:
        request_id = secrets.token_hex(_REQUEST_ID_BYTES)
        response_token = secrets.token_bytes(_RESPONSE_TOKEN_BYTES)
        paths = self.paths(request_id, response_token=response_token)
        protected_payload = dict(payload)
        protected_payload["response_token"] = base64.b64encode(
            response_token
        ).decode("ascii")
        plaintext = json.dumps(
            protected_payload,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        protected = self._secret_protector().protect(
            plaintext,
            _request_entropy(request_id),
        )
        envelope = {
            "version": CREATION_PROTOCOL_VERSION,
            "request_id": request_id,
            "protected_payload": base64.b64encode(protected).decode("ascii"),
        }
        self.directory.mkdir(parents=True, exist_ok=True)
        self._write_json_atomic(paths.request_path, envelope)
        return paths

    def consume_request(self, request_path: Path) -> DiskCreationRequest:
        source = Path(request_path).expanduser().resolve()
        request_id = _request_id_from_path(source)
        if source != self.paths(request_id, response_token=b"x" * 32).request_path:
            raise MountUnavailableError("Путь запроса создания диска недопустим.")
        try:
            envelope = json.loads(source.read_text(encoding="utf-8"))
            if not isinstance(envelope, dict) or set(envelope) != {
                "version",
                "request_id",
                "protected_payload",
            }:
                raise ValueError("invalid envelope")
            if int(envelope["version"]) != CREATION_PROTOCOL_VERSION:
                raise ValueError("unsupported version")
            if str(envelope["request_id"]) != request_id:
                raise ValueError("invalid identity")
            protected = base64.b64decode(
                str(envelope["protected_payload"]), validate=True
            )
            plaintext = self._secret_protector().unprotect(
                protected,
                _request_entropy(request_id),
            )
            payload = json.loads(plaintext.decode("utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("invalid payload")
            response_token = base64.b64decode(
                str(payload.pop("response_token")), validate=True
            )
            if len(response_token) != _RESPONSE_TOKEN_BYTES:
                raise ValueError("invalid response token")
            request = self._decode_request(request_id, response_token, payload)
        except MountUnavailableError:
            raise
        except (
            OSError,
            UnicodeError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise MountUnavailableError(
                "Защищённый запрос создания диска повреждён."
            ) from error
        finally:
            try:
                source.unlink()
            except FileNotFoundError:
                pass
        return request

    def _decode_request(
        self,
        request_id: str,
        response_token: bytes,
        payload: dict[str, object],
    ) -> DiskCreationRequest:
        kind = str(payload.get("kind"))
        path = Path(str(payload.get("container_path"))).expanduser().resolve()
        file_system = str(payload.get("file_system"))
        overwrite = _strict_bool(payload.get("overwrite"))
        labels = _decode_labels(payload.get("context_menu_labels"))
        paths = self.paths(request_id, response_token=response_token)
        if kind == _ORDINARY:
            required = {
                "kind",
                "container_path",
                "master_key",
                "password",
                "logical_capacity",
                "label",
                "algorithm",
                "file_system",
                "overwrite",
                "context_menu_labels",
            }
            if set(payload) != required:
                raise ValueError("invalid ordinary request fields")
            master_key = base64.b64decode(
                str(payload["master_key"]), validate=True
            )
            if not master_key:
                raise ValueError("empty master key")
            password_value = payload["password"]
            if password_value is not None and not isinstance(password_value, str):
                raise TypeError("invalid password")
            capacity = int(payload["logical_capacity"])
            if capacity <= 0:
                raise ValueError("invalid capacity")
            return DiskCreationRequest(
                request_id,
                paths.progress_path,
                paths.response_path,
                response_token,
                kind,
                path,
                master_key,
                password_value,
                capacity,
                str(payload["label"]),
                str(payload["algorithm"]),
                file_system,
                overwrite,
                labels,
            )
        if kind == _HIDDEN:
            required = {
                "kind",
                "container_path",
                "outer_password",
                "hidden_password",
                "outer_capacity",
                "hidden_capacity",
                "outer_label",
                "hidden_label",
                "file_system",
                "overwrite",
                "context_menu_labels",
            }
            if set(payload) != required:
                raise ValueError("invalid hidden request fields")
            outer_capacity = int(payload["outer_capacity"])
            hidden_capacity = int(payload["hidden_capacity"])
            if outer_capacity <= 0 or hidden_capacity <= 0:
                raise ValueError("invalid hidden capacity")
            return DiskCreationRequest(
                request_id,
                paths.progress_path,
                paths.response_path,
                response_token,
                kind,
                path,
                None,
                None,
                None,
                None,
                None,
                file_system,
                overwrite,
                labels,
                outer_password=str(payload["outer_password"]),
                hidden_password=str(payload["hidden_password"]),
                outer_capacity=outer_capacity,
                hidden_capacity=hidden_capacity,
                outer_label=str(payload["outer_label"]),
                hidden_label=str(payload["hidden_label"]),
            )
        raise ValueError("unsupported creation kind")

    def write_progress(
        self,
        request: DiskCreationRequest,
        value: int,
        message: str,
    ) -> None:
        body = {
            "version": CREATION_PROTOCOL_VERSION,
            "request_id": request.request_id,
            "value": max(0, min(100, int(value))),
            "message": str(message)[:1000],
        }
        self._write_authenticated(
            request.progress_path,
            body,
            request.response_token,
        )

    def read_progress(
        self,
        paths: DiskCreationPaths,
    ) -> tuple[int, str] | None:
        if not paths.progress_path.is_file():
            return None
        payload = self._read_authenticated(paths.progress_path, paths)
        value = int(payload["value"])
        if not 0 <= value <= 100:
            raise ValueError("invalid progress")
        return value, str(payload.get("message") or "")

    def write_success(self, request: DiskCreationRequest, drive: str) -> None:
        self._write_authenticated(
            request.response_path,
            {
                "version": CREATION_PROTOCOL_VERSION,
                "request_id": request.request_id,
                "status": "ok",
                "drive": _normalize_drive(drive),
            },
            request.response_token,
        )

    def write_error(self, request: DiskCreationRequest, message: str) -> None:
        self._write_authenticated(
            request.response_path,
            {
                "version": CREATION_PROTOCOL_VERSION,
                "request_id": request.request_id,
                "status": "error",
                "error": str(message)[:4000],
            },
            request.response_token,
        )

    def consume_response(self, paths: DiskCreationPaths) -> str:
        try:
            payload = self._read_authenticated(paths.response_path, paths)
            if payload.get("status") == "error":
                raise MountUnavailableError(
                    str(payload.get("error") or "Не удалось создать зашифрованный диск.")
                )
            if payload.get("status") != "ok":
                raise ValueError("invalid response status")
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
                "Процесс создания диска вернул некорректный ответ."
            ) from error

    def paths(
        self,
        request_id: str,
        *,
        response_token: bytes,
    ) -> DiskCreationPaths:
        _validate_request_id(request_id)
        if len(response_token) != _RESPONSE_TOKEN_BYTES:
            raise ValueError("Disk creation response token has an invalid length.")
        return DiskCreationPaths(
            request_id,
            self.directory / f"disk-create-request-{request_id}.json",
            self.directory / f"disk-create-progress-{request_id}.json",
            self.directory / f"disk-create-response-{request_id}.json",
            bytes(response_token),
        )

    def cleanup(self, paths: DiskCreationPaths) -> None:
        for path in (
            paths.request_path,
            paths.progress_path,
            paths.response_path,
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        try:
            self.directory.rmdir()
        except OSError:
            pass

    def _read_authenticated(
        self,
        source: Path,
        paths: DiskCreationPaths,
    ) -> dict[str, object]:
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("invalid response")
        mac = str(payload.pop("mac", ""))
        if int(payload.get("version", -1)) != CREATION_PROTOCOL_VERSION:
            raise ValueError("unsupported response version")
        if str(payload.get("request_id")) != paths.request_id:
            raise ValueError("invalid response identity")
        expected = hmac.new(
            paths.response_token,
            _canonical(payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(mac, expected):
            raise ValueError("response authentication failed")
        return payload

    def _write_authenticated(
        self,
        destination: Path,
        body: dict[str, object],
        token: bytes,
    ) -> None:
        payload = dict(body)
        payload["mac"] = hmac.new(
            token,
            _canonical(body),
            hashlib.sha256,
        ).hexdigest()
        self._write_json_atomic(destination, payload)

    @staticmethod
    def _write_json_atomic(destination: Path, payload: dict[str, object]) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
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

    def _secret_protector(self) -> CreationSecretProtector:
        if self._protector is None:
            if sys.platform != "win32":
                raise MountUnavailableError(
                    "Изолированное создание диска доступно только в Windows."
                )
            from cleverpgp.biometrics.key_protection import WindowsDpapiProtector

            self._protector = WindowsDpapiProtector()
        return self._protector


def create_windows_disk_isolated(
    container_path: Path,
    master_key: bytes,
    *,
    logical_capacity: int,
    label: str,
    algorithm: str,
    password: str | None,
    file_system: str,
    overwrite: bool,
    context_menu_labels: tuple[str, ...] | None,
    progress: Callable[[int, str], None] | None = None,
    exchange: DiskCreationExchange | None = None,
    command_prefix: Iterable[str] | None = None,
) -> str:
    selected = exchange or DiskCreationExchange()
    paths = selected.create_ordinary(
        container_path,
        master_key,
        logical_capacity=logical_capacity,
        label=label,
        algorithm=algorithm,
        password=password,
        file_system=file_system,
        overwrite=overwrite,
        context_menu_labels=context_menu_labels,
    )
    return _run_creation_process(
        paths,
        selected,
        progress=progress,
        command_prefix=command_prefix,
    )


def create_hidden_windows_disk_isolated(
    container_path: Path,
    outer_password: str,
    hidden_password: str,
    *,
    outer_capacity: int,
    hidden_capacity: int,
    outer_label: str,
    hidden_label: str,
    file_system: str,
    overwrite: bool,
    context_menu_labels: tuple[str, ...] | None,
    progress: Callable[[int, str], None] | None = None,
    exchange: DiskCreationExchange | None = None,
    command_prefix: Iterable[str] | None = None,
) -> str:
    selected = exchange or DiskCreationExchange()
    paths = selected.create_hidden(
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
    )
    return _run_creation_process(
        paths,
        selected,
        progress=progress,
        command_prefix=command_prefix,
    )


def _run_creation_process(
    paths: DiskCreationPaths,
    exchange: DiskCreationExchange,
    *,
    progress: Callable[[int, str], None] | None,
    command_prefix: Iterable[str] | None,
) -> str:
    prefix = tuple(command_prefix or application_command_prefix())
    if not prefix:
        exchange.cleanup(paths)
        raise MountUnavailableError("Команда создания диска Clever PGP не найдена.")
    command = [*prefix, "--windows-create-helper", str(paths.request_path)]
    creation_flags = (
        getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    )
    if progress is not None:
        progress(2, "Защита одноразового запроса создания диска")
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
        exchange.cleanup(paths)
        raise
    last_progress: tuple[int, str] | None = None
    try:
        if progress is not None:
            progress(3, "Запуск изолированного процесса")
        while True:
            current = exchange.read_progress(paths)
            if current is not None and current != last_progress:
                last_progress = current
                if progress is not None:
                    progress(*current)
            if paths.response_path.is_file():
                return exchange.consume_response(paths)
            exit_code = process.poll()
            if exit_code is not None:
                if paths.response_path.is_file():
                    return exchange.consume_response(paths)
                raise MountUnavailableError(
                    "Изолированный процесс создания диска завершился без ответа."
                )
            time.sleep(0.05)
    finally:
        exchange.cleanup(paths)


def run_windows_create_helper(
    request_path: Path,
    *,
    exchange: DiskCreationExchange | None = None,
    manager_factory: Callable[..., Any] | None = None,
) -> int:
    source = Path(request_path).expanduser().resolve()
    selected = exchange or DiskCreationExchange(source.parent)
    request: DiskCreationRequest | None = None
    try:
        request = selected.consume_request(source)
        if manager_factory is None:
            from cleverpgp.core.windows_storage import WindowsSystemDiskManager

            manager_factory = WindowsSystemDiskManager
        manager = manager_factory(recover_existing=False)

        def report(value: int, message: str) -> None:
            selected.write_progress(request, value, message)

        report(4, "Подготовка криптографической защиты диска")
        prepare = getattr(manager, "prepare_backend", None)
        if callable(prepare):
            prepare()
        if request.kind == _ORDINARY:
            assert request.master_key is not None
            assert request.logical_capacity is not None
            assert request.label is not None
            assert request.algorithm is not None
            drive = manager.create_and_mount(
                request.container_path,
                request.master_key,
                logical_capacity=request.logical_capacity,
                label=request.label,
                algorithm=request.algorithm,
                password=request.password,
                file_system=request.file_system,
                overwrite=request.overwrite,
                context_menu_labels=request.context_menu_labels,
                progress=report,
            )
        else:
            assert request.outer_password is not None
            assert request.hidden_password is not None
            assert request.outer_capacity is not None
            assert request.hidden_capacity is not None
            assert request.outer_label is not None
            assert request.hidden_label is not None
            drive = manager.create_hidden_and_mount(
                request.container_path,
                request.outer_password,
                request.hidden_password,
                outer_capacity=request.outer_capacity,
                hidden_capacity=request.hidden_capacity,
                outer_label=request.outer_label,
                hidden_label=request.hidden_label,
                file_system=request.file_system,
                overwrite=request.overwrite,
                context_menu_labels=request.context_menu_labels,
                progress=report,
            )
        selected.write_success(request, str(drive))
        return 0
    except BaseException as error:
        if request is not None:
            try:
                selected.write_error(request, str(error) or error.__class__.__name__)
            except Exception:
                pass
        return 1


def _encode_labels(labels: tuple[str, ...] | None) -> list[str] | None:
    if labels is None:
        return None
    return [str(label) for label in labels]


def _decode_labels(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not 2 <= len(value) <= 7:
        raise ValueError("invalid context menu labels")
    if not all(isinstance(label, str) for label in value):
        raise TypeError("invalid context menu label")
    return tuple(value)


def _strict_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError("boolean value required")
    return value


def _request_entropy(request_id: str) -> bytes:
    return _REQUEST_ENTROPY_PREFIX + request_id.encode("ascii")


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _request_id_from_path(path: Path) -> str:
    prefix = "disk-create-request-"
    suffix = ".json"
    name = path.name
    if not name.startswith(prefix) or not name.endswith(suffix):
        raise MountUnavailableError("Имя запроса создания диска недопустимо.")
    request_id = name[len(prefix) : -len(suffix)]
    _validate_request_id(request_id)
    return request_id


def _validate_request_id(request_id: str) -> None:
    if len(request_id) != _REQUEST_ID_BYTES * 2:
        raise ValueError("Disk creation request id is invalid.")
    try:
        bytes.fromhex(request_id)
    except ValueError as error:
        raise ValueError("Disk creation request id is invalid.") from error


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
