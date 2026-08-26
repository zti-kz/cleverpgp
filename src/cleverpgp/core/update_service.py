from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from urllib.parse import parse_qs, urlparse

from cleverpgp.core.errors import BioPGPError

UPDATE_ENDPOINT = "https://cpgp.zti.kz/app.php?version"
UPDATE_HOST = "cpgp.zti.kz"
MAXIMUM_RESPONSE_BYTES = 128 * 1024
MAXIMUM_INSTALLER_BYTES = 512 * 1024 * 1024
_VERSION = re.compile(r"^\d+(?:\.\d+){1,3}$")
ProgressCallback = Callable[[int, str], None]


class UpdateError(BioPGPError):
    pass


@dataclass(frozen=True, slots=True)
class UpdateCheckResult:
    status: str
    current_version: str
    latest_version: str | None = None
    download_url: str | None = None

    @property
    def update_available(self) -> bool:
        return self.status == "available" and self.download_url is not None


def check_for_update(
    current_version: str,
    *,
    endpoint: str = UPDATE_ENDPOINT,
    opener: Callable[..., BinaryIO] = urllib.request.urlopen,
) -> UpdateCheckResult:
    request = urllib.request.Request(
        endpoint,
        headers={"Accept": "application/json", "User-Agent": f"Clever-PGP/{current_version}"},
    )
    try:
        with opener(request, timeout=15) as response:
            payload_bytes = response.read(MAXIMUM_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError) as error:
        raise UpdateError("Не удалось связаться с сервером обновлений.") from error
    if len(payload_bytes) > MAXIMUM_RESPONSE_BYTES:
        raise UpdateError("Сервер вернул слишком большой ответ.")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise UpdateError("Сервер вернул неверные данные о версии.") from error
    if not isinstance(payload, dict):
        raise UpdateError("Сервер вернул неверные данные о версии.")
    if payload.get("ok") is False:
        return UpdateCheckResult("unavailable", current_version)
    latest = payload.get("version")
    download_url = payload.get("download_url")
    if not isinstance(latest, str) or _VERSION.fullmatch(latest) is None:
        raise UpdateError("Сервер не указал корректную версию программы.")
    if not isinstance(download_url, str):
        raise UpdateError("Сервер не предоставил ссылку на установщик.")
    _validate_download_url(download_url)
    status = "available" if _version_tuple(latest) > _version_tuple(current_version) else "current"
    return UpdateCheckResult(status, current_version, latest, download_url)


def download_update(
    result: UpdateCheckResult,
    *,
    progress: ProgressCallback | None = None,
    opener: Callable[..., BinaryIO] = urllib.request.urlopen,
    destination_directory: Path | None = None,
) -> Path:
    if not result.update_available or result.latest_version is None:
        raise UpdateError("Новая версия не выбрана.")
    assert result.download_url is not None
    _validate_download_url(result.download_url)
    request = urllib.request.Request(
        result.download_url,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": f"Clever-PGP/{result.current_version}",
        },
    )
    _report(progress, 1, "Подготовка загрузки обновления")
    try:
        response = opener(request, timeout=60)
    except (OSError, urllib.error.URLError) as error:
        raise UpdateError("Не удалось скачать обновление.") from error
    with response:
        final_url = str(getattr(response, "geturl", lambda: result.download_url)())
        _validate_download_url(final_url)
        raw_length = response.headers.get("Content-Length")
        try:
            total = int(raw_length) if raw_length else 0
        except ValueError:
            total = 0
        if total > MAXIMUM_INSTALLER_BYTES:
            raise UpdateError("Файл обновления превышает допустимый размер.")
        directory = (
            Path(tempfile.mkdtemp(prefix="CleverPGP-Update-"))
            if destination_directory is None
            else Path(destination_directory).expanduser().resolve()
        )
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / f"Clever-PGP-Setup-{result.latest_version}.exe"
        temporary = target.with_suffix(".exe.part")
        received = 0
        try:
            with temporary.open("wb") as stream:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > MAXIMUM_INSTALLER_BYTES:
                        raise UpdateError("Файл обновления превышает допустимый размер.")
                    stream.write(chunk)
                    value = (
                        5 + round(90 * received / total)
                        if total
                        else min(94, 5 + received // (2 * 1024 * 1024))
                    )
                    _report(progress, value, "Загрузка обновления")
                stream.flush()
                os.fsync(stream.fileno())
            with temporary.open("rb") as stream:
                signature = stream.read(2)
            if received < 2 or signature != b"MZ":
                raise UpdateError("Загруженный файл не является установщиком Windows.")
            os.replace(temporary, target)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    _report(progress, 100, "Обновление загружено")
    return target


def launch_update_installer(installer: Path) -> None:
    selected = Path(installer).resolve()
    if not selected.is_file() or selected.suffix.casefold() != ".exe":
        raise UpdateError("Файл установщика обновления не найден.")
    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    try:
        subprocess.Popen([str(selected)], creationflags=creation_flags)
    except OSError as error:
        raise UpdateError("Windows не запустила установщик обновления.") from error


def _validate_download_url(url: str) -> None:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if (
        parsed.scheme.casefold() != "https"
        or (parsed.hostname or "").casefold() != UPDATE_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/app.php"
        or not query.get("download")
    ):
        raise UpdateError("Сервер предоставил недопустимую ссылку на обновление.")


def _version_tuple(version: str) -> tuple[int, ...]:
    if _VERSION.fullmatch(version) is None:
        raise UpdateError("Неверный номер версии программы.")
    values = tuple(int(part) for part in version.split("."))
    return values + (0,) * (4 - len(values))


def _report(callback: ProgressCallback | None, value: int, message: str) -> None:
    if callback is not None:
        callback(max(0, min(100, int(value))), message)


__all__ = [
    "UPDATE_ENDPOINT",
    "UpdateCheckResult",
    "UpdateError",
    "check_for_update",
    "download_update",
    "launch_update_installer",
]
