from __future__ import annotations

import os
import secrets
import stat
import sys
import time
from collections.abc import Callable
from pathlib import Path

from cleverpgp.core.errors import ValidationError

ProgressCallback = Callable[[int, str], None]
OVERWRITE_CHUNK_SIZE = 1024 * 1024


def secure_delete_file(
    source_path: Path,
    *,
    passes: int = 3,
    progress: ProgressCallback | None = None,
) -> None:
    """Overwrite a regular file and remove its directory entry."""

    source = Path(source_path).expanduser().absolute()
    if source.is_symlink():
        raise ValidationError(
            "Защищённая перезапись символической ссылки не поддерживается."
        )
    if not source.is_file():
        raise ValidationError("Выбранный файл не найден.")
    if passes < 1 or passes > 7:
        raise ValidationError("Недопустимое число проходов перезаписи.")
    source_stat = source.stat()
    size = source_stat.st_size
    _report(progress, 1, "Проверка выбранного файла")
    if not source_stat.st_mode & stat.S_IWRITE:
        source.chmod(source_stat.st_mode | stat.S_IWRITE)
    with source.open("r+b", buffering=0) as stream:
        for pass_index in range(passes):
            stream.seek(0)
            written = 0
            while written < size:
                chunk_size = min(OVERWRITE_CHUNK_SIZE, size - written)
                if pass_index == 1:
                    chunk = b"\x00" * chunk_size
                else:
                    chunk = secrets.token_bytes(chunk_size)
                stream.write(chunk)
                written += chunk_size
                fraction = (pass_index + written / max(1, size)) / passes
                _report(
                    progress,
                    2 + round(92 * fraction),
                    f"Перезапись файла: проход {pass_index + 1} из {passes}",
                )
            stream.flush()
            os.fsync(stream.fileno())
        stream.seek(0)
        stream.truncate(0)
        stream.flush()
        os.fsync(stream.fileno())

    _report(progress, 96, "Удаление записи файла")
    renamed = source.with_name(f".{secrets.token_hex(16)}.deleted")
    os.replace(source, renamed)
    _unlink_with_retry(renamed)
    if source.exists() or renamed.exists():
        raise OSError("Windows не подтвердила удаление выбранного файла.")
    _notify_windows_shell(source)
    _report(progress, 100, "Файл безвозвратно удалён")


def _unlink_with_retry(source: Path, *, attempts: int = 8) -> None:
    last_error: OSError | None = None
    for attempt in range(attempts):
        try:
            source.unlink()
            return
        except FileNotFoundError:
            return
        except PermissionError as error:
            last_error = error
            if attempt + 1 < attempts:
                time.sleep(0.075 * (attempt + 1))
    if last_error is not None:
        raise last_error


def _notify_windows_shell(source: Path) -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        # SHCNE_DELETE | SHCNF_PATHW: remove a stale Explorer item immediately.
        ctypes.windll.shell32.SHChangeNotify(0x00000004, 0x0005, str(source), None)
    except (AttributeError, OSError):
        pass


def _report(
    callback: ProgressCallback | None,
    value: int,
    message: str,
) -> None:
    if callback is not None:
        callback(max(0, min(100, int(value))), message)


__all__ = ["secure_delete_file"]
