from __future__ import annotations

import os
import secrets
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
    """Overwrite a regular file and remove its directory entry.

    This is meaningful for directly addressed magnetic media. SSD wear
    levelling, snapshots and filesystem copies can retain older physical data;
    the UI explicitly discloses that limitation.
    """

    source = Path(source_path).expanduser().absolute()
    if source.is_symlink():
        raise ValidationError(
            "Защищённая перезапись символической ссылки не поддерживается."
        )
    if not source.is_file():
        raise ValidationError("Выбранный файл не найден.")
    if passes < 1 or passes > 7:
        raise ValidationError("Недопустимое число проходов перезаписи.")
    size = source.stat().st_size
    _report(progress, 1, "Проверка выбранного файла")
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

    renamed = source.with_name(f".{secrets.token_hex(16)}.deleted")
    os.replace(source, renamed)
    renamed.unlink()
    _report(progress, 100, "Файл безвозвратно удалён")


def _report(
    callback: ProgressCallback | None,
    value: int,
    message: str,
) -> None:
    if callback is not None:
        callback(max(0, min(100, int(value))), message)


__all__ = ["secure_delete_file"]
