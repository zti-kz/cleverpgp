from __future__ import annotations

import os
from pathlib import Path

from biopgp.core.errors import ValidationError

CONTAINER_SUFFIX = ".cpgv"
_WINDOWS_DEVICE_PREFIXES = (
    "\\\\.\\",
    "\\\\?\\",
    "\\??\\",
    "\\device\\",
)


def resolve_file_hosted_container_path(path: os.PathLike[str] | str) -> Path:
    """Resolve a .cpgv path while refusing Windows device namespaces.

    Clever PGP volumes are deliberately file-hosted. Physical disks, partitions,
    boot volumes and NT object-manager device paths are outside the product scope.
    The check happens before ``Path.resolve`` so a device path is never opened as
    a side effect of normalisation.
    """

    raw_path = os.fspath(path)
    if not raw_path or "\0" in raw_path:
        raise ValidationError("Путь к файлу зашифрованного диска недопустим.")
    windows_path = raw_path.replace("/", "\\").casefold()
    if windows_path.startswith(_WINDOWS_DEVICE_PREFIXES):
        raise ValidationError(
            "Clever PGP работает только с файловыми контейнерами .cpgv и не "
            "изменяет физические, системные или загрузочные диски."
        )
    resolved = Path(raw_path).expanduser().resolve()
    if resolved.suffix.casefold() != CONTAINER_SUFFIX:
        raise ValidationError(
            "Зашифрованный диск Clever PGP должен быть файлом с расширением .cpgv."
        )
    return resolved
