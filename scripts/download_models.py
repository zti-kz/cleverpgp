from __future__ import annotations

import hashlib
import sys
import tempfile
import urllib.request
from pathlib import Path

PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORY = PROJECT_DIRECTORY / "src"
sys.path.insert(0, str(SOURCE_DIRECTORY))

from cleverpgp.biometrics.model_assets import MODEL_ASSETS  # noqa: E402


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    models_directory = PROJECT_DIRECTORY / "models"
    models_directory.mkdir(parents=True, exist_ok=True)
    for asset in MODEL_ASSETS:
        target = models_directory / asset.filename
        if target.is_file() and digest(target) == asset.sha256:
            print(f"Модель проверена: {asset.filename}")
            continue

        print(f"Загрузка модели: {asset.filename}")
        with tempfile.NamedTemporaryFile(
            dir=models_directory, prefix=f".{asset.filename}.", delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
        try:
            urllib.request.urlretrieve(asset.url, temporary_path)
            actual_digest = digest(temporary_path)
            if actual_digest != asset.sha256:
                raise RuntimeError(
                    f"Неверная SHA-256 для {asset.filename}: {actual_digest}"
                )
            temporary_path.replace(target)
        finally:
            temporary_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
