from __future__ import annotations

import hashlib
import json
import tempfile
import time
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run(marker: Path) -> int:
    import _cffi_backend
    import cv2
    import numpy
    from nacl import utils
    from nacl.secret import Aead
    from PySide6.QtCore import qVersion

    from biopgp.biometrics.model_assets import MODEL_ASSETS
    from biopgp.config import bundled_models_directory
    from biopgp.core.file_crypto import FileCryptoService

    aead = Aead(utils.random(Aead.KEY_SIZE))
    message = b"BioPGP packaged runtime check"
    encrypted = aead.encrypt(message)
    if aead.decrypt(encrypted) != message:
        raise RuntimeError("Проверка криптографического backend завершилась ошибкой.")

    models_directory = bundled_models_directory()
    for asset in MODEL_ASSETS:
        model_path = models_directory / asset.filename
        if not model_path.is_file() or _sha256(model_path) != asset.sha256:
            raise RuntimeError(f"Модель не найдена или повреждена: {asset.filename}")

    FileCryptoService()
    marker.write_text(
        json.dumps(
            {
                "status": "ok",
                "qt": qVersion(),
                "opencv": cv2.__version__,
                "numpy": numpy.__version__,
                "cffi_backend": str(getattr(_cffi_backend, "__version__", "loaded")),
                "models": len(MODEL_ASSETS),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


def run_virtual_disk(marker: Path) -> int:
    from nacl import secret, utils

    from biopgp.core.container import MIN_DATA_CAPACITY, EncryptedContainer
    from biopgp.core.mount import VaultMountManager, mount_backend_available

    if not mount_backend_available():
        marker.write_text(
            json.dumps({"status": "skipped", "reason": "WinFsp unavailable"}),
            encoding="utf-8",
        )
        return 0

    with tempfile.TemporaryDirectory(prefix="cleverpgp-disk-check-") as directory:
        container_path = Path(directory) / "packaged-check.cpgv"
        master_key = utils.random(secret.SecretBox.KEY_SIZE)
        container = EncryptedContainer.create(
            container_path,
            master_key,
            data_capacity=MIN_DATA_CAPACITY,
            label="Clever PGP Check",
        )
        container.close(save=False)

        manager = VaultMountManager()
        payload = b"Clever PGP packaged virtual disk check\n" * 128
        drive = manager.mount(container_path, master_key)
        try:
            drive_root = Path(f"{drive}\\")
            deadline = time.monotonic() + 8
            while not drive_root.exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            if not drive_root.exists():
                raise RuntimeError("Подключённый диск не появился в Windows.")
            mounted_file = drive_root / "packaged-check.txt"
            mounted_file.write_bytes(payload)
            if mounted_file.read_bytes() != payload:
                raise RuntimeError("Проверка чтения подключённого диска не пройдена.")
        finally:
            manager.unmount()

        with EncryptedContainer.open(container_path, master_key) as reopened:
            if reopened.read_file("/packaged-check.txt") != payload:
                raise RuntimeError("Запись не сохранилась внутри контейнера.")

    marker.write_text(
        json.dumps({"status": "ok", "drive": drive}, ensure_ascii=False),
        encoding="utf-8",
    )
    return 0
