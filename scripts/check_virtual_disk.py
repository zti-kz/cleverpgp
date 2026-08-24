from __future__ import annotations

import multiprocessing
import time
from pathlib import Path

from nacl import secret, utils

from cleverpgp.core.container import MIN_DATA_CAPACITY, EncryptedContainer
from cleverpgp.core.mount import VaultMountManager


def main() -> int:
    project_directory = Path(__file__).resolve().parents[1]
    check_directory = project_directory / "build" / "virtual-disk-check"
    check_directory.mkdir(parents=True, exist_ok=True)
    container_path = check_directory / f"write-check-{time.time_ns()}.cpgv"
    master_key = utils.random(secret.SecretBox.KEY_SIZE)
    with EncryptedContainer.create(
        container_path,
        master_key,
        data_capacity=MIN_DATA_CAPACITY,
        label="Clever PGP Check",
    ):
        pass

    manager = VaultMountManager()
    payload = b"Clever PGP encrypted disk write check\n" * 128
    drive = manager.mount(container_path, master_key)
    try:
        drive_root = Path(f"{drive}\\")
        deadline = time.monotonic() + 8
        while not drive_root.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        if not drive_root.exists():
            raise RuntimeError("Подключённый диск не появился в Windows.")
        mounted_file = Path(f"{drive}\\copied-to-encrypted-disk.txt")
        mounted_file.write_bytes(payload)
        if mounted_file.read_bytes() != payload:
            raise RuntimeError("Данные на подключённом диске не совпадают.")
    finally:
        manager.unmount()

    with EncryptedContainer.open(container_path, master_key) as container:
        if container.read_file("/copied-to-encrypted-disk.txt") != payload:
            raise RuntimeError("Файл не сохранился внутри контейнера.")
    print(f"Запись на зашифрованный диск проверена: {drive}")
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
