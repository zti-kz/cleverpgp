from __future__ import annotations

import argparse
import hashlib
import shutil
import tempfile
from pathlib import Path
from time import perf_counter, sleep

from nacl import secret, utils

from cleverpgp.core.block_container import BlockVaultContainer
from cleverpgp.core.mount import VaultMountManager, mount_backend_available

MEBIBYTE = 1024 * 1024


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(MEBIBYTE):
            digest.update(chunk)
    return digest.hexdigest()


def run(payload_size: int, capacity: int) -> None:
    if not mount_backend_available():
        raise RuntimeError("Компонент виртуального диска недоступен.")
    if payload_size >= capacity:
        raise ValueError("Размер проверочного файла должен быть меньше размера диска.")

    master_key = utils.random(secret.SecretBox.KEY_SIZE)
    with tempfile.TemporaryDirectory(
        prefix="cleverpgp-copy-benchmark-"
    ) as directory:
        root = Path(directory)
        source = root / "source.bin"
        container_path = root / "speed-check.cpgv"
        with source.open("wb") as stream:
            block = hashlib.sha512(b"Clever PGP speed check").digest() * 1024
            remaining = payload_size
            while remaining:
                chunk = block[: min(len(block), remaining)]
                stream.write(chunk)
                remaining -= len(chunk)

        started = perf_counter()
        container = BlockVaultContainer.create(
            container_path,
            master_key,
            data_capacity=capacity,
            label="Clever PGP Speed Check",
        )
        container.close(save=False)
        creation_seconds = perf_counter() - started

        manager = VaultMountManager()
        drive = manager.mount(container_path, master_key)
        drive_root = Path(f"{drive}\\")
        deadline = perf_counter() + 8
        while not drive_root.exists() and perf_counter() < deadline:
            sleep(0.05)
        if not drive_root.exists():
            manager.unmount()
            raise RuntimeError("Подключённый диск не появился в Windows.")
        target = drive_root / "movie.bin"
        try:
            started = perf_counter()
            shutil.copyfile(source, target)
            copy_seconds = perf_counter() - started
            started = perf_counter()
            target_digest = sha256(target)
            read_seconds = perf_counter() - started
            if target_digest != sha256(source):
                raise RuntimeError("Контрольная сумма подключённого файла не совпала.")
        finally:
            manager.unmount()

        with BlockVaultContainer.open(container_path, master_key) as reopened:
            reopened_digest = hashlib.sha256(
                reopened.read_file("/movie.bin")
            ).hexdigest()
            if reopened_digest != target_digest:
                raise RuntimeError("Файл изменился после повторного открытия диска.")

    size_mib = payload_size / MEBIBYTE
    print(f"Создание диска: {creation_seconds:.3f} с")
    print(
        f"Копирование: {copy_seconds:.3f} с; "
        f"{size_mib / copy_seconds:.1f} МиБ/с"
    )
    print(
        f"Чтение: {read_seconds:.3f} с; "
        f"{size_mib / read_seconds:.1f} МиБ/с"
    )
    print("Целостность после отключения: подтверждена")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Проверка скорости подключённого диска Clever PGP"
    )
    parser.add_argument("--size-mib", type=int, default=32)
    parser.add_argument("--capacity-mib", type=int, default=64)
    arguments = parser.parse_args()
    run(arguments.size_mib * MEBIBYTE, arguments.capacity_mib * MEBIBYTE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
