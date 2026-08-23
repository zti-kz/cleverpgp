from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from time import perf_counter


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
    from biopgp.core.disk_crypto import (
        DISK_NONCE_FIELD_SIZE,
        available_disk_ciphers,
    )
    from biopgp.core.file_crypto import FileCryptoService
    from biopgp.core.winspd import WinSpdLibrary
    from biopgp.core.windows_shell import (
        SYSTEM_DRIVE_MENU_KEY,
        drive_context_menu_values,
    )

    aead = Aead(utils.random(Aead.KEY_SIZE))
    message = b"BioPGP packaged runtime check"
    encrypted = aead.encrypt(message)
    if aead.decrypt(encrypted) != message:
        raise RuntimeError("Проверка криптографического backend завершилась ошибкой.")
    disk_algorithms: list[str] = []
    disk_key = utils.random(Aead.KEY_SIZE)
    disk_nonce = utils.random(DISK_NONCE_FIELD_SIZE)
    for cipher in available_disk_ciphers():
        protected = cipher.encrypt(message, b"runtime block", disk_nonce, disk_key)
        if cipher.decrypt(
            protected,
            b"runtime block",
            disk_nonce,
            disk_key,
        ) != message:
            raise RuntimeError(
                f"Проверка метода защиты {cipher.name} завершилась ошибкой."
            )
        disk_algorithms.append(cipher.name)

    models_directory = bundled_models_directory()
    for asset in MODEL_ASSETS:
        model_path = models_directory / asset.filename
        if not model_path.is_file() or _sha256(model_path) != asset.sha256:
            raise RuntimeError(f"Модель не найдена или повреждена: {asset.filename}")

    FileCryptoService()
    WinSpdLibrary()
    shell_values = drive_context_menu_values(
        "Z:",
        command_prefix=(sys.executable,),
        icon_path=Path(sys.executable),
        open_label="Open",
        info_label="Info",
        settings_label="Settings",
        resize_label="Resize",
        unmount_label="Unmount",
        password_label="Change password",
    )
    shell_lookup = {
        (value.subkey, value.name): value.value for value in shell_values
    }
    if shell_lookup.get((SYSTEM_DRIVE_MENU_KEY, "AppliesTo")) != (
        'System.ItemPathDisplay:="Z:\\' + '"'
    ):
        raise RuntimeError("Проверка контекстного меню виртуального диска не пройдена.")
    resize_command = shell_lookup.get(
        (SYSTEM_DRIVE_MENU_KEY + r"\shell\Resize\command", "")
    )
    if "--resize-drive" not in str(resize_command):
        raise RuntimeError("Команда увеличения виртуального диска не упакована.")
    password_command = shell_lookup.get(
        (SYSTEM_DRIVE_MENU_KEY + r"\shell\Password\command", "")
    )
    if "--change-disk-password" not in str(password_command):
        raise RuntimeError("Команда смены пароля диска не упакована.")
    marker.write_text(
        json.dumps(
            {
                "status": "ok",
                "qt": qVersion(),
                "opencv": cv2.__version__,
                "numpy": numpy.__version__,
                "cffi_backend": str(getattr(_cffi_backend, "__version__", "loaded")),
                "disk_algorithms": disk_algorithms,
                "models": len(MODEL_ASSETS),
                "winspd": "loaded",
                "windows_shell": "drive-scoped",
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


def run_virtual_disk(marker: Path) -> int:
    from nacl import secret, utils

    from biopgp.core.block_container import BlockVaultContainer as EncryptedContainer
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
            data_capacity=16 * 1024 * 1024,
            label="Clever PGP Check",
        )
        container.close(save=False)

        manager = VaultMountManager()
        payload = hashlib.sha512(
            b"Clever PGP packaged virtual disk check"
        ).digest() * (128 * 1024)
        drive = manager.mount(container_path, master_key)
        try:
            drive_root = Path(f"{drive}\\")
            deadline = time.monotonic() + 8
            while not drive_root.exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            if not drive_root.exists():
                raise RuntimeError("Подключённый диск не появился в Windows.")
            mounted_file = drive_root / "packaged-check.txt"
            started = perf_counter()
            mounted_file.write_bytes(payload)
            write_seconds = perf_counter() - started
            started = perf_counter()
            mounted_payload = mounted_file.read_bytes()
            read_seconds = perf_counter() - started
            if mounted_payload != payload:
                raise RuntimeError("Проверка чтения подключённого диска не пройдена.")
        finally:
            manager.unmount()

        with EncryptedContainer.open(container_path, master_key) as reopened:
            if reopened.read_file("/packaged-check.txt") != payload:
                raise RuntimeError("Запись не сохранилась внутри контейнера.")

    marker.write_text(
        json.dumps(
            {
                "status": "ok",
                "drive": drive,
                "payload_mib": len(payload) / (1024 * 1024),
                "write_mib_s": len(payload) / (1024 * 1024) / write_seconds,
                "read_mib_s": len(payload) / (1024 * 1024) / read_seconds,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return 0


def run_winspd_pipe(marker: Path, stgtest_path: Path) -> int:
    from nacl import secret, utils

    from biopgp.core.disk_control import DiskControlStore, send_disk_control_command
    from biopgp.core.disk_host import WinSpdHostManager
    from biopgp.core.errors import MountUnavailableError
    from biopgp.core.winspd import (
        WinSpdLibrary,
        create_windows_block_volume,
        open_windows_block_volume,
        resize_windows_block_volume,
    )
    from biopgp.core.windows_storage import WindowsSystemDiskManager

    test_tool = Path(stgtest_path).expanduser().resolve()
    if not test_tool.is_file():
        raise RuntimeError("Официальная утилита проверки WinSpd не найдена.")
    pipe_name = rf"\\.\pipe\cleverpgp-packaged-{uuid.uuid4().hex}"
    with tempfile.TemporaryDirectory(prefix="cleverpgp-packaged-winspd-") as directory:
        container_path = Path(directory) / "packaged-winspd.cpgv"
        master_key = utils.random(secret.SecretBox.KEY_SIZE)
        library = WinSpdLibrary()
        volume = create_windows_block_volume(
            container_path,
            master_key,
            logical_capacity=32 * 1024 * 1024,
            library=library,
        )
        volume.close()
        resized_capacity = 40 * 1024 * 1024
        resize_windows_block_volume(
            container_path,
            master_key,
            logical_capacity=resized_capacity,
        )
        with open_windows_block_volume(container_path, master_key) as resized:
            if resized.logical_capacity != resized_capacity:
                raise RuntimeError("Увеличение блочного контейнера не сохранилось.")
        manager = WinSpdHostManager()
        manager.start(
            container_path,
            master_key,
            device_name=pipe_name,
        )
        started = perf_counter()
        try:
            result = subprocess.run(
                [
                    str(test_tool),
                    pipe_name + r"\0",
                    "2000",
                    "WRFU",
                    "*",
                    "*",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode:
                raise RuntimeError(
                    result.stderr.strip()
                    or result.stdout.strip()
                    or f"stgtest завершился с кодом {result.returncode}."
                )
            if not manager.running:
                raise RuntimeError("Фоновый процесс виртуального диска остановился.")
            endpoint = manager.control_endpoint
            if endpoint is None:
                raise RuntimeError("Локальный канал управления диском не создан.")
            send_disk_control_command(endpoint, "ping")
            process_id = manager.process_id
            if process_id is None:
                raise RuntimeError("Идентификатор дискового процесса не получен.")
            control_store = DiskControlStore(Path(directory) / "mount-state")
            record = control_store.publish(
                endpoint,
                drive="Z:",
                process_id=process_id,
            )

            class NoopContextMenu:
                @staticmethod
                def remove() -> None:
                    pass

            def provider_running(_drive: str) -> bool:
                try:
                    send_disk_control_command(endpoint, "ping", timeout=0.2)
                    return True
                except MountUnavailableError:
                    return False

            recovered = WindowsSystemDiskManager(
                WinSpdHostManager(),
                control_store=control_store,
                context_menu=NoopContextMenu(),  # type: ignore[arg-type]
                drive_available=provider_running,
            )
            if recovered.mounted_drive != "Z:":
                raise RuntimeError(
                    "Новый менеджер не восстановил самостоятельный дисковый процесс."
                )
            recovered.unmount()
            if record.path.exists():
                raise RuntimeError("Запись отключённого диска не была удалена.")
        finally:
            manager.stop()
        elapsed = perf_counter() - started

    marker.write_text(
        json.dumps(
            {
                "status": "ok",
                "operations": 2000,
                "elapsed_seconds": elapsed,
                "provider_process": "detached-host",
                "key_transport": "dpapi-one-time-request",
                "external_control": "authenticated-loopback",
                "restart_recovery": "verified",
                "resized_capacity_mib": resized_capacity // (1024 * 1024),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0
