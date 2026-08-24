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

    from cleverpgp.biometrics.model_assets import MODEL_ASSETS
    from cleverpgp.config import bundled_models_directory
    from cleverpgp.core.disk_crypto import (
        DISK_NONCE_FIELD_SIZE,
        available_disk_ciphers,
    )
    from cleverpgp.core.file_crypto import FileCryptoService
    from cleverpgp.core.winspd import WinSpdLibrary
    from cleverpgp.core.windows_shell import (
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


def run_ui_worker(marker: Path) -> int:
    """Verify that Qt delegates password KDF and disk creation to a child."""
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QApplication

    from cleverpgp.core.windows_shell import application_command_prefix
    from cleverpgp.ui.main_window import BackgroundTaskThread

    application = QApplication.instance() or QApplication([])
    event_loop = QEventLoop()
    timeout_timer = QTimer()
    timeout_timer.setSingleShot(True)
    state: dict[str, object] = {"progress": []}

    def operation(report_progress):
        report_progress(3, "starting isolated creation")
        with tempfile.TemporaryDirectory(
            prefix="cleverpgp-ui-worker-check-"
        ) as directory:
            child_marker = Path(directory) / "child-progress.json"
            command = [
                *application_command_prefix(),
                "--block-create-check-child",
                str(child_marker),
            ]
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    if sys.platform == "win32"
                    else 0
                ),
            )
            deadline = time.monotonic() + 45
            last_progress: tuple[int, str] | None = None
            while time.monotonic() < deadline:
                if child_marker.is_file():
                    try:
                        payload = json.loads(
                            child_marker.read_text(encoding="utf-8")
                        )
                    except (OSError, ValueError, json.JSONDecodeError):
                        payload = None
                    if isinstance(payload, dict):
                        current = (
                            int(payload.get("value", 4)),
                            str(payload.get("message") or "creating encrypted disk"),
                        )
                        if current != last_progress:
                            last_progress = current
                            report_progress(*current)
                if process.poll() is not None:
                    break
                time.sleep(0.05)
            if process.poll() is None:
                process.terminate()
                raise RuntimeError("Isolated creation child timed out.")
            if process.returncode != 0 or not child_marker.is_file():
                details = (
                    child_marker.read_text(encoding="utf-8")
                    if child_marker.is_file()
                    else "child marker was not created"
                )
                raise RuntimeError(details)
            payload = json.loads(child_marker.read_text(encoding="utf-8"))
            if payload.get("status") != "ok":
                raise RuntimeError("Isolated creation child did not finish.")
            created_size = int(payload.get("created_size", 0))
        report_progress(100, "completed")
        return {"created_size": created_size}

    thread = BackgroundTaskThread(operation)

    def on_progress(value: int, message: str) -> None:
        progress = state["progress"]
        assert isinstance(progress, list)
        progress.append([value, message])

    def on_succeeded(result: object) -> None:
        state["result"] = result
        event_loop.quit()

    def on_failed(message: str) -> None:
        state["error"] = message
        event_loop.quit()

    def on_timeout() -> None:
        state["error"] = "Isolated UI task did not finish within 60 seconds."
        event_loop.quit()

    thread.progress.connect(on_progress)
    thread.succeeded.connect(on_succeeded)
    thread.failed.connect(on_failed)
    timeout_timer.timeout.connect(on_timeout)
    thread.start()
    timeout_timer.start(60_000)
    event_loop.exec()
    timeout_timer.stop()
    thread.wait(2_000)

    if thread.isRunning():
        raise RuntimeError("Фоновая операция интерфейса не завершилась.")
    if state.get("error"):
        raise RuntimeError(str(state["error"]))
    result = state.get("result")
    if not isinstance(result, dict) or int(result.get("created_size", 0)) <= 0:
        raise RuntimeError("Фоновая операция не вернула ожидаемый результат.")
    if [100, "completed"] not in state["progress"]:
        raise RuntimeError("Прогресс фоновой операции не был доставлен интерфейсу.")

    marker.write_text(
        json.dumps({"status": "ok", **state}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return 0


def run_block_create_child(marker: Path) -> int:
    """Create a password-protected block image in the child main thread."""

    from nacl import secret, utils

    from cleverpgp.core.winspd import WinSpdLibrary, create_windows_block_volume

    target = marker.with_suffix(".cpgv")

    def write_state(payload: dict[str, object]) -> None:
        temporary = marker.with_suffix(".writing")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False),
            encoding="utf-8",
        )
        temporary.replace(marker)

    try:
        write_state(
            {
                "status": "running",
                "value": 4,
                "message": "hardening portable password",
            }
        )
        library = WinSpdLibrary()
        volume = create_windows_block_volume(
            target,
            utils.random(secret.SecretBox.KEY_SIZE),
            logical_capacity=32 * 1024 * 1024,
            library=library,
            password="packaged portable disk password",
            progress=lambda completed, total: write_state(
                {
                    "status": "running",
                    "value": 5 + round(completed / total * 90),
                    "message": "creating encrypted disk",
                }
            ),
        )
        volume.close()
        created_size = target.stat().st_size
        write_state(
            {
                "status": "ok",
                "value": 100,
                "message": "completed",
                "created_size": created_size,
            }
        )
        return 0
    finally:
        # Native Windows storage can release the final file handle a few
        # milliseconds after ``close`` returns.  A transient sharing error
        # must not turn a successful packaged-runtime check into a failure.
        for attempt in range(20):
            try:
                target.unlink(missing_ok=True)
                break
            except PermissionError:
                if attempt == 19:
                    break
                time.sleep(0.05)


def run_virtual_disk(marker: Path) -> int:
    from nacl import secret, utils

    from cleverpgp.core.block_container import BlockVaultContainer as EncryptedContainer
    from cleverpgp.core.mount import VaultMountManager, mount_backend_available

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

    from cleverpgp.core.block_volume import LOGICAL_BLOCK_SIZE
    from cleverpgp.core.disk_crypto import available_disk_ciphers
    from cleverpgp.core.disk_control import DiskControlStore, send_disk_control_command
    from cleverpgp.core.disk_host import WinSpdHostManager
    from cleverpgp.core.errors import MountUnavailableError
    from cleverpgp.core.winspd import (
        DEFAULT_DISPATCHER_THREADS,
        DEFAULT_MAX_TRANSFER_LENGTH,
        WinSpdLibrary,
        convert_windows_block_volume_algorithm,
        create_windows_block_volume,
        open_windows_block_volume,
        resize_windows_block_volume,
    )
    from cleverpgp.core.windows_storage import WindowsSystemDiskManager

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
        conversion_payload = hashlib.sha256(
            b"Clever PGP packaged algorithm conversion check"
        ).digest() * 128
        with open_windows_block_volume(container_path, master_key) as resized:
            if resized.logical_capacity != resized_capacity:
                raise RuntimeError("Увеличение блочного контейнера не сохранилось.")
            resized.write_blocks(1, conversion_payload)
            source_algorithm = resized.algorithm
        alternative_ciphers = tuple(
            cipher
            for cipher in available_disk_ciphers()
            if cipher.identifier != source_algorithm
        )
        conversion_algorithm = source_algorithm
        conversion_seconds = 0.0
        conversion_status = "alternative-unavailable"
        if alternative_ciphers:
            conversion_algorithm = alternative_ciphers[0].identifier
            conversion_started = perf_counter()
            convert_windows_block_volume_algorithm(
                container_path,
                master_key,
                algorithm=conversion_algorithm,
            )
            conversion_seconds = perf_counter() - conversion_started
            conversion_status = "verified"
        with open_windows_block_volume(container_path, master_key) as converted:
            if converted.logical_capacity != resized_capacity:
                raise RuntimeError(
                    "Размер диска изменился при смене метода шифрования."
                )
            if converted.algorithm != conversion_algorithm:
                raise RuntimeError("Новый метод шифрования не сохранился.")
            if converted.read_blocks(1, 1) != conversion_payload:
                raise RuntimeError(
                    "Данные не сохранились после смены метода шифрования."
                )
        manager = WinSpdHostManager()
        manager.start(
            container_path,
            master_key,
            device_name=pipe_name,
        )
        fixed_block_count = (
            DEFAULT_MAX_TRANSFER_LENGTH * 3 // LOGICAL_BLOCK_SIZE
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
                    str(fixed_block_count),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
            stgtest_seconds = perf_counter() - started
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
                "blocks_per_operation": fixed_block_count,
                "block_size_bytes": LOGICAL_BLOCK_SIZE,
                "verified_payload_mib": (
                    2000
                    // 4
                    * 3
                    * fixed_block_count
                    * LOGICAL_BLOCK_SIZE
                    / (1024 * 1024)
                ),
                "stgtest_seconds": stgtest_seconds,
                "elapsed_seconds": elapsed,
                "max_transfer_kib": DEFAULT_MAX_TRANSFER_LENGTH // 1024,
                "dispatcher_threads": DEFAULT_DISPATCHER_THREADS,
                "provider_process": "detached-host",
                "key_transport": "dpapi-one-time-request",
                "external_control": "authenticated-loopback",
                "restart_recovery": "verified",
                "resized_capacity_mib": resized_capacity // (1024 * 1024),
                "algorithm_conversion": conversion_status,
                "algorithm_before": source_algorithm,
                "algorithm_after": conversion_algorithm,
                "algorithm_conversion_seconds": conversion_seconds,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0
