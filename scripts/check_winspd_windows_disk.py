from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from time import perf_counter

from nacl import secret, utils

from cleverpgp.core.disk_host import WinSpdHostManager
from cleverpgp.core.winspd import (
    WinSpdLibrary,
    create_windows_block_volume,
)
from cleverpgp.core.windows_storage import (
    format_ephemeral_cleverpgp_disk,
    list_windows_disks,
    wait_for_disk_removal,
    wait_for_new_cleverpgp_disk,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Attach and format a temporary encrypted Clever PGP WinSpd disk."
    )
    parser.add_argument("--marker", required=True, type=Path)
    parser.add_argument("--capacity-mib", type=int, default=128)
    parser.add_argument("--file-system", choices=("NTFS", "exFAT"), default="NTFS")
    parser.add_argument("--confirm-ephemeral-format", action="store_true")
    args = parser.parse_args()

    if not args.confirm_ephemeral_format:
        parser.error("--confirm-ephemeral-format is required")
    if not 64 <= args.capacity_mib <= 512:
        parser.error("--capacity-mib must be between 64 and 512")
    if not bool(ctypes.windll.shell32.IsUserAnAdmin()):
        raise RuntimeError("Проверку необходимо запустить с правами администратора.")

    marker = args.marker.expanduser().resolve()
    marker.parent.mkdir(parents=True, exist_ok=True)
    logical_capacity = args.capacity_mib * 1024 * 1024
    before = list_windows_disks()

    with tempfile.TemporaryDirectory(prefix="cleverpgp-windows-disk-") as directory:
        container_path = Path(directory) / "ephemeral-system-disk.cpgv"
        master_key = utils.random(secret.SecretBox.KEY_SIZE)
        library = WinSpdLibrary()
        volume = create_windows_block_volume(
            container_path,
            master_key,
            logical_capacity=logical_capacity,
            library=library,
            label="CleverPGP Check",
        )
        volume.close()

        manager = WinSpdHostManager()
        selected_disk = None
        drive = ""
        try:
            manager.start(container_path, master_key, device_name=None)
            selected_disk = wait_for_new_cleverpgp_disk(
                before,
                expected_size=logical_capacity,
            )
            drive = format_ephemeral_cleverpgp_disk(
                selected_disk,
                expected_size=logical_capacity,
                file_system=args.file_system,
            )
            drive_root = Path(f"{drive}\\")
            deadline = time.monotonic() + 10
            while not drive_root.exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            if not drive_root.exists():
                raise RuntimeError("Отформатированный тестовый диск не появился.")
            payload = os.urandom(8 * 1024 * 1024)
            payload_hash = hashlib.sha256(payload).hexdigest()
            test_file = drive_root / "cleverpgp-system-check.bin"
            started = perf_counter()
            test_file.write_bytes(payload)
            write_seconds = perf_counter() - started
            started = perf_counter()
            restored = test_file.read_bytes()
            read_seconds = perf_counter() - started
            if hashlib.sha256(restored).hexdigest() != payload_hash:
                raise RuntimeError("Данные тестового NTFS/exFAT-диска не совпали.")
        finally:
            manager.stop()

        if selected_disk is None:
            raise RuntimeError("Временный диск не был определён.")
        wait_for_disk_removal(selected_disk.number)

    marker.write_text(
        json.dumps(
            {
                "status": "ok",
                "provider_process": "detached-host",
                "key_transport": "dpapi-one-time-request",
                "external_control": "authenticated-loopback",
                "disk_number": selected_disk.number,
                "friendly_name": selected_disk.friendly_name,
                "capacity_mib": args.capacity_mib,
                "file_system": args.file_system,
                "drive": drive,
                "payload_mib": 8,
                "write_mib_s": 8 / write_seconds,
                "read_mib_s": 8 / read_seconds,
                "removed": True,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
