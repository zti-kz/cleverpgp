from __future__ import annotations

import argparse
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from nacl import secret, utils

from biopgp.core.block_volume import EncryptedBlockVolume
from biopgp.core.winspd import WinSpdBlockDevice, WinSpdLibrary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the encrypted WinSpd backend through the official stgtest utility."
    )
    parser.add_argument("--dll", required=True, type=Path)
    parser.add_argument("--stgtest", required=True, type=Path)
    parser.add_argument("--operations", type=int, default=1000)
    parser.add_argument("--pattern", default="WRFU", choices=("WR", "WRF", "WRFU"))
    args = parser.parse_args()

    if args.operations <= 0:
        parser.error("--operations must be positive")
    pipe_id = f"cleverpgp-{uuid.uuid4().hex}"
    pipe_name = rf"\\.\pipe\{pipe_id}"

    with tempfile.TemporaryDirectory(prefix="cleverpgp-winspd-") as folder:
        path = Path(folder) / "integration.cpgv"
        key = utils.random(secret.SecretBox.KEY_SIZE)
        with EncryptedBlockVolume.create(
            path,
            key,
            logical_capacity=16 * 1024 * 1024,
        ) as volume:
            device = WinSpdBlockDevice(
                volume,
                library=WinSpdLibrary(args.dll),
                pipe_name=pipe_name,
            )
            device.start()
            try:
                time.sleep(0.15)
                command = [
                    str(args.stgtest.resolve()),
                    pipe_name + r"\0",
                    str(args.operations),
                    args.pattern,
                    "*",
                    "*",
                ]
                result = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.stdout:
                    print(result.stdout.rstrip())
                if result.stderr:
                    print(result.stderr.rstrip())
                if result.returncode:
                    return result.returncode
                if device.last_error is not None:
                    raise device.last_error
            finally:
                device.stop()

    print("WinSpd encrypted block backend: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
