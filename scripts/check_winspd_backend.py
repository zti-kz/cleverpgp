from __future__ import annotations

import argparse
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from time import perf_counter

from nacl import secret, utils

from biopgp.core.block_volume import LOGICAL_BLOCK_SIZE
from biopgp.core.winspd import (
    DEFAULT_MAX_TRANSFER_LENGTH,
    WinSpdLibrary,
    WinSpdProcessManager,
    create_windows_block_volume,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the encrypted WinSpd backend through the official stgtest utility."
    )
    parser.add_argument("--dll", required=True, type=Path)
    parser.add_argument("--stgtest", required=True, type=Path)
    parser.add_argument("--operations", type=int, default=1000)
    parser.add_argument("--pattern", default="WRFU", choices=("WR", "WRF", "WRFU"))
    parser.add_argument(
        "--block-count",
        type=int,
        help="Use a fixed number of 512-byte blocks per operation.",
    )
    args = parser.parse_args()

    if args.operations <= 0:
        parser.error("--operations must be positive")
    if args.block_count is not None and args.block_count <= 0:
        parser.error("--block-count must be positive")
    # The official stgtest allows three advertised transfers so it can also
    # verify driver chunking. Larger requested values are silently clipped,
    # which would make performance comparisons process different byte counts.
    maximum_test_block_count = (
        DEFAULT_MAX_TRANSFER_LENGTH * 3 // LOGICAL_BLOCK_SIZE
    )
    if (
        args.block_count is not None
        and args.block_count > maximum_test_block_count
    ):
        parser.error(
            "--block-count exceeds the stgtest maximum for this provider "
            f"({maximum_test_block_count})"
        )
    pipe_id = f"cleverpgp-{uuid.uuid4().hex}"
    pipe_name = rf"\\.\pipe\{pipe_id}"

    with tempfile.TemporaryDirectory(prefix="cleverpgp-winspd-") as folder:
        path = Path(folder) / "integration.cpgv"
        key = utils.random(secret.SecretBox.KEY_SIZE)
        library = WinSpdLibrary(args.dll)
        volume = create_windows_block_volume(
            path,
            key,
            logical_capacity=32 * 1024 * 1024,
            library=library,
        )
        volume.close()
        manager = WinSpdProcessManager()
        manager.start(
            path,
            key,
            device_name=pipe_name,
            dll_path=args.dll,
        )
        try:
            time.sleep(0.15)
            command = [
                str(args.stgtest.resolve()),
                pipe_name + r"\0",
                str(args.operations),
                args.pattern,
                "*",
                str(args.block_count) if args.block_count is not None else "*",
            ]
            started = perf_counter()
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
            elapsed = perf_counter() - started
            if result.stdout:
                print(result.stdout.rstrip())
            if result.stderr:
                print(result.stderr.rstrip())
            if result.returncode:
                return result.returncode
            if not manager.running:
                raise RuntimeError("WinSpd provider stopped unexpectedly.")
        finally:
            manager.stop()

    fixed_range = (
        "random"
        if args.block_count is None
        else f"{args.block_count} blocks"
    )
    print(
        "WinSpd encrypted block backend: OK "
        f"({elapsed:.3f} s, {fixed_range})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
