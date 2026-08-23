from __future__ import annotations

import argparse
import hashlib
import tempfile
from pathlib import Path
from statistics import median
from time import perf_counter

from nacl import secret, utils

from biopgp.core.block_volume import LOGICAL_BLOCK_SIZE, EncryptedBlockVolume
from biopgp.core.disk_crypto import (
    DEFAULT_DISK_ALGORITHM,
    available_disk_ciphers,
)
from biopgp.core.winspd import WINDOWS_BLOCK_STORAGE_FORMAT

MEBIBYTE = 1024 * 1024


def _payload(size: int) -> bytes:
    pattern = hashlib.sha512(b"Clever PGP authenticated block benchmark").digest()
    return (pattern * ((size + len(pattern) - 1) // len(pattern)))[:size]


def run(
    *,
    payload_size: int,
    capacity: int,
    request_size: int,
    rounds: int,
    algorithm: str,
) -> None:
    if payload_size > capacity:
        raise ValueError("Payload must fit inside the temporary volume.")
    if payload_size % LOGICAL_BLOCK_SIZE:
        raise ValueError("Payload size must be a multiple of the logical block size.")
    if request_size <= 0 or request_size % LOGICAL_BLOCK_SIZE:
        raise ValueError("Request size must be a positive logical block multiple.")
    if rounds <= 0:
        raise ValueError("Rounds must be positive.")

    payload = _payload(payload_size)
    expected_digest = hashlib.sha256(payload).digest()
    request_blocks = request_size // LOGICAL_BLOCK_SIZE
    write_rates: list[float] = []
    read_rates: list[float] = []

    with tempfile.TemporaryDirectory(prefix="cleverpgp-block-benchmark-") as folder:
        path = Path(folder) / "benchmark.cpgv"
        volume = EncryptedBlockVolume.create(
            path,
            utils.random(secret.SecretBox.KEY_SIZE),
            logical_capacity=capacity,
            algorithm=algorithm,
            storage_format=WINDOWS_BLOCK_STORAGE_FORMAT,
        )
        try:
            for _round in range(rounds):
                started = perf_counter()
                for start in range(0, payload_size, request_size):
                    chunk = payload[start : start + request_size]
                    volume.write_blocks(start // LOGICAL_BLOCK_SIZE, chunk)
                volume.flush()
                write_seconds = perf_counter() - started

                digest = hashlib.sha256()
                started = perf_counter()
                for start in range(0, payload_size, request_size):
                    remaining = payload_size - start
                    block_count = min(request_blocks, remaining // LOGICAL_BLOCK_SIZE)
                    digest.update(
                        volume.read_blocks(
                            start // LOGICAL_BLOCK_SIZE,
                            block_count,
                        )
                    )
                read_seconds = perf_counter() - started
                if digest.digest() != expected_digest:
                    raise RuntimeError("Decrypted benchmark data does not match.")

                size_mib = payload_size / MEBIBYTE
                write_rates.append(size_mib / write_seconds)
                read_rates.append(size_mib / read_seconds)
        finally:
            volume.close()

    print(f"algorithm={algorithm}")
    print(f"payload_mib={payload_size / MEBIBYTE:g}")
    print(f"request_kib={request_size / 1024:g}")
    print(f"rounds={rounds}")
    print(f"write_mib_s_median={median(write_rates):.1f}")
    print(f"read_mib_s_median={median(read_rates):.1f}")
    print("integrity=verified")


def main() -> int:
    algorithms = tuple(cipher.identifier for cipher in available_disk_ciphers())
    parser = argparse.ArgumentParser(
        description="Benchmark the authenticated Clever PGP block layer."
    )
    parser.add_argument("--payload-mib", type=int, default=32)
    parser.add_argument("--capacity-mib", type=int, default=64)
    parser.add_argument("--request-kib", type=int, default=64)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument(
        "--algorithm",
        choices=algorithms,
        default=DEFAULT_DISK_ALGORITHM,
    )
    arguments = parser.parse_args()
    run(
        payload_size=arguments.payload_mib * MEBIBYTE,
        capacity=arguments.capacity_mib * MEBIBYTE,
        request_size=arguments.request_kib * 1024,
        rounds=arguments.rounds,
        algorithm=arguments.algorithm,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
