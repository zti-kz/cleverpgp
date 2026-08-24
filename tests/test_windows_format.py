from __future__ import annotations

import json
from pathlib import Path

import pytest

from cleverpgp.core.disk_control import DiskControlEndpoint
from cleverpgp.core.errors import MountUnavailableError
from cleverpgp.core.windows_format import (
    WindowsFormatExchange,
    run_elevated_windows_format,
    run_windows_format_helper,
)
from cleverpgp.core.windows_storage import WindowsDiskInfo


class FakeProtector:
    @staticmethod
    def protect(plaintext: bytes, entropy: bytes) -> bytes:
        return b"protected:" + entropy[:12] + bytes(reversed(plaintext))

    @staticmethod
    def unprotect(protected: bytes, entropy: bytes) -> bytes:
        prefix = b"protected:" + entropy[:12]
        if not protected.startswith(prefix):
            raise ValueError("invalid protection")
        return bytes(reversed(protected[len(prefix) :]))


def endpoint() -> DiskControlEndpoint:
    return DiskControlEndpoint(b"v" * 16, 23456, b"t" * 32)


def disk(*, unique_id: str = "unique-7") -> WindowsDiskInfo:
    return WindowsDiskInfo(
        number=7,
        friendly_name="CleverPGP",
        serial_number="serial-7",
        unique_id=unique_id,
        size=128 * 1024 * 1024,
        partition_style="MBR",
        bus_type="File Backed Virtual",
    )


def exchange(tmp_path: Path) -> WindowsFormatExchange:
    return WindowsFormatExchange(tmp_path / "format", FakeProtector())


def test_format_request_round_trip_is_authenticated_and_one_time(
    tmp_path: Path,
) -> None:
    selected_exchange = exchange(tmp_path)
    selected_endpoint = endpoint()
    selected_disk = disk()
    paths = selected_exchange.create(
        selected_endpoint,
        selected_disk,
        file_system="ntfs",
        label="Личные документы",
    )
    raw = paths.request_path.read_text(encoding="utf-8")

    assert "master_key" not in raw
    assert "password" not in raw
    assert "biometric" not in raw
    assert "request_mac" in raw

    request = selected_exchange.consume_request(paths.request_path)

    assert request.endpoint == selected_endpoint
    assert request.disk == selected_disk
    assert request.file_system == "NTFS"
    assert request.label == "Личные документы"
    assert not paths.request_path.exists()


def test_format_request_rejects_tampered_disk_identity(tmp_path: Path) -> None:
    selected_exchange = exchange(tmp_path)
    paths = selected_exchange.create(
        endpoint(),
        disk(),
        file_system="NTFS",
        label="Private",
    )
    payload = json.loads(paths.request_path.read_text(encoding="utf-8"))
    payload["disk"]["unique_id"] = "other-disk"
    paths.request_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(MountUnavailableError, match="повреждён"):
        selected_exchange.consume_request(paths.request_path)

    assert not paths.request_path.exists()


def test_format_helper_rechecks_host_and_exact_disk_before_format(
    tmp_path: Path,
) -> None:
    selected_exchange = exchange(tmp_path)
    selected_endpoint = endpoint()
    selected_disk = disk()
    paths = selected_exchange.create(
        selected_endpoint,
        selected_disk,
        file_system="EXFAT",
        label="Exchange",
    )
    commands: list[tuple[DiskControlEndpoint, str, float]] = []
    format_calls: list[dict[str, object]] = []

    def send_control(
        current_endpoint: DiskControlEndpoint,
        command: str,
        *,
        timeout: float,
    ) -> None:
        commands.append((current_endpoint, command, timeout))

    def format_disk(
        current_disk: WindowsDiskInfo,
        **options: object,
    ) -> str:
        format_calls.append({"disk": current_disk, **options})
        return "Q:"

    result = run_windows_format_helper(
        paths.request_path,
        paths.response_path,
        exchange=selected_exchange,
        disk_lister=lambda: [selected_disk],
        formatter=format_disk,
        control_sender=send_control,
        administrator_check=lambda: True,
    )

    assert result == 0
    assert selected_exchange.consume_response(paths) == "Q:"
    assert commands == [
        (selected_endpoint, "ping", 1.0),
        (selected_endpoint, "ping", 1.0),
    ]
    assert format_calls == [
        {
            "disk": selected_disk,
            "expected_size": selected_disk.size,
            "file_system": "EXFAT",
            "label": "Exchange",
        }
    ]


def test_format_helper_refuses_disk_replacement(tmp_path: Path) -> None:
    selected_exchange = exchange(tmp_path)
    selected_disk = disk()
    paths = selected_exchange.create(
        endpoint(),
        selected_disk,
        file_system="NTFS",
        label="Private",
    )
    formatted: list[bool] = []

    result = run_windows_format_helper(
        paths.request_path,
        paths.response_path,
        exchange=selected_exchange,
        disk_lister=lambda: [disk(unique_id="replacement")],
        formatter=lambda *_args, **_kwargs: formatted.append(True) or "Z:",
        control_sender=lambda *_args, **_kwargs: None,
        administrator_check=lambda: True,
    )

    assert result == 1
    with pytest.raises(MountUnavailableError, match="изменились"):
        selected_exchange.consume_response(paths)
    assert formatted == []


def test_format_helper_refuses_to_run_without_elevation(tmp_path: Path) -> None:
    selected_exchange = exchange(tmp_path)
    paths = selected_exchange.create(
        endpoint(),
        disk(),
        file_system="NTFS",
        label="Private",
    )
    touched: list[bool] = []

    result = run_windows_format_helper(
        paths.request_path,
        paths.response_path,
        exchange=selected_exchange,
        disk_lister=lambda: touched.append(True) or [],
        formatter=lambda *_args, **_kwargs: touched.append(True) or "Z:",
        control_sender=lambda *_args, **_kwargs: touched.append(True),
        administrator_check=lambda: False,
    )

    assert result == 1
    with pytest.raises(MountUnavailableError, match="администратора"):
        selected_exchange.consume_response(paths)
    assert touched == []


def test_elevated_format_uses_minimal_helper_command_and_cleans_exchange(
    tmp_path: Path,
) -> None:
    selected_exchange = exchange(tmp_path)
    commands: list[tuple[list[str], float]] = []

    def launch(command: list[str], timeout: float) -> int:
        commands.append((command, timeout))
        request = selected_exchange.consume_request(Path(command[-2]))
        selected_exchange.write_success(Path(command[-1]), request.request_id, "Z:")
        return 0

    drive = run_elevated_windows_format(
        endpoint(),
        disk(),
        file_system="NTFS",
        label="Private",
        exchange=selected_exchange,
        command_prefix=("CleverPGP.exe",),
        launcher=launch,
        timeout=45.0,
    )

    assert drive == "Z:"
    assert commands[0][0][1] == "--windows-format-helper"
    assert commands[0][1] == 45.0
    assert list((tmp_path / "format").glob("*.json")) == []
