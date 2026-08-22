from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from biopgp.core.disk_control import DiskControlEndpoint
from biopgp.core.disk_host import (
    DiskHostExchange,
    DiskHostRequest,
    WinSpdHostManager,
)
from biopgp.core.errors import MountUnavailableError


class FakeProtector:
    def protect(self, plaintext: bytes, entropy: bytes) -> bytes:
        assert entropy
        return bytes(value ^ 0x6D for value in plaintext)

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes:
        assert entropy
        return bytes(value ^ 0x6D for value in protected)


class RunningProcess:
    def poll(self) -> None:
        return None


class FakePopen:
    pid = 4321

    def __init__(self, command: list[str], **_options: object) -> None:
        self.command = command
        self.terminated = False

    def poll(self) -> None:
        return None

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, _timeout: float) -> int:
        return 0

    def kill(self) -> None:
        self.terminated = True


def test_host_exchange_consumes_one_time_protected_master_key(
    tmp_path: Path,
) -> None:
    master_key = b"k" * 32
    exchange = DiskHostExchange(tmp_path, FakeProtector())
    container = tmp_path / "private.cpgv"

    request = exchange.create_request(
        container,
        master_key,
        device_name=r"\\.\pipe\cleverpgp-test",
        dll_path=tmp_path / "winspd-x64.dll",
    )
    raw_request = json.loads(request.request_path.read_text(encoding="utf-8"))
    decoded = exchange.consume_request(request.request_path)

    assert base64.b64decode(raw_request["protected_master_key"]) != master_key
    assert decoded.master_key == master_key
    assert decoded.container_path == container.resolve()
    assert decoded.device_name == r"\\.\pipe\cleverpgp-test"
    assert not request.request_path.exists()

    endpoint = DiskControlEndpoint(b"v" * 16, 23456, b"t" * 32)
    exchange.write_ready(decoded, endpoint)
    returned_endpoint, process_id = exchange.wait_response(
        request,
        timeout=1,
        process=RunningProcess(),  # type: ignore[arg-type]
    )

    assert returned_endpoint == endpoint
    assert process_id == os.getpid()
    assert not request.response_path.exists()


def test_host_exchange_propagates_sanitized_start_error(tmp_path: Path) -> None:
    exchange = DiskHostExchange(tmp_path, FakeProtector())
    request = exchange.create_request(
        tmp_path / "private.cpgv",
        b"k" * 32,
        device_name=None,
        dll_path=None,
    )
    exchange.write_error(request.response_path, request.request_id, "driver failed")

    with pytest.raises(MountUnavailableError, match="driver failed"):
        exchange.wait_response(
            request,
            timeout=1,
            process=RunningProcess(),  # type: ignore[arg-type]
        )

    exchange.cleanup(request)


def test_host_manager_passes_only_request_path_to_detached_process(
    tmp_path: Path,
) -> None:
    request = DiskHostRequest(
        "a" * 32,
        tmp_path / ("request-" + "a" * 32 + ".json"),
        tmp_path / ("response-" + "a" * 32 + ".json"),
    )
    endpoint = DiskControlEndpoint(b"v" * 16, 23456, b"t" * 32)

    class FakeExchange:
        received_key: bytes | None = None

        def create_request(
            self,
            _container_path: Path,
            master_key: bytes,
            **_options: object,
        ) -> DiskHostRequest:
            type(self).received_key = master_key
            return request

        def wait_response(
            self,
            _request: DiskHostRequest,
            **_options: object,
        ) -> tuple[DiskControlEndpoint, int]:
            return endpoint, 6789

        def cleanup(self, _request: DiskHostRequest) -> None:
            raise AssertionError("Successful host startup must not need cleanup.")

    commands: list[str] = []

    def control(
        _endpoint: DiskControlEndpoint,
        command: str,
        **_options: object,
    ) -> None:
        commands.append(command)
        if command == "ping" and "stop" in commands:
            raise MountUnavailableError("stopped")

    manager = WinSpdHostManager(
        FakeExchange(),  # type: ignore[arg-type]
        command_prefix=("CleverPGP.exe",),
    )
    with (
        patch("biopgp.core.disk_host.subprocess.Popen", side_effect=FakePopen) as popen,
        patch("biopgp.core.disk_host.send_disk_control_command", side_effect=control),
    ):
        manager.start(tmp_path / "private.cpgv", b"k" * 32)
        manager.stop()

    launched_command = popen.call_args.args[0]
    assert launched_command == [
        "CleverPGP.exe",
        "--winspd-host",
        str(request.request_path),
    ]
    assert "k" * 32 not in " ".join(launched_command)
    assert FakeExchange.received_key == b"k" * 32
    assert commands == ["ping", "stop", "ping"]


def test_host_manager_does_not_force_kill_unconfirmed_disk() -> None:
    endpoint = DiskControlEndpoint(b"v" * 16, 23456, b"t" * 32)
    process = FakePopen(["CleverPGP.exe"])
    manager = WinSpdHostManager(command_prefix=("CleverPGP.exe",))
    manager._process = process  # type: ignore[assignment]
    manager._control_endpoint = endpoint
    manager._process_id = 4321

    with patch("biopgp.core.disk_host.send_disk_control_command"):
        with pytest.raises(MountUnavailableError, match="безопасное отключение"):
            manager.stop(timeout=0)

    assert manager._control_endpoint == endpoint
    assert not process.terminated
