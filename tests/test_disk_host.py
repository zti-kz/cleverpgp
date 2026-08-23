from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from biopgp.core.disk_control import DiskControlEndpoint
from biopgp.core.disk_host import (
    DecodedDiskHostRequest,
    DiskHostExchange,
    DiskHostRequest,
    WinSpdHostManager,
    run_disk_host,
)
from biopgp.core.errors import MountUnavailableError
from biopgp.core.hidden_volume import HiddenVolumeDescriptor
from biopgp.core.opaque_volume_header import OpaqueVolumeHeader


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

    assert raw_request["access_mode"] == "legacy_master_key"
    assert (
        base64.b64decode(raw_request["protected_access_material"])
        != master_key
    )
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


def test_host_exchange_transfers_opaque_headers_without_password(
    tmp_path: Path,
) -> None:
    cover_id = b"v" * 16
    cover_key = b"c" * 32
    outer = OpaqueVolumeHeader(
        role="outer",
        generation=1,
        cover_volume_id=cover_id,
        cover_key=cover_key,
        cover_block_count=4096,
        label="Outer private disk",
        storage_format="CLEVERPGP-WINDOWS-BLOCK-DISK-V1",
        created_at="2026-08-23T04:00:00+00:00",
    )
    descriptor = HiddenVolumeDescriptor(
        volume_id=b"h" * 16,
        region_start_block=3000,
        region_block_count=259,
        hidden_block_count=256,
        label="Hidden private disk",
        storage_format="CLEVERPGP-WINDOWS-BLOCK-DISK-V1",
    )
    hidden = OpaqueVolumeHeader(
        role="hidden",
        generation=1,
        cover_volume_id=cover_id,
        cover_key=cover_key,
        cover_block_count=4096,
        label=descriptor.label,
        storage_format=descriptor.storage_format,
        created_at="2026-08-23T04:05:00+00:00",
        hidden_key=b"i" * 32,
        hidden_descriptor=descriptor,
    )
    exchange = DiskHostExchange(tmp_path, FakeProtector())

    request = exchange.create_request(
        tmp_path / "private-v4.cpgv",
        None,
        device_name=None,
        dll_path=None,
        opaque_header=outer,
        protection_header=hidden,
    )
    raw_text = request.request_path.read_text(encoding="utf-8")
    decoded = exchange.consume_request(request.request_path)

    assert '"access_mode":"opaque_header"' in raw_text
    assert "Outer private disk" not in raw_text
    assert base64.b64encode(cover_key).decode("ascii") not in raw_text
    assert decoded.master_key == b""
    assert decoded.opaque_header == outer
    assert decoded.protection_header == hidden
    assert not request.request_path.exists()


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


def test_detached_host_opens_v4_material_without_password(tmp_path: Path) -> None:
    cover_id = b"v" * 16
    cover_key = b"c" * 32
    descriptor = HiddenVolumeDescriptor(
        volume_id=b"h" * 16,
        region_start_block=3000,
        region_block_count=259,
        hidden_block_count=256,
        label="Hidden",
        storage_format="CLEVERPGP-WINDOWS-BLOCK-DISK-V1",
    )
    outer = OpaqueVolumeHeader(
        role="outer",
        generation=1,
        cover_volume_id=cover_id,
        cover_key=cover_key,
        cover_block_count=4096,
        label="Outer",
        storage_format="CLEVERPGP-WINDOWS-BLOCK-DISK-V1",
        created_at="2026-08-23T04:00:00+00:00",
    )
    hidden = OpaqueVolumeHeader(
        role="hidden",
        generation=1,
        cover_volume_id=cover_id,
        cover_key=cover_key,
        cover_block_count=4096,
        label="Hidden",
        storage_format="CLEVERPGP-WINDOWS-BLOCK-DISK-V1",
        created_at="2026-08-23T04:05:00+00:00",
        hidden_key=b"i" * 32,
        hidden_descriptor=descriptor,
    )
    request_path = tmp_path / ("request-" + "a" * 32 + ".json")
    decoded = DecodedDiskHostRequest(
        "a" * 32,
        tmp_path / ("response-" + "a" * 32 + ".json"),
        tmp_path / "private-v4.cpgv",
        b"",
        None,
        None,
        outer,
        hidden,
    )

    class FakeExchange:
        ready = False

        def __init__(self, directory: Path) -> None:
            self.directory = directory

        @staticmethod
        def consume_request(_path: Path) -> DecodedDiskHostRequest:
            return decoded

        @classmethod
        def write_ready(cls, _request: object, _endpoint: object) -> None:
            cls.ready = True

        @staticmethod
        def write_error(*_args: object) -> None:
            raise AssertionError("v4 host should start successfully")

    class FakeVolume:
        volume_id = cover_id
        storage_format = "CLEVERPGP-WINDOWS-BLOCK-DISK-V1"

        @staticmethod
        def close() -> None:
            return None

    class FakeDevice:
        last_error = None

        def __init__(self, volume: object, **_options: object) -> None:
            assert isinstance(volume, FakeVolume)

        @staticmethod
        def start() -> None:
            return None

        @staticmethod
        def stop() -> None:
            return None

    class FakeServer:
        port = 23456
        token = b"t" * 32

        @staticmethod
        def poll(**_options: object) -> str:
            return "stop"

        @staticmethod
        def close() -> None:
            return None

    with (
        patch("biopgp.core.disk_host.DiskHostExchange", FakeExchange),
        patch(
            "biopgp.core.disk_host.OpaqueBlockVolume.open_with_header",
            return_value=FakeVolume(),
        ) as opener,
        patch("biopgp.core.disk_host.WinSpdBlockDevice", FakeDevice),
        patch("biopgp.core.disk_host.WinSpdLibrary"),
        patch("biopgp.core.disk_host.DiskControlServer", FakeServer),
    ):
        result = run_disk_host(request_path)

    assert result == 0
    assert FakeExchange.ready
    opener.assert_called_once_with(
        decoded.container_path,
        outer,
        protected_hidden_descriptor=descriptor,
    )
