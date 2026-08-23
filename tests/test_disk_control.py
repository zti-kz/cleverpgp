from __future__ import annotations

import base64
import json
import threading
from pathlib import Path

import pytest

from biopgp.core.disk_control import (
    DiskControlEndpoint,
    DiskControlServer,
    DiskControlStore,
    send_disk_control_command,
)
from biopgp.core.errors import MountUnavailableError


class FakeProtector:
    def protect(self, plaintext: bytes, entropy: bytes) -> bytes:
        assert entropy.endswith(b"v" * 16)
        return bytes(value ^ 0xA5 for value in plaintext)

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes:
        assert entropy.endswith(b"v" * 16)
        return bytes(value ^ 0xA5 for value in protected)


def test_authenticated_loopback_control_accepts_ping_and_stop() -> None:
    token = b"t" * 32
    commands: list[str] = []
    server = DiskControlServer(token=token)
    endpoint = DiskControlEndpoint(b"v" * 16, server.port, token)

    def serve() -> None:
        while True:
            command = server.poll(timeout=1)
            if command is not None:
                commands.append(command)
            if command == "stop":
                break

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        send_disk_control_command(endpoint, "ping")
        send_disk_control_command(endpoint, "stop")
        thread.join(3)
    finally:
        server.close()

    assert not thread.is_alive()
    assert commands == ["ping", "stop"]


def test_control_rejects_an_invalid_token() -> None:
    server = DiskControlServer(token=b"a" * 32)
    wrong_endpoint = DiskControlEndpoint(b"v" * 16, server.port, b"b" * 32)
    thread = threading.Thread(target=lambda: server.poll(timeout=1))
    thread.start()
    try:
        with pytest.raises(MountUnavailableError):
            send_disk_control_command(wrong_endpoint, "stop")
        thread.join(3)
    finally:
        server.close()

    assert not thread.is_alive()


def test_control_rejects_ping_after_disk_error_but_still_accepts_stop() -> None:
    token = b"t" * 32
    server = DiskControlServer(token=token)
    endpoint = DiskControlEndpoint(b"v" * 16, server.port, token)
    commands: list[str | None] = []

    def serve() -> None:
        commands.append(server.poll(timeout=1, accept=lambda: False))
        commands.append(server.poll(timeout=1, accept=lambda: False))

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        with pytest.raises(MountUnavailableError):
            send_disk_control_command(endpoint, "ping")
        send_disk_control_command(endpoint, "stop")
        thread.join(3)
    finally:
        server.close()

    assert not thread.is_alive()
    assert commands == [None, "stop"]


def test_control_store_protects_token_and_finds_drive(tmp_path: Path) -> None:
    token = b"s" * 32
    endpoint = DiskControlEndpoint(b"v" * 16, 23456, token)
    store = DiskControlStore(tmp_path, FakeProtector())

    container_path = tmp_path / "private.cpgv"
    published = store.publish(
        endpoint,
        drive="z:\\",
        process_id=1234,
        container_path=container_path,
    )
    payload = json.loads(published.path.read_text(encoding="utf-8"))
    found = store.find_by_drive("Z:")

    assert found is not None
    assert store.records() == (found,)
    assert found.drive == "Z:"
    assert base64.b64decode(payload["protected_token"]) != token
    assert str(container_path) not in published.path.read_text(encoding="utf-8")
    assert store.endpoint(found) == endpoint
    assert store.container_path(found) == container_path.resolve()

    store.remove(found)
    assert not published.path.exists()


def test_control_store_ignores_malformed_state(tmp_path: Path) -> None:
    (tmp_path / "mount-invalid.json").write_text("not-json", encoding="utf-8")
    store = DiskControlStore(tmp_path, FakeProtector())

    assert store.find_by_drive("Z:") is None
    assert store.records() == ()
