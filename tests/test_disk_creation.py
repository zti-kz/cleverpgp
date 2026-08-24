from __future__ import annotations

import json
import os
from pathlib import Path

from cleverpgp.core.disk_creation import (
    DiskCreationExchange,
    create_windows_disk_isolated,
    run_windows_create_helper,
)


class FakeProtector:
    @staticmethod
    def protect(plaintext: bytes, entropy: bytes) -> bytes:
        return b"protected:" + entropy[-8:] + bytes(reversed(plaintext))

    @staticmethod
    def unprotect(protected: bytes, entropy: bytes) -> bytes:
        prefix = b"protected:" + entropy[-8:]
        if not protected.startswith(prefix):
            raise ValueError("invalid protection")
        return bytes(reversed(protected[len(prefix) :]))


def exchange(tmp_path: Path) -> DiskCreationExchange:
    return DiskCreationExchange(tmp_path / "operations", FakeProtector())


def test_creation_request_protects_secrets_and_is_one_time(tmp_path: Path) -> None:
    selected = exchange(tmp_path)
    password = "portable secret password"
    master_key = b"k" * 32
    paths = selected.create_ordinary(
        tmp_path / "private.cpgv",
        master_key,
        logical_capacity=64 * 1024 * 1024,
        label="Private",
        algorithm="XCHACHA20-POLY1305",
        password=password,
        file_system="NTFS",
        overwrite=False,
        context_menu_labels=("Open", "Info", "Settings", "Unmount"),
    )
    raw = paths.request_path.read_text(encoding="utf-8")

    assert password not in raw
    assert master_key.hex() not in raw
    assert "private.cpgv" not in raw

    request = selected.consume_request(paths.request_path)

    assert request.master_key == master_key
    assert request.password == password
    assert request.logical_capacity == 64 * 1024 * 1024
    assert request.context_menu_labels == ("Open", "Info", "Settings", "Unmount")
    assert not paths.request_path.exists()

    selected.write_progress(request, 41, "Preparing blocks")
    assert selected.read_progress(paths) == (41, "Preparing blocks")
    selected.write_success(request, "z:\\")
    assert selected.consume_response(paths) == "Z:"
    selected.cleanup(paths)
    assert not selected.directory.exists()


def test_creation_helper_runs_manager_in_current_process(tmp_path: Path) -> None:
    selected = exchange(tmp_path)
    paths = selected.create_ordinary(
        tmp_path / "created.cpgv",
        b"m" * 32,
        logical_capacity=32 * 1024 * 1024,
        label="Created",
        algorithm="XCHACHA20-POLY1305",
        password="portable secret password",
        file_system="EXFAT",
        overwrite=False,
        context_menu_labels=None,
    )
    calls: list[dict[str, object]] = []

    class Manager:
        def __init__(self, *, recover_existing: bool) -> None:
            assert not recover_existing

        def prepare_backend(self) -> None:
            calls.append({"prepare": True})

        def create_and_mount(
            self,
            container_path: Path,
            master_key: bytes,
            **options: object,
        ) -> str:
            progress = options.pop("progress")
            assert callable(progress)
            progress(55, "Preparing encrypted blocks")
            calls.append(
                {
                    "container_path": container_path,
                    "master_key": master_key,
                    **options,
                }
            )
            return "Y:"

    result = run_windows_create_helper(
        paths.request_path,
        exchange=selected,
        manager_factory=Manager,
    )

    assert result == 0
    assert selected.read_progress(paths) == (55, "Preparing encrypted blocks")
    assert selected.consume_response(paths) == "Y:"
    assert calls[1]["container_path"] == tmp_path / "created.cpgv"
    assert calls[1]["password"] == "portable secret password"
    selected.cleanup(paths)


def test_creation_helper_continues_when_progress_file_is_temporarily_locked(
    monkeypatch,
    tmp_path: Path,
) -> None:
    selected = exchange(tmp_path)
    paths = selected.create_ordinary(
        tmp_path / "created.cpgv",
        b"m" * 32,
        logical_capacity=32 * 1024 * 1024,
        label="Created",
        algorithm="XCHACHA20-POLY1305",
        password=None,
        file_system="NTFS",
        overwrite=False,
        context_menu_labels=None,
    )

    class Manager:
        def __init__(self, *, recover_existing: bool) -> None:
            assert not recover_existing

        def create_and_mount(self, *_args: object, **options: object) -> str:
            report = options["progress"]
            assert callable(report)
            report(55, "Preparing encrypted blocks")
            return "W:"

    monkeypatch.setattr(
        selected,
        "write_progress",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PermissionError(13, "Access is denied")
        ),
    )

    assert (
        run_windows_create_helper(
            paths.request_path,
            exchange=selected,
            manager_factory=Manager,
        )
        == 0
    )
    assert selected.consume_response(paths) == "W:"
    selected.cleanup(paths)


def test_isolated_launcher_reports_child_progress_and_removes_ipc(
    monkeypatch,
    tmp_path: Path,
) -> None:
    selected = exchange(tmp_path)
    commands: list[list[str]] = []

    class Process:
        def __init__(self, command: list[str], **_options: object) -> None:
            commands.append(command)
            request = selected.consume_request(Path(command[-1]))
            selected.write_progress(request, 57, "Preparing encrypted blocks")
            selected.write_success(request, "X:")

        @staticmethod
        def poll() -> int:
            return 0

    monkeypatch.setattr(
        "cleverpgp.core.disk_creation.subprocess.Popen",
        Process,
    )
    progress: list[tuple[int, str]] = []

    drive = create_windows_disk_isolated(
        tmp_path / "isolated.cpgv",
        b"q" * 32,
        logical_capacity=32 * 1024 * 1024,
        label="Isolated",
        algorithm="XCHACHA20-POLY1305",
        password="portable secret password",
        file_system="NTFS",
        overwrite=False,
        context_menu_labels=None,
        progress=lambda value, message: progress.append((value, message)),
        exchange=selected,
        command_prefix=("CleverPGP.exe",),
    )

    assert drive == "X:"
    assert commands[0][1] == "--windows-create-helper"
    assert progress[-1] == (57, "Preparing encrypted blocks")
    assert not selected.directory.exists()


def test_tampered_creation_progress_is_rejected(tmp_path: Path) -> None:
    selected = exchange(tmp_path)
    paths = selected.create_ordinary(
        tmp_path / "private.cpgv",
        b"a" * 32,
        logical_capacity=32 * 1024 * 1024,
        label="Private",
        algorithm="XCHACHA20-POLY1305",
        password=None,
        file_system="NTFS",
        overwrite=False,
        context_menu_labels=None,
    )
    request = selected.consume_request(paths.request_path)
    selected.write_progress(request, 20, "Preparing")
    payload = json.loads(paths.progress_path.read_text(encoding="utf-8"))
    payload["value"] = 99
    paths.progress_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        selected.read_progress(paths)
    except ValueError as error:
        assert "authentication" in str(error)
    else:
        raise AssertionError("Tampered progress was accepted")
    finally:
        selected.cleanup(paths)


def test_atomic_progress_write_retries_windows_sharing_violation(
    monkeypatch,
    tmp_path: Path,
) -> None:
    selected = exchange(tmp_path)
    destination = selected.directory / "progress.json"
    real_replace = os.replace
    attempts = 0

    def temporarily_locked(source: Path, target: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 4:
            raise PermissionError(13, "Access is denied", str(target))
        real_replace(source, target)

    monkeypatch.setattr(
        "cleverpgp.core.disk_creation.os.replace",
        temporarily_locked,
    )
    monkeypatch.setattr(
        "cleverpgp.core.disk_creation.time.sleep",
        lambda _seconds: None,
    )

    selected._write_json_atomic(destination, {"value": 12})

    assert attempts == 4
    assert json.loads(destination.read_text(encoding="utf-8")) == {"value": 12}


def test_authenticated_progress_read_retries_windows_sharing_violation(
    monkeypatch,
    tmp_path: Path,
) -> None:
    selected = exchange(tmp_path)
    paths = selected.create_ordinary(
        tmp_path / "private.cpgv",
        b"a" * 32,
        logical_capacity=32 * 1024 * 1024,
        label="Private",
        algorithm="XCHACHA20-POLY1305",
        password=None,
        file_system="NTFS",
        overwrite=False,
        context_menu_labels=None,
    )
    request = selected.consume_request(paths.request_path)
    selected.write_progress(request, 18, "Preparing")
    real_read_text = Path.read_text
    attempts = 0

    def temporarily_locked(source: Path, *args: object, **kwargs: object) -> str:
        nonlocal attempts
        if source == paths.progress_path:
            attempts += 1
            if attempts < 3:
                raise PermissionError(13, "Access is denied", str(source))
        return real_read_text(source, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", temporarily_locked)
    monkeypatch.setattr(
        "cleverpgp.core.disk_creation.time.sleep",
        lambda _seconds: None,
    )

    assert selected.read_progress(paths) == (18, "Preparing")
    assert attempts == 3
    selected.cleanup(paths)
