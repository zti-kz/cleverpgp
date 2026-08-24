from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Iterable

from cleverpgp.core.windows_shell import application_command_prefix


def restart_after_process_exit(
    process_id: int,
    *,
    command_prefix: Iterable[str] | None = None,
    timeout_seconds: float = 30.0,
) -> int:
    """Wait for the old shell to exit, then start exactly one replacement."""

    if process_id <= 0 or process_id == os.getpid():
        return 1
    if not _wait_for_process_exit(process_id, timeout_seconds):
        return 1
    command = tuple(command_prefix or application_command_prefix())
    if not command:
        return 1
    creation_flags = 0
    if sys.platform == "win32":
        creation_flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess,
            "CREATE_NEW_PROCESS_GROUP",
            0,
        )
    try:
        subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creation_flags,
        )
    except OSError:
        return 1
    return 0


def _wait_for_process_exit(process_id: int, timeout_seconds: float) -> bool:
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        synchronize = 0x00100000
        wait_object_0 = 0
        wait_timeout = 258
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        wait_for_single_object = kernel32.WaitForSingleObject
        wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        wait_for_single_object.restype = wintypes.DWORD
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        handle = open_process(synchronize, False, process_id)
        if not handle:
            return True
        try:
            timeout_ms = max(0, min(0xFFFFFFFE, round(timeout_seconds * 1000)))
            result = wait_for_single_object(handle, timeout_ms)
            if result == wait_object_0:
                return True
            if result == wait_timeout:
                return False
            return False
        finally:
            close_handle(handle)

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        time.sleep(0.05)
    return False
