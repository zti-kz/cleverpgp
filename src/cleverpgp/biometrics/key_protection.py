from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Protocol

from cleverpgp.core.errors import BiometricUnavailableError


class KeyProtector(Protocol):
    def protect(self, plaintext: bytes, entropy: bytes) -> bytes: ...

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes: ...


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class WindowsDpapiProtector:
    """Current-user, current-machine DPAPI protection for the biometric slot."""

    _UI_FORBIDDEN = 0x1

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise BiometricUnavailableError("Windows DPAPI доступен только в Windows.")
        self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure_functions()

    def protect(self, plaintext: bytes, entropy: bytes) -> bytes:
        if not plaintext:
            raise ValueError("DPAPI plaintext must not be empty")
        input_blob, input_buffer = self._make_blob(plaintext)
        entropy_blob, entropy_buffer = self._make_blob(entropy)
        output_blob = _DataBlob()
        success = self._crypt32.CryptProtectData(
            ctypes.byref(input_blob),
            "BioPGP biometric key slot",
            ctypes.byref(entropy_blob),
            None,
            None,
            self._UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
        del input_buffer, entropy_buffer
        if not success:
            raise BiometricUnavailableError(
                f"Windows DPAPI не смог защитить ключ: {ctypes.WinError(ctypes.get_last_error())}"
            )
        return self._copy_and_free(output_blob)

    def unprotect(self, protected: bytes, entropy: bytes) -> bytes:
        if not protected:
            raise ValueError("DPAPI protected data must not be empty")
        input_blob, input_buffer = self._make_blob(protected)
        entropy_blob, entropy_buffer = self._make_blob(entropy)
        output_blob = _DataBlob()
        success = self._crypt32.CryptUnprotectData(
            ctypes.byref(input_blob),
            None,
            ctypes.byref(entropy_blob),
            None,
            None,
            self._UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
        del input_buffer, entropy_buffer
        if not success:
            raise BiometricUnavailableError(
                f"Windows DPAPI не смог открыть ключ: {ctypes.WinError(ctypes.get_last_error())}"
            )
        return self._copy_and_free(output_blob)

    def _configure_functions(self) -> None:
        self._crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(_DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        self._crypt32.CryptProtectData.restype = wintypes.BOOL
        self._crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        self._crypt32.CryptUnprotectData.restype = wintypes.BOOL
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p

    @staticmethod
    def _make_blob(data: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_ubyte]]:
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        blob = _DataBlob(
            len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        )
        return blob, buffer

    def _copy_and_free(self, blob: _DataBlob) -> bytes:
        try:
            return ctypes.string_at(blob.pbData, blob.cbData)
        finally:
            if blob.pbData:
                self._kernel32.LocalFree(blob.pbData)


def default_key_protector() -> KeyProtector:
    if sys.platform == "win32":
        return WindowsDpapiProtector()
    raise BiometricUnavailableError(
        "Для этой системы пока не реализовано защищённое хранилище ключа."
    )
