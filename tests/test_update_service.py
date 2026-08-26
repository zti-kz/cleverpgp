from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from cleverpgp.core.update_service import (
    UpdateCheckResult,
    UpdateError,
    check_for_update,
    download_update,
)


class FakeResponse(io.BytesIO):
    def __init__(self, payload: bytes, *, url: str, length: bool = True) -> None:
        super().__init__(payload)
        self._url = url
        self.headers = {"Content-Length": str(len(payload))} if length else {}

    def geturl(self) -> str:
        return self._url


def test_update_check_detects_a_newer_official_release() -> None:
    url = "https://cpgp.zti.kz/app.php?download=abc123"
    payload = json.dumps(
        {
            "ok": True,
            "name": "Clever PGP",
            "version": "0.16.0",
            "download_url": url,
        }
    ).encode()

    result = check_for_update(
        "0.15.2",
        opener=lambda *_args, **_kwargs: FakeResponse(payload, url=url),
    )

    assert result.update_available is True
    assert result.latest_version == "0.16.0"


def test_update_check_reports_temporarily_unavailable_installer() -> None:
    payload = json.dumps(
        {"ok": False, "error": "installer_unavailable"}
    ).encode()

    result = check_for_update(
        "0.15.2",
        opener=lambda *_args, **_kwargs: FakeResponse(
            payload,
            url="https://cpgp.zti.kz/app.php?version",
        ),
    )

    assert result.status == "unavailable"
    assert result.update_available is False


def test_update_check_rejects_an_untrusted_download_host() -> None:
    payload = json.dumps(
        {
            "ok": True,
            "version": "0.16.0",
            "download_url": "https://example.org/Clever-PGP.exe",
        }
    ).encode()

    with pytest.raises(UpdateError):
        check_for_update(
            "0.15.2",
            opener=lambda *_args, **_kwargs: FakeResponse(
                payload,
                url="https://cpgp.zti.kz/app.php?version",
            ),
        )


def test_update_download_reports_progress_and_writes_an_exe(tmp_path: Path) -> None:
    url = "https://cpgp.zti.kz/app.php?download=abc123"
    payload = b"MZ" + b"installer" * 100
    progress: list[int] = []
    result = UpdateCheckResult("available", "0.15.2", "0.16.0", url)

    target = download_update(
        result,
        progress=lambda value, _message: progress.append(value),
        opener=lambda *_args, **_kwargs: FakeResponse(payload, url=url),
        destination_directory=tmp_path,
    )

    assert target.name == "Clever-PGP-Setup-0.16.0.exe"
    assert target.read_bytes() == payload
    assert progress[0] == 1
    assert progress[-1] == 100
