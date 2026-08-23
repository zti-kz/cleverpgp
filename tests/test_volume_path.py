from __future__ import annotations

from pathlib import Path

import pytest

from biopgp.core.errors import ValidationError
from biopgp.core.volume_path import resolve_file_hosted_container_path


def test_accepts_only_normal_cpgv_file_path(tmp_path: Path) -> None:
    path = tmp_path / "private.cpgv"

    assert resolve_file_hosted_container_path(path) == path.resolve()


@pytest.mark.parametrize(
    "path",
    [
        r"\\.\PhysicalDrive0",
        r"\\?\PhysicalDrive1",
        r"\\?\Volume{12345678-1234-1234-1234-123456789abc}",
        r"\Device\Harddisk0\Partition1",
        r"\??\C:\Windows",
    ],
)
def test_rejects_windows_device_namespaces(path: str) -> None:
    with pytest.raises(ValidationError, match="физические"):
        resolve_file_hosted_container_path(path)


def test_rejects_non_container_extension(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match=r"\.cpgv"):
        resolve_file_hosted_container_path(tmp_path / "disk.img")
