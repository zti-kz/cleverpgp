from __future__ import annotations

from pathlib import Path
import stat

import pytest

from cleverpgp.core.errors import ValidationError
from cleverpgp.core.secure_delete import secure_delete_file


def test_secure_delete_overwrites_every_pass_before_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "confidential report.txt"
    source.write_bytes(b"classified-data" * 100_000)
    updates: list[tuple[int, str]] = []
    fsync_calls: list[int] = []
    monkeypatch.setattr("cleverpgp.core.secure_delete.os.fsync", fsync_calls.append)

    secure_delete_file(
        source,
        passes=3,
        progress=lambda value, message: updates.append((value, message)),
    )

    assert not source.exists()
    assert len(fsync_calls) == 4
    assert updates[-1] == (100, "Файл безвозвратно удалён")
    assert [value for value, _message in updates] == sorted(
        value for value, _message in updates
    )


def test_secure_delete_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="не найден"):
        secure_delete_file(tmp_path / "missing.txt")


def test_secure_delete_removes_a_read_only_file(tmp_path: Path) -> None:
    source = tmp_path / "read-only.txt"
    source.write_bytes(b"sensitive")
    source.chmod(stat.S_IREAD)

    secure_delete_file(source, passes=1)

    assert source.exists() is False
