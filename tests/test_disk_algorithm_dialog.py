from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

from biopgp.core.disk_crypto import (
    AES256_GCM,
    XCHACHA20_POLY1305,
    disk_cipher_available,
)
from biopgp.ui.disk_algorithm_dialog import DiskAlgorithmChangeDialog


def test_algorithm_dialog_selects_only_an_available_replacement(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    container = tmp_path / "disk.cpgv"
    container.write_bytes(b"encrypted" * 1024)

    dialog = DiskAlgorithmChangeDialog(container, XCHACHA20_POLY1305)

    assert dialog.container_path == container.resolve()
    assert dialog.required_temporary_space == container.stat().st_size
    if disk_cipher_available(AES256_GCM):
        assert dialog.algorithm_input.count() == 1
        assert dialog.new_algorithm == AES256_GCM
        assert "256-битным" in dialog.algorithm_description.text()
        assert dialog.convert_button.isEnabled()
    else:
        assert dialog.algorithm_input.count() == 0
        assert not dialog.convert_button.isEnabled()
    buttons = dialog.findChildren(QPushButton)
    assert buttons == [dialog.convert_button]
    dialog.close()


@pytest.mark.skipif(
    not disk_cipher_available(AES256_GCM),
    reason="AES-256-GCM is not available on this processor",
)
def test_algorithm_dialog_requires_space_for_atomic_replacement(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    container = tmp_path / "large-disk.cpgv"
    container.write_bytes(b"ciphertext")
    with patch(
        "biopgp.ui.disk_algorithm_dialog.shutil.disk_usage",
        return_value=SimpleNamespace(free=container.stat().st_size - 1),
    ):
        dialog = DiskAlgorithmChangeDialog(container, XCHACHA20_POLY1305)

    assert "Недостаточно свободного места" in dialog.notice.text()
    assert not dialog.convert_button.isEnabled()
    dialog.close()
