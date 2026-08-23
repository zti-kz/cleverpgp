from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from biopgp.ui.hidden_volume_dialog import (  # noqa: E402
    HiddenVolumeCreationDialog,
    OpaqueVolumeUnlockDialog,
)


def test_hidden_creation_collects_distinct_passwords_and_capacity() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = HiddenVolumeCreationDialog(
        96 * 1024 * 1024,
        "Outer",
    )
    dialog.outer_password.setText("outer correct horse battery staple")
    dialog.outer_password_repeat.setText("outer correct horse battery staple")
    dialog.hidden_password.setText("hidden correct horse battery staple")
    dialog.hidden_password_repeat.setText("hidden correct horse battery staple")
    dialog.hidden_label.setText("Private")

    dialog.accept()

    assert dialog.request is not None
    assert dialog.request.hidden_capacity >= 32 * 1024 * 1024
    assert dialog.request.outer_password.startswith("outer")
    assert dialog.request.hidden_password.startswith("hidden")
    assert dialog.request.hidden_label == "Private"
    dialog.close()
    application.processEvents()


def test_hidden_creation_rejects_same_or_mismatched_passwords() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = HiddenVolumeCreationDialog(
        96 * 1024 * 1024,
        "Outer",
    )
    password = "same correct horse battery staple"
    dialog.outer_password.setText(password)
    dialog.outer_password_repeat.setText(password)
    dialog.hidden_password.setText(password)
    dialog.hidden_password_repeat.setText(password)

    dialog.accept()

    assert dialog.request is None
    assert not dialog.error_label.isHidden()
    assert "отличаться" in dialog.error_label.text()
    dialog.close()
    application.processEvents()


def test_opaque_unlock_can_request_hidden_region_protection(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    dialog = OpaqueVolumeUnlockDialog(tmp_path / "private.cpgv")
    dialog.password.setText("outer correct horse battery staple")
    dialog.protect_hidden.setChecked(True)
    dialog.protection_password.setText("hidden correct horse battery staple")

    dialog.accept()

    assert dialog.request is not None
    assert dialog.request.password.startswith("outer")
    assert dialog.request.hidden_protection_password is not None
    assert not dialog.protection_password.isHidden()
    dialog.close()
    application.processEvents()
