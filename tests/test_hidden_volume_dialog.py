from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from cleverpgp.ui.hidden_volume_dialog import (  # noqa: E402
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


def test_opaque_unlock_only_requests_the_selected_disk_password(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    dialog = OpaqueVolumeUnlockDialog(tmp_path / "private.cpgv")
    dialog.password.setText("outer correct horse battery staple")

    dialog.accept()

    assert dialog.request is not None
    assert dialog.request.password.startswith("outer")
    assert not hasattr(dialog, "protect_hidden")
    assert not hasattr(dialog, "protection_password")
    dialog.close()
    application.processEvents()


def test_opaque_unlock_reuses_one_window_for_progress_and_error(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    dialog = OpaqueVolumeUnlockDialog(tmp_path / "CPGP_2GB.cpgv")
    dialog.show()

    dialog.begin_operation()
    dialog.update_progress(42, "Подключение диска")

    assert dialog.progress.isVisible()
    assert dialog.progress.value() == 42
    assert dialog.unlock_button.isEnabled() is False

    dialog.operation_failed("Неверный пароль диска.")

    assert dialog.error_label.text() == "Неверный пароль диска."
    assert dialog.unlock_button.isEnabled() is True
    dialog.close()
    application.processEvents()
