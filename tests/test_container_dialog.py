from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QSlider  # noqa: E402

from biopgp.ui.container_dialog import (  # noqa: E402
    TEBIBYTE,
    MEBIBYTE,
    ContainerCreationDialog,
)
from biopgp.core.container import EncryptedContainer  # noqa: E402


def test_container_size_is_selected_with_a_slider(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    dialog = ContainerCreationDialog()
    dialog.path_input.setText(str(tmp_path / "private"))

    assert dialog.findChildren(QSlider) == [dialog.size_slider]
    dialog.size_slider.setValue(
        dialog._capacity_to_slider(64 * MEBIBYTE, dialog._maximum_capacity)
    )
    assert dialog.data_capacity == 64 * MEBIBYTE
    assert dialog.size_value.text() == "64 МБ"

    assert dialog.minimum_size_label.text().startswith("Минимум:")
    assert dialog.maximum_size_label.text().startswith("Максимум:")

    dialog.accept()
    assert dialog.container_path == (tmp_path / "private.cpgv").resolve()
    dialog.close()
    application.processEvents()


def test_container_capacity_has_no_512_mb_product_limit(monkeypatch) -> None:
    monkeypatch.setattr(
        EncryptedContainer,
        "storage_space",
        classmethod(lambda cls, path: (4 * TEBIBYTE, 4 * TEBIBYTE)),
    )
    application = QApplication.instance() or QApplication([])
    dialog = ContainerCreationDialog()
    dialog.size_slider.setValue(
        dialog._capacity_to_slider(2 * TEBIBYTE, dialog._maximum_capacity)
    )

    assert dialog.data_capacity == 2 * TEBIBYTE
    assert dialog.size_value.text() == "2 ТБ"

    dialog.close()
    application.processEvents()


def test_selected_drive_limits_container_capacity(monkeypatch, tmp_path: Path) -> None:
    calls: list[Path] = []

    def storage_space(cls, path: Path) -> tuple[int, int]:
        calls.append(Path(path))
        return 100 * MEBIBYTE, 40 * MEBIBYTE

    monkeypatch.setattr(
        EncryptedContainer, "storage_space", classmethod(storage_space)
    )
    application = QApplication.instance() or QApplication([])
    dialog = ContainerCreationDialog()
    selected = tmp_path / "selected-drive" / "private.cpgv"
    selected.parent.mkdir()
    dialog.path_input.setText(str(selected))

    assert calls[-1] == selected.resolve()
    assert "100 МБ" in dialog.storage_space.text()
    assert "40 МБ" in dialog.storage_space.text()

    dialog.size_slider.setValue(dialog.size_slider.maximum())
    assert dialog.data_capacity == 40 * MEBIBYTE
    assert dialog.create_button.isEnabled()
    dialog.accept()
    assert dialog.result() == dialog.DialogCode.Accepted

    dialog.close()
    application.processEvents()
