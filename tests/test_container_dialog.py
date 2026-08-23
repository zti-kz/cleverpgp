from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QComboBox, QSlider  # noqa: E402

from biopgp.ui.container_dialog import (  # noqa: E402
    DISK_BACKEND_WINDOWS,
    DISK_BACKEND_WINFSP,
    VOLUME_KIND_HIDDEN,
    TEBIBYTE,
    MEBIBYTE,
    ContainerCreationDialog,
)
from biopgp.core.block_container import BlockVaultContainer as EncryptedContainer  # noqa: E402
from biopgp.core.disk_crypto import (  # noqa: E402
    AES256_GCM,
    XCHACHA20_POLY1305,
    disk_cipher_available,
)
from biopgp.core.winspd import (  # noqa: E402
    MIN_HIDDEN_WINDOWS_COVER_CAPACITY,
    MIN_WINDOWS_DISK_CAPACITY,
)
from biopgp.ui.resize_dialog import ContainerResizeDialog  # noqa: E402


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


def test_system_disk_dialog_enforces_windows_minimum_capacity() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = ContainerCreationDialog(
        minimum_capacity=MIN_WINDOWS_DISK_CAPACITY,
        system_disk=True,
    )

    assert dialog.data_capacity >= MIN_WINDOWS_DISK_CAPACITY
    assert dialog._capacity_choices[0] == MIN_WINDOWS_DISK_CAPACITY
    assert "32 МБ" in dialog.minimum_size_label.text()
    assert dialog.file_system == "NTFS"
    assert dialog.findChild(QComboBox, "fileSystemInput") is dialog.file_system_input
    assert dialog.disk_algorithm == XCHACHA20_POLY1305
    assert "192-битным" in dialog.algorithm_description.text()

    dialog.file_system_input.setCurrentIndex(1)
    assert dialog.file_system == "EXFAT"
    assert "журналирование" in dialog.file_system_description.text()

    dialog.close()
    application.processEvents()


def test_disk_algorithm_choice_and_hidden_disk_constraint() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = ContainerCreationDialog(
        minimum_capacity=MIN_WINDOWS_DISK_CAPACITY,
        system_disk=True,
        hidden_volume_available=True,
    )

    if disk_cipher_available(AES256_GCM):
        aes_index = dialog.algorithm_input.findData(AES256_GCM)
        assert aes_index >= 0
        dialog.algorithm_input.setCurrentIndex(aes_index)
        assert dialog.disk_algorithm == AES256_GCM
        assert "256-битным" in dialog.algorithm_description.text()

    hidden_index = dialog.volume_kind_input.findData(VOLUME_KIND_HIDDEN)
    dialog.volume_kind_input.setCurrentIndex(hidden_index)
    assert dialog.disk_algorithm == XCHACHA20_POLY1305
    assert not dialog.algorithm_input.isEnabled()

    dialog.close()
    application.processEvents()


def test_legacy_disk_dialog_keeps_implicit_ntfs_without_format_selector() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = ContainerCreationDialog()

    assert dialog.file_system == "NTFS"
    assert dialog.findChild(QComboBox, "fileSystemInput") is None

    dialog.close()
    application.processEvents()


def test_automatic_dialog_recommends_fast_windows_disk_and_keeps_winfsp() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = ContainerCreationDialog(
        minimum_capacity=MIN_WINDOWS_DISK_CAPACITY,
        allow_backend_choice=True,
        system_backend_available=True,
        winfsp_backend_available=True,
    )

    assert dialog.backend_input.count() == 2
    assert dialog.backend_input.currentData() == DISK_BACKEND_WINDOWS
    assert dialog.system_disk
    assert dialog.disk_backend == DISK_BACKEND_WINDOWS
    assert "больших файлов" in dialog.backend_description.text()
    assert not dialog.format_card.isHidden()

    dialog.backend_input.setCurrentIndex(1)

    assert dialog.backend_input.currentData() == DISK_BACKEND_WINFSP
    assert not dialog.system_disk
    assert dialog.disk_backend == DISK_BACKEND_WINFSP
    assert dialog.file_system == "NTFS"
    assert "резервный вариант" in dialog.backend_description.text()
    assert dialog.format_card.isHidden()

    dialog.close()
    application.processEvents()


def test_automatic_dialog_uses_winfsp_when_system_component_is_missing() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = ContainerCreationDialog(
        minimum_capacity=MIN_WINDOWS_DISK_CAPACITY,
        allow_backend_choice=True,
        system_backend_available=False,
        winfsp_backend_available=True,
    )

    assert dialog.backend_input.count() == 1
    assert dialog.backend_input.currentData() == DISK_BACKEND_WINFSP
    assert not dialog.system_disk
    assert dialog.format_card.isHidden()

    dialog.close()
    application.processEvents()


def test_hidden_kind_raises_outer_slider_minimum_and_requires_winspd() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = ContainerCreationDialog(
        minimum_capacity=MIN_WINDOWS_DISK_CAPACITY,
        allow_backend_choice=True,
        system_backend_available=True,
        winfsp_backend_available=True,
        hidden_volume_available=True,
    )

    dialog.volume_kind_input.setCurrentIndex(
        dialog.volume_kind_input.findData(VOLUME_KIND_HIDDEN)
    )

    assert dialog.hidden_volume
    assert dialog.data_capacity >= MIN_HIDDEN_WINDOWS_COVER_CAPACITY
    assert "внешний" in dialog.volume_kind_description.text()

    dialog.backend_input.setCurrentIndex(
        dialog.backend_input.findData(DISK_BACKEND_WINFSP)
    )

    assert not dialog.hidden_volume
    assert dialog.volume_kind_card.isHidden()
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


def test_resize_dialog_uses_one_slider_and_selected_drive_space(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    container_path = tmp_path / "mounted.cpgv"
    container_path.write_bytes(b"container")
    with patch(
        "biopgp.ui.resize_dialog.shutil.disk_usage",
        return_value=SimpleNamespace(free=256 * MEBIBYTE),
    ):
        dialog = ContainerResizeDialog(
            container_path,
            current_capacity=64 * MEBIBYTE,
            file_system="NTFS",
        )

    assert dialog.findChildren(QSlider) == [dialog.size_slider]
    assert not dialog.resize_button.isEnabled()
    target = min(
        dialog._capacity_choices,
        key=lambda capacity: abs(capacity - 128 * MEBIBYTE),
    )
    dialog.size_slider.setValue(dialog._capacity_choices.index(target))
    assert dialog.logical_capacity == target
    assert dialog.resize_button.isEnabled()
    assert "процентах" in dialog.notice.text()

    dialog.close()
    application.processEvents()


def test_resize_dialog_explains_why_exfat_growth_is_disabled(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    container_path = tmp_path / "exfat.cpgv"
    container_path.write_bytes(b"container")
    with patch(
        "biopgp.ui.resize_dialog.shutil.disk_usage",
        return_value=SimpleNamespace(free=256 * MEBIBYTE),
    ):
        dialog = ContainerResizeDialog(
            container_path,
            current_capacity=64 * MEBIBYTE,
            file_system="EXFAT",
        )

    dialog.size_slider.setValue(dialog.size_slider.maximum())
    assert not dialog.resize_button.isEnabled()
    assert "exFAT" in dialog.notice.text()

    dialog.close()
    application.processEvents()


def test_resize_dialog_allows_retry_without_additional_free_space(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    container_path = tmp_path / "pending.cpgv"
    container_path.write_bytes(b"container")
    with patch(
        "biopgp.ui.resize_dialog.shutil.disk_usage",
        return_value=SimpleNamespace(free=0),
    ):
        dialog = ContainerResizeDialog(
            container_path,
            current_capacity=64 * MEBIBYTE,
            file_system="NTFS",
            partition_growth_pending=True,
        )

    assert dialog.resize_button.isEnabled()
    assert "Повторить" in dialog.resize_button.text()

    dialog.close()
    application.processEvents()
