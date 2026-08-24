from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QPushButton, QProgressBar  # noqa: E402

from cleverpgp.core.disk_info import MountedDiskInfo  # noqa: E402
from cleverpgp.core.disk_crypto import XCHACHA20_POLY1305  # noqa: E402
from cleverpgp.localization import set_language  # noqa: E402
from cleverpgp.ui.disk_info_dialog import DiskInfoDialog  # noqa: E402


def mounted_info() -> MountedDiskInfo:
    return MountedDiskInfo(
        drive="Z:",
        backend="Виртуальный диск Windows",
        file_system="NTFS",
        capacity=100 * 1024 * 1024,
        free_space=25 * 1024 * 1024,
        algorithm=XCHACHA20_POLY1305,
    )


def test_disk_information_is_compact_read_only_window_without_close_button() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = DiskInfoDialog(mounted_info())

    assert dialog.findChildren(QPushButton) == []
    progress = dialog.findChild(QProgressBar)
    assert progress is not None
    assert progress.value() == 75
    text = "\n".join(label.text() for label in dialog.findChildren(QLabel))
    assert "Z:\\" in text
    assert "NTFS" in text
    assert "XChaCha20-Poly1305" in text
    assert "192-битный" in text

    dialog.close()
    application.processEvents()


def test_disk_information_is_translated_to_english_and_kazakh() -> None:
    application = QApplication.instance() or QApplication([])
    for language, expected, expected_protection in (
        ("en", "Mounted disk information", "192-bit nonce"),
        (
            "kk",
            "Қосылған диск туралы мәліметтер",
            "192 биттік бір реттік параметр",
        ),
    ):
        set_language(language)
        dialog = DiskInfoDialog(mounted_info())
        text = "\n".join(label.text() for label in dialog.findChildren(QLabel))
        assert expected in text
        assert expected_protection in text
        dialog.close()
        application.processEvents()
