from __future__ import annotations

import os
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from biopgp.localization import set_language  # noqa: E402
from biopgp.ui.disk_password_dialog import (  # noqa: E402
    DiskPasswordChangeDialog,
)


class FakeManager:
    def __init__(self, result: Path) -> None:
        self.result = result
        self.calls: list[tuple[str, str]] = []

    def change_opaque_password(
        self,
        current_password: str,
        new_password: str,
        *,
        progress,
    ) -> Path:
        self.calls.append((current_password, new_password))
        progress(25, "Проверка текущего пароля диска")
        progress(100, "Пароль диска успешно изменён")
        return self.result


def test_disk_password_dialog_rejects_mismatched_replacement(
    tmp_path: Path,
) -> None:
    set_language("ru")
    application = QApplication.instance() or QApplication([])
    manager = FakeManager(tmp_path / "hidden.cpgv")
    dialog = DiskPasswordChangeDialog(
        "Z:",
        manager,  # type: ignore[arg-type]
    )
    dialog.current_password.setText("current password long enough")
    dialog.new_password.setText("replacement password long enough")
    dialog.repeat_password.setText("different replacement password")

    dialog._start()

    assert not dialog.running
    assert not manager.calls
    assert "не совпадают" in dialog.status.text()
    dialog.close()
    application.processEvents()


def test_disk_password_dialog_runs_change_with_numeric_progress(
    tmp_path: Path,
) -> None:
    set_language("ru")
    application = QApplication.instance() or QApplication([])
    target = tmp_path / "hidden.cpgv"
    manager = FakeManager(target)
    dialog = DiskPasswordChangeDialog(
        "z:\\",
        manager,  # type: ignore[arg-type]
    )
    dialog.current_password.setText("current password long enough")
    dialog.new_password.setText("replacement password long enough")
    dialog.repeat_password.setText("replacement password long enough")

    dialog._start()
    deadline = time.monotonic() + 5
    while dialog.running and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert manager.calls == [
        (
            "current password long enough",
            "replacement password long enough",
        )
    ]
    assert dialog.operation_succeeded
    assert "Диск отключён" in dialog.status.text()
    assert dialog.change_button.isHidden()
    dialog.close()
    application.processEvents()
