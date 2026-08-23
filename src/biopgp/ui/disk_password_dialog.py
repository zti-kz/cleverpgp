from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from biopgp.config import APP_NAME, ORGANIZATION_NAME, database_path
from biopgp.core.mount import normalized_drive_name
from biopgp.core.opaque_volume_header import (
    MAXIMUM_PASSWORD_BYTES,
    MINIMUM_PASSWORD_LENGTH,
)
from biopgp.core.storage import ProfileRepository
from biopgp.localization import localize_widget_tree, set_language, tr
from biopgp.ui.icons import line_icon

if TYPE_CHECKING:
    from biopgp.core.windows_storage import WindowsSystemDiskManager


class DiskPasswordWorker(QObject):
    succeeded = Signal(str)
    failed = Signal(str)
    progress = Signal(int, str)
    finished = Signal()

    def __init__(
        self,
        manager: WindowsSystemDiskManager,
        current_password: str,
        new_password: str,
    ) -> None:
        super().__init__()
        self.manager = manager
        self._passwords: list[str | None] = [
            current_password,
            new_password,
        ]

    @Slot()
    def run(self) -> None:
        try:
            result = self.manager.change_opaque_password(
                self._passwords[0],
                self._passwords[1],
                progress=self._report_progress,
            )
            self.succeeded.emit(str(result))
        except Exception as error:  # Qt worker boundary
            self.failed.emit(str(error) or "Операция завершилась ошибкой.")
        finally:
            self._passwords[0] = None
            self._passwords[1] = None
            self.finished.emit()

    def _report_progress(self, value: int, message: str) -> None:
        self.progress.emit(max(0, min(100, int(value))), message)


class DiskPasswordChangeDialog(QDialog):
    """Compact password rotation window for an active opaque disk."""

    def __init__(
        self,
        drive: str,
        manager: WindowsSystemDiskManager,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.drive = normalized_drive_name(drive)
        self.manager = manager
        self.running = False
        self.operation_succeeded: bool | None = None
        self.thread: QThread | None = None
        self.worker: DiskPasswordWorker | None = None
        self.setWindowTitle("Смена пароля диска — Clever PGP")
        self.setMinimumWidth(620)
        self.resize(660, 570)
        self.setStyleSheet(DISK_PASSWORD_STYLESHEET)
        self._build_ui()
        localize_widget_tree(self)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 25, 30, 26)
        layout.setSpacing(14)

        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        title = QLabel("Изменить пароль зашифрованного диска")
        title.setObjectName("title")
        disk = QLabel(tr("Подключённый диск: {drive}", drive=self.drive))
        disk.setObjectName("path")
        layout.addWidget(brand)
        layout.addWidget(title)
        layout.addWidget(disk)

        explanation = QLabel(
            "Изменяется пароль только открытого внешнего или скрытого диска. "
            "Ключи шифрования и файлы не перешифровываются. Перед изменением "
            "диск будет безопасно отключён; закройте открытые на нём файлы."
        )
        explanation.setObjectName("muted")
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        self.current_password = self._password_input("Текущий пароль диска")
        self.new_password = self._password_input("Новый пароль диска")
        self.repeat_password = self._password_input("Повторите новый пароль диска")
        self.repeat_password.returnPressed.connect(self._start)
        layout.addWidget(self.current_password)
        layout.addWidget(self.new_password)
        layout.addWidget(self.repeat_password)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(1)
        self.progress.setFormat(tr("1% — Запуск операции"))
        self.progress.hide()
        layout.addWidget(self.progress)

        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.hide()
        layout.addWidget(self.status)

        buttons = QHBoxLayout()
        self.change_button = QPushButton("Изменить пароль диска")
        self.change_button.setObjectName("primary")
        self.change_button.setIcon(line_icon("lock"))
        self.change_button.clicked.connect(self._start)
        buttons.addStretch()
        buttons.addWidget(self.change_button)
        layout.addLayout(buttons)
        self.current_password.setFocus()

    @staticmethod
    def _password_input(placeholder: str) -> QLineEdit:
        field = QLineEdit()
        field.setEchoMode(QLineEdit.EchoMode.Password)
        field.setPlaceholderText(placeholder)
        field.addAction(line_icon("lock"), QLineEdit.ActionPosition.LeadingPosition)
        return field

    def _start(self) -> None:
        if self.running:
            return
        current = self.current_password.text()
        replacement = self.new_password.text()
        try:
            self._validate_password(current)
            self._validate_password(replacement)
            if replacement != self.repeat_password.text():
                raise ValueError("Новые пароли диска не совпадают.")
            if current == replacement:
                raise ValueError(
                    "Новый пароль диска должен отличаться от текущего."
                )
        except ValueError as error:
            self._show_status(str(error), error=True)
            return

        self.running = True
        self.operation_succeeded = None
        self.current_password.clear()
        self.new_password.clear()
        self.repeat_password.clear()
        for field in (
            self.current_password,
            self.new_password,
            self.repeat_password,
        ):
            field.setEnabled(False)
        self.change_button.setEnabled(False)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self.show()
        self.status.hide()
        self.progress.setValue(1)
        self.progress.setFormat(tr("1% — Запуск операции"))
        self.progress.show()

        self.thread = QThread(self)
        self.worker = DiskPasswordWorker(
            self.manager,
            current,
            replacement,
        )
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.succeeded.connect(self._succeeded)
        self.worker.failed.connect(self._failed)
        self.worker.progress.connect(self._progress_changed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < MINIMUM_PASSWORD_LENGTH:
            raise ValueError(
                f"Пароль диска должен содержать не менее "
                f"{MINIMUM_PASSWORD_LENGTH} символов."
            )
        if len(password.encode("utf-8")) > MAXIMUM_PASSWORD_BYTES:
            raise ValueError("Пароль диска слишком длинный.")

    @Slot(str)
    def _succeeded(self, _result: str) -> None:
        self.operation_succeeded = True
        self._show_status(
            "Пароль диска изменён. Диск отключён; откройте контейнер снова "
            "с новым паролем.",
            error=False,
        )
        self.change_button.hide()

    @Slot(str)
    def _failed(self, message: str) -> None:
        self.operation_succeeded = False
        self._show_status(message or "Операция завершилась ошибкой.", error=True)

    @Slot(int, str)
    def _progress_changed(self, value: int, message: str) -> None:
        self.progress.setValue(value)
        self.progress.setFormat(
            f"{value}%" + (f" — {tr(message)}" if message else "")
        )

    @Slot()
    def _thread_finished(self) -> None:
        self.progress.hide()
        self.running = False
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, True)
        self.show()
        self.worker = None
        self.thread = None
        self.change_button.setEnabled(True)
        if not self.operation_succeeded:
            for field in (
                self.current_password,
                self.new_password,
                self.repeat_password,
            ):
                field.setEnabled(True)
            self.current_password.setFocus()

    def _show_status(self, message: str, *, error: bool) -> None:
        self.status.setObjectName("error" if error else "success")
        self.status.setText(tr(message))
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.show()

    def reject(self) -> None:
        if self.running:
            return
        self.current_password.clear()
        self.new_password.clear()
        self.repeat_password.clear()
        super().reject()


def run_disk_password_change_dialog(drive: str) -> int:
    application = QApplication.instance() or QApplication(sys.argv)
    application.setApplicationName(APP_NAME)
    application.setOrganizationName(ORGANIZATION_NAME)
    application.setWindowIcon(line_icon("shield", "#38bdf8"))
    repository = ProfileRepository(database_path())
    repository.initialize()
    set_language(repository.get_setting("language"))

    try:
        from biopgp.core.windows_storage import WindowsSystemDiskManager

        manager = WindowsSystemDiskManager()
        expected = normalized_drive_name(drive)
        if manager.mounted_drive != expected:
            raise ValueError(
                "Выбранный виртуальный диск Clever PGP не подключён."
            )
        dialog = DiskPasswordChangeDialog(expected, manager)
    except Exception as error:
        QMessageBox.critical(None, "Clever PGP", tr(str(error)))
        return 2
    return 0 if dialog.exec() == QDialog.DialogCode.Accepted else 1


DISK_PASSWORD_STYLESHEET = """
QDialog {
    background: #0b1220;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
}
QLabel { background: transparent; }
QLabel#brand { color: #7dd3fc; font-size: 22px; font-weight: 700; }
QLabel#title { color: #f8fafc; font-size: 22px; font-weight: 700; }
QLabel#muted { color: #94a3b8; }
QLabel#path {
    background: #0d2135;
    border: 1px solid #1e4f70;
    border-radius: 9px;
    color: #cbd5e1;
    padding: 10px;
}
QLabel#error {
    background: #3f151b;
    border: 1px solid #991b1b;
    border-radius: 8px;
    color: #fecaca;
    padding: 10px;
}
QLabel#success {
    background: #0d3029;
    border: 1px solid #0f766e;
    border-radius: 8px;
    color: #99f6e4;
    padding: 10px;
}
QLineEdit {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 9px;
    color: #f8fafc;
    min-height: 40px;
    padding: 0 12px;
}
QLineEdit:focus { border-color: #38bdf8; }
QPushButton {
    background: #1e293b;
    border: 1px solid #475569;
    border-radius: 9px;
    color: #f8fafc;
    min-height: 40px;
    padding: 0 18px;
    font-weight: 650;
}
QPushButton:hover { background: #334155; }
QPushButton#primary { background: #0284c7; border-color: #0ea5e9; }
QProgressBar {
    border: 1px solid #475569;
    border-radius: 8px;
    background: #1e293b;
    color: #f8fafc;
    min-height: 28px;
    text-align: center;
    font-weight: 650;
}
QProgressBar::chunk { background: #0284c7; border-radius: 7px; }
"""


__all__ = [
    "DiskPasswordChangeDialog",
    "DiskPasswordWorker",
    "run_disk_password_change_dialog",
]
