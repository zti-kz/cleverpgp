from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from cleverpgp.config import APP_NAME, ORGANIZATION_NAME
from cleverpgp.core.secure_delete import secure_delete_file
from cleverpgp.localization import localize_widget_tree, tr
from cleverpgp.ui.adaptive import scrollable_dialog_layout
from cleverpgp.ui.icons import line_icon
from cleverpgp.ui.screen_bounds import fit_window_to_screen, install_screen_bounds


class SecureDeleteWorker(QObject):
    progress = Signal(int, str)
    succeeded = Signal()
    failed = Signal(str)
    finished = Signal()

    def __init__(self, source: Path) -> None:
        super().__init__()
        self.source = source

    @Slot()
    def run(self) -> None:
        try:
            secure_delete_file(
                self.source,
                progress=lambda value, message: self.progress.emit(value, message),
            )
            self.succeeded.emit()
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            self.finished.emit()


class SecureDeleteDialog(QDialog):
    def __init__(self, source: Path, parent=None) -> None:
        super().__init__(parent)
        self.source = Path(source).expanduser().absolute()
        self.thread: QThread | None = None
        self.worker: SecureDeleteWorker | None = None
        self.running = False
        self.setWindowTitle("Безвозвратное удаление файла — Clever PGP")
        self.setMinimumSize(620, 460)
        self.resize(760, 540)
        self.setStyleSheet(SECURE_DELETE_STYLESHEET)
        self._build_ui()
        localize_widget_tree(self)

    def _build_ui(self) -> None:
        layout = scrollable_dialog_layout(self)
        layout.setContentsMargins(28, 26, 28, 26)
        layout.setSpacing(14)
        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        title = QLabel("Безвозвратно удалить выбранный файл")
        title.setObjectName("title")
        layout.addWidget(brand)
        layout.addWidget(title)
        path = QLabel(str(self.source))
        path.setObjectName("path")
        path.setWordWrap(True)
        path.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(path)
        explanation = QLabel(
            "Clever PGP выполнит три прохода перезаписи содержимого и затем удалит файл. "
            "Операцию нельзя отменить."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        limitation = QLabel(
            "Ограничение SSD: из-за резервных ячеек, TRIM и выравнивания износа "
            "физическое уничтожение всех прежних копий не может быть гарантировано. "
            "Для SSD основным методом защиты является шифрование данных до записи."
        )
        limitation.setObjectName("warning")
        limitation.setWordWrap(True)
        layout.addWidget(limitation)
        self.confirmation = QCheckBox(
            "Я понимаю, что выбранный файл будет удалён без возможности восстановления"
        )
        self.confirmation.toggled.connect(
            lambda checked: self.delete_button.setEnabled(checked)
        )
        layout.addWidget(self.confirmation)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.hide()
        layout.addWidget(self.progress)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(52)
        self.status.setContentsMargins(14, 10, 14, 10)
        self.status.hide()
        layout.addWidget(self.status)
        buttons = QHBoxLayout()
        buttons.addStretch()
        self.cancel_button = QPushButton("Отмена")
        self.cancel_button.clicked.connect(self.reject)
        self.delete_button = QPushButton("Безвозвратно удалить файл")
        self.delete_button.setObjectName("danger")
        self.delete_button.setIcon(line_icon("trash"))
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self._start)
        buttons.addWidget(self.cancel_button)
        buttons.addWidget(self.delete_button)
        layout.addLayout(buttons)

    def _start(self) -> None:
        if self.running or not self.confirmation.isChecked():
            return
        self.running = True
        self.confirmation.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.delete_button.setEnabled(False)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self.show()
        self.progress.setValue(1)
        self.progress.setFormat("1% — Проверка выбранного файла")
        self.progress.show()
        self.thread = QThread(self)
        self.worker = SecureDeleteWorker(self.source)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._progress)
        self.worker.succeeded.connect(self._succeeded)
        self.worker.failed.connect(self._failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(int, str)
    def _progress(self, value: int, message: str) -> None:
        self.progress.setValue(value)
        self.progress.setFormat(f"{value}% — {tr(message)}")

    @Slot()
    def _succeeded(self) -> None:
        self.status.setObjectName("success")
        self.status.setText("Файл безвозвратно удалён.")
        self.status.show()
        self.delete_button.setText("Закрыть")
        self.delete_button.clicked.disconnect()
        self.delete_button.clicked.connect(self.accept)

    @Slot(str)
    def _failed(self, message: str) -> None:
        self.status.setObjectName("error")
        self.status.setText(message or "Не удалось удалить файл.")
        self.status.show()

    @Slot()
    def _finished(self) -> None:
        self.running = False
        self.progress.hide()
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, True)
        self.show()
        self.cancel_button.setEnabled(True)
        self.delete_button.setEnabled(True)
        self.worker = None
        self.thread = None

    def reject(self) -> None:
        if not self.running:
            super().reject()


def run_secure_delete_dialog(source: Path) -> int:
    application = QApplication(sys.argv)
    application.setApplicationName(APP_NAME)
    application.setOrganizationName(ORGANIZATION_NAME)
    install_screen_bounds(application)
    dialog = SecureDeleteDialog(source)
    dialog.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
    dialog.show()
    fit_window_to_screen(dialog)
    return 0 if dialog.exec() else 1


SECURE_DELETE_STYLESHEET = """
QDialog { background: #111827; color: #e5e7eb; font-family: "Segoe UI"; font-size: 14px; }
QLabel { background: transparent; }
QLabel#brand { color: #7dd3fc; font-size: 22px; font-weight: 700; }
QLabel#title { color: #f9fafb; font-size: 20px; font-weight: 700; }
QLabel#path { background: #182235; border: 1px solid #2d3b52; border-radius: 8px; padding: 10px 14px; color: #cbd5e1; }
QLabel#warning { color: #fde68a; background: #422006; border: 1px solid #a16207; border-radius: 9px; padding: 12px 14px; }
QLabel#success { color: #99f6e4; background: #052e2b; border: 1px solid #0f766e; border-radius: 9px; padding: 10px 14px; }
QLabel#error { color: #fca5a5; background: #3f151b; border: 1px solid #991b1b; border-radius: 9px; padding: 10px 14px; }
QCheckBox { spacing: 10px; padding: 8px 2px; }
QPushButton { background: #263449; border: 1px solid #475569; border-radius: 8px; color: #f9fafb; min-height: 42px; padding: 0 16px; font-weight: 600; }
QPushButton#danger { background: #b91c1c; border-color: #ef4444; }
QPushButton:disabled { color: #64748b; background: #1e293b; }
QProgressBar { border: 1px solid #475569; border-radius: 8px; background: #1e293b; color: #f8fafc; min-height: 28px; text-align: center; font-weight: 650; }
QProgressBar::chunk { background: #dc2626; border-radius: 7px; }
"""


__all__ = ["SecureDeleteDialog", "run_secure_delete_dialog"]
