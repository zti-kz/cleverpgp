from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from cleverpgp import __version__
from cleverpgp.core.update_service import (
    UpdateCheckResult,
    check_for_update,
    download_update,
    launch_update_installer,
)
from cleverpgp.localization import tr
from cleverpgp.ui.icons import line_icon


class UpdateCheckThread(QThread):
    checked = Signal(object)
    failed = Signal(str)

    def run(self) -> None:
        try:
            self.checked.emit(check_for_update(__version__))
        except Exception as error:
            self.failed.emit(str(error))


class UpdateDownloadThread(QThread):
    downloaded = Signal(object)
    failed = Signal(str)
    progress = Signal(int, str)

    def __init__(self, result: UpdateCheckResult, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.result = result

    def run(self) -> None:
        try:
            target = download_update(
                self.result,
                progress=lambda value, message: self.progress.emit(value, message),
            )
            self.downloaded.emit(target)
        except Exception as error:
            self.failed.emit(str(error))


class UpdateWidget(QFrame):
    """User-initiated update check embedded in the Settings dialog."""

    busy_changed = Signal(bool)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._update_result: UpdateCheckResult | None = None
        self._update_thread: QThread | None = None
        self.setObjectName("settingsCard")
        self._build_ui()

    @property
    def busy(self) -> bool:
        return self._update_thread is not None

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 18)
        layout.setSpacing(10)
        title_row = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(line_icon("shield", "#7dd3fc").pixmap(21, 21))
        title = QLabel("Обновление Clever PGP")
        title.setObjectName("sectionTitle")
        title_row.addWidget(icon)
        title_row.addWidget(title)
        title_row.addStretch()
        layout.addLayout(title_row)
        self.status = QLabel("Проверка выполняется только по запросу пользователя.")
        self.status.setObjectName("muted")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.hide()
        layout.addWidget(self.progress)
        self.button = QPushButton("Проверить обновления")
        self.button.setObjectName("primary")
        self.button.setIcon(line_icon("shield"))
        self.button.clicked.connect(self._update_action)
        layout.addWidget(self.button)

    def _update_action(self) -> None:
        if self._update_thread is not None:
            return
        if self._update_result is not None and self._update_result.update_available:
            self._download_selected_update()
            return
        self._update_result = None
        self.button.setEnabled(False)
        self.status.setText(tr("Проверяем доступную версию…"))
        self.progress.setRange(0, 0)
        self.progress.setFormat("")
        self.progress.show()
        worker = UpdateCheckThread(self)
        self._update_thread = worker
        self.busy_changed.emit(True)
        worker.checked.connect(self._update_checked)
        worker.failed.connect(self._update_failed)
        worker.finished.connect(self._update_thread_finished)
        worker.start()

    @Slot(object)
    def _update_checked(self, result: object) -> None:
        if not isinstance(result, UpdateCheckResult):
            self._update_failed("Сервер вернул неверные данные о версии.")
            return
        self._update_result = result
        self.progress.hide()
        self.button.setEnabled(True)
        if result.update_available:
            self.status.setText(
                tr(
                    "Доступна версия {version}. Установщик будет загружен с официального сайта.",
                    version=result.latest_version or "",
                )
            )
            self.button.setText(tr("Скачать и установить"))
        elif result.status == "unavailable":
            self.status.setText(
                tr("Установщик на сервере пока недоступен. Попробуйте позже.")
            )
            self.button.setText(tr("Проверить снова"))
        else:
            self.status.setText(tr("Установлена актуальная версия Clever PGP."))
            self.button.setText(tr("Проверить снова"))

    def _download_selected_update(self) -> None:
        assert self._update_result is not None
        self.button.setEnabled(False)
        self.status.setText(tr("Загрузка обновления с официального сайта…"))
        self.progress.setRange(0, 100)
        self.progress.setValue(1)
        self.progress.setFormat(tr("1% — Подготовка загрузки"))
        self.progress.show()
        worker = UpdateDownloadThread(self._update_result, self)
        self._update_thread = worker
        self.busy_changed.emit(True)
        worker.progress.connect(self._download_progress)
        worker.downloaded.connect(self._update_downloaded)
        worker.failed.connect(self._update_failed)
        worker.finished.connect(self._update_thread_finished)
        worker.start()

    @Slot(int, str)
    def _download_progress(self, value: int, message: str) -> None:
        self.progress.setValue(value)
        self.progress.setFormat(f"{value}% — {tr(message)}")

    @Slot(object)
    def _update_downloaded(self, installer: object) -> None:
        try:
            launch_update_installer(Path(str(installer)))
        except Exception as error:
            self._update_failed(str(error))
            return
        self.progress.setValue(100)
        self.progress.setFormat(tr("100% — Установщик запущен"))
        self.status.setText(
            tr("Установщик обновления запущен. Clever PGP завершает работу.")
        )
        application = QApplication.instance()
        if application is not None:
            application.quit()

    @Slot(str)
    def _update_failed(self, message: str) -> None:
        self._update_result = None
        self.progress.hide()
        self.status.setText(tr(message or "Не удалось проверить обновления."))
        self.button.setText(tr("Проверить снова"))
        self.button.setEnabled(True)

    @Slot()
    def _update_thread_finished(self) -> None:
        worker = self._update_thread
        self._update_thread = None
        self.busy_changed.emit(False)
        if worker is not None:
            worker.deleteLater()


__all__ = ["UpdateWidget"]
