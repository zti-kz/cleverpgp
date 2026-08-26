from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Qt, Signal, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
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
from cleverpgp.localization import localize_widget_tree, tr
from cleverpgp.ui.icons import line_icon


COPYRIGHT_TEXT = (
    "© 2026 Алмас Оскенбаев, Институт интеллектуальных технологий. "
    "Все права защищены."
)
LICENSE_TEXT = "Свободное программное обеспечение: GNU GPL v3 или более поздняя версия."
WINFSP_NOTICE = (
    "WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos. "
    '<a href="https://github.com/winfsp/winfsp">github.com/winfsp/winfsp</a>'
)
WINSPD_NOTICE = (
    "WinSpd - Windows Storage Proxy Driver, Copyright (C) Bill Zissimopoulos. "
    '<a href="https://github.com/winfsp/winspd">github.com/winfsp/winspd</a>'
)


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


class AboutDialog(QDialog):
    """Product information presented inside the application."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._update_result: UpdateCheckResult | None = None
        self._update_thread: QThread | None = None
        self.setWindowTitle("О программе Clever PGP")
        self.setModal(True)
        self.resize(960, 840)
        self.setMinimumSize(420, 320)
        self.setStyleSheet(ABOUT_STYLESHEET)
        self._build_ui()
        localize_widget_tree(self)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setObjectName("aboutScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        body = QWidget()
        body.setObjectName("aboutBody")
        outer = QVBoxLayout(body)
        outer.setContentsMargins(28, 26, 28, 24)
        outer.setSpacing(18)

        header = QHBoxLayout()
        identity = QVBoxLayout()
        brand = QLabel("Clever PGP")
        brand.setObjectName("aboutBrand")
        tagline = QLabel("Криптографическая защита файлов и дисков")
        tagline.setObjectName("muted")
        identity.addWidget(brand)
        identity.addWidget(tagline)
        header.addLayout(identity)
        header.addStretch()
        version = QLabel(tr("Версия {version}", version=__version__))
        version.setObjectName("versionBadge")
        header.addWidget(version, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(header)

        summary = QLabel(
            "Clever PGP — локальная программа для криптографической защиты файлов "
            "и зашифрованных дисков с биометрическим управлением. Программа "
            "разрабатывается как реализация метода "
            "криптографической защиты файлов с биометрическим управлением на "
            "основе распознавания лица. Она защищает отдельные файлы и создаёт "
            "контейнеры, которые подключаются в Windows как обычные диски."
        )
        summary.setObjectName("lead")
        summary.setWordWrap(True)
        outer.addWidget(summary)

        outer.addWidget(self._section(
            "Принцип криптографической защиты",
            "Для каждого файла и диска криптографически стойкий генератор "
            "формирует независимый случайный ключ. Пароль объекта не хранится и "
            "не используется как ключ данных: из него с индивидуальной солью и "
            "ресурсоёмкой функцией вырабатывается ключ доступа, защищающий "
            "случайный ключ объекта. Содержимое преобразуется аутентифицированным "
            "шифрованием. Изменение блока, неправильный пароль или повреждение "
            "приводят к отказу открытия без выдачи недостоверного результата.",
            "shield",
        ))
        outer.addWidget(self._section(
            "Биометрическое управление",
            "Биометрический доступ добавляется только после входа в выбранный "
            "диск по его паролю. Распознавание лица и проверка присутствия "
            "выполняются локально. Лицо не превращается в криптографический ключ: "
            "успешная верификация только разрешает использование защищённого "
            "ключа конкретного диска. Изображения, пароль и ключи не передаются "
            "на сервер.",
            "face",
        ))
        outer.addWidget(self._section(
            "Файлы и зашифрованные диски",
            "При отдельном шифровании исходный файл сохраняется, а защищённая "
            "копия получает расширение .cpgp. Контейнер .cpgv содержит "
            "зашифрованную файловую систему: защищаются структура каталогов, "
            "имена, метаданные и содержимое файлов. При записи криптографическое "
            "преобразование выполняется только для затронутых логических блоков. "
            "Каждый блок снабжается независимым параметром преобразования и кодом "
            "аутентичности, а его адрес и контекст поколения записи связаны с "
            "шифротекстом. Поэтому подмена, перестановка, возврат к прежней версии "
            "или повреждение блоков обнаруживаются при чтении. "
            "Метаданные сохраняются чередующимися согласованными состояниями: "
            "если запись прервана, используется предыдущее завершённое состояние. "
            "Открытая временная папка на диске не создаётся.",
            "vault",
        ))
        update_card = QFrame()
        update_card.setObjectName("aboutSection")
        update_layout = QVBoxLayout(update_card)
        update_layout.setContentsMargins(18, 15, 18, 16)
        update_layout.setSpacing(9)
        update_title = QLabel("Обновление Clever PGP")
        update_title.setObjectName("sectionTitle")
        self.update_status = QLabel(
            "Проверка выполняется только по запросу пользователя."
        )
        self.update_status.setObjectName("sectionText")
        self.update_status.setWordWrap(True)
        self.update_progress = QProgressBar()
        self.update_progress.setRange(0, 100)
        self.update_progress.hide()
        self.update_button = QPushButton("Проверить обновления")
        self.update_button.setObjectName("updateButton")
        self.update_button.setIcon(line_icon("shield"))
        self.update_button.clicked.connect(self._update_action)
        update_layout.addWidget(update_title)
        update_layout.addWidget(self.update_status)
        update_layout.addWidget(self.update_progress)
        update_layout.addWidget(self.update_button)
        outer.addWidget(update_card)
        outer.addStretch()

        copyright_label = QLabel(COPYRIGHT_TEXT)
        copyright_label.setObjectName("copyright")
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        copyright_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        outer.addWidget(copyright_label)
        license_label = QLabel(LICENSE_TEXT)
        license_label.setObjectName("license")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        license_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        outer.addWidget(license_label)
        winfsp_label = QLabel(WINFSP_NOTICE)
        winfsp_label.setObjectName("thirdParty")
        winfsp_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        winfsp_label.setTextFormat(Qt.TextFormat.RichText)
        winfsp_label.setOpenExternalLinks(True)
        winfsp_label.setWordWrap(True)
        outer.addWidget(winfsp_label)
        winspd_label = QLabel(WINSPD_NOTICE)
        winspd_label.setObjectName("thirdParty")
        winspd_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        winspd_label.setTextFormat(Qt.TextFormat.RichText)
        winspd_label.setOpenExternalLinks(True)
        winspd_label.setWordWrap(True)
        outer.addWidget(winspd_label)
        scroll.setWidget(body)
        root.addWidget(scroll)

    def _update_action(self) -> None:
        if self._update_thread is not None:
            return
        if self._update_result is not None and self._update_result.update_available:
            self._download_selected_update()
            return
        self._update_result = None
        self.update_button.setEnabled(False)
        self.update_status.setText(tr("Проверяем доступную версию…"))
        self.update_progress.setRange(0, 0)
        self.update_progress.setFormat("")
        self.update_progress.show()
        worker = UpdateCheckThread(self)
        self._update_thread = worker
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
        self.update_progress.hide()
        self.update_button.setEnabled(True)
        if result.update_available:
            self.update_status.setText(
                tr(
                    "Доступна версия {version}. Установщик будет загружен с официального сайта.",
                    version=result.latest_version or "",
                )
            )
            self.update_button.setText(tr("Скачать и установить"))
        elif result.status == "unavailable":
            self.update_status.setText(
                tr("Установщик на сервере пока недоступен. Попробуйте позже.")
            )
            self.update_button.setText(tr("Проверить снова"))
        else:
            self.update_status.setText(tr("Установлена актуальная версия Clever PGP."))
            self.update_button.setText(tr("Проверить снова"))

    def _download_selected_update(self) -> None:
        assert self._update_result is not None
        self.update_button.setEnabled(False)
        self.update_status.setText(tr("Загрузка обновления с официального сайта…"))
        self.update_progress.setRange(0, 100)
        self.update_progress.setValue(1)
        self.update_progress.setFormat(tr("1% — Подготовка загрузки"))
        self.update_progress.show()
        worker = UpdateDownloadThread(self._update_result, self)
        self._update_thread = worker
        worker.progress.connect(self._download_progress)
        worker.downloaded.connect(self._update_downloaded)
        worker.failed.connect(self._update_failed)
        worker.finished.connect(self._update_thread_finished)
        worker.start()

    @Slot(int, str)
    def _download_progress(self, value: int, message: str) -> None:
        self.update_progress.setValue(value)
        self.update_progress.setFormat(f"{value}% — {tr(message)}")

    @Slot(object)
    def _update_downloaded(self, installer: object) -> None:
        try:
            launch_update_installer(Path(str(installer)))
        except Exception as error:
            self._update_failed(str(error))
            return
        self.update_progress.setValue(100)
        self.update_progress.setFormat(tr("100% — Установщик запущен"))
        self.update_status.setText(
            tr("Установщик обновления запущен. Clever PGP завершает работу.")
        )
        application = QApplication.instance()
        if application is not None:
            application.quit()

    @Slot(str)
    def _update_failed(self, message: str) -> None:
        self._update_result = None
        self.update_progress.hide()
        self.update_status.setText(tr(message or "Не удалось проверить обновления."))
        self.update_button.setText(tr("Проверить снова"))
        self.update_button.setEnabled(True)

    @Slot()
    def _update_thread_finished(self) -> None:
        worker = self._update_thread
        self._update_thread = None
        if worker is not None:
            worker.deleteLater()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._update_thread is not None:
            event.ignore()
            return
        super().closeEvent(event)

    @staticmethod
    def _section(title: str, text: str, icon_name: str) -> QFrame:
        card = QFrame()
        card.setObjectName("aboutSection")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 15, 18, 16)
        layout.setSpacing(7)
        heading_row = QHBoxLayout()
        heading_icon = QLabel()
        heading_icon.setPixmap(line_icon(icon_name, "#7dd3fc").pixmap(22, 22))
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        description = QLabel(text)
        description.setObjectName("sectionText")
        description.setWordWrap(True)
        description.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        heading_row.addWidget(heading_icon)
        heading_row.addWidget(heading)
        heading_row.addStretch()
        layout.addLayout(heading_row)
        layout.addWidget(description)
        return card


ABOUT_STYLESHEET = """
QDialog, QWidget {
    background: #111827;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
}
QScrollArea#aboutScroll, QWidget#aboutBody { border: 0; background: #111827; }
QLabel { background: transparent; }
QLabel#aboutBrand { color: #7dd3fc; font-size: 28px; font-weight: 700; }
QLabel#muted { color: #9ca3af; }
QLabel#copyright { color: #94a3b8; padding: 8px 0 2px 0; }
QLabel#license { color: #7dd3fc; padding: 0 0 2px 0; }
QLabel#thirdParty { color: #94a3b8; padding: 0 0 2px 0; }
QLabel#thirdParty a { color: #7dd3fc; }
QLabel#versionBadge {
    color: #bae6fd;
    background: #0c4a6e;
    border: 1px solid #0369a1;
    border-radius: 13px;
    padding: 6px 12px;
    font-weight: 600;
}
QLabel#lead { color: #f3f4f6; font-size: 15px; line-height: 1.4; }
QFrame#aboutSection {
    background: #172033;
    border: 1px solid #2b3a55;
    border-radius: 12px;
}
QLabel#sectionTitle { color: #f9fafb; font-size: 16px; font-weight: 650; }
QLabel#sectionText { color: #cbd5e1; }
QPushButton#updateButton {
    background: #0284c7;
    border: 1px solid #0ea5e9;
    border-radius: 9px;
    color: white;
    min-height: 40px;
    padding: 0 16px;
    font-weight: 650;
}
QPushButton#updateButton:disabled { background: #1e293b; color: #64748b; }
QProgressBar {
    background: #1e293b;
    border: 1px solid #475569;
    border-radius: 8px;
    color: #f8fafc;
    min-height: 28px;
    text-align: center;
}
QProgressBar::chunk { background: #0284c7; border-radius: 7px; }
"""
