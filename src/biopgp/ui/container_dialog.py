from __future__ import annotations

from decimal import Decimal, InvalidOperation
from pathlib import Path

from PySide6.QtCore import Qt, QStandardPaths, QRegularExpression
from PySide6.QtGui import QColor, QRegularExpressionValidator
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from biopgp.core.container import (
    CONTAINER_SUFFIX,
    MAX_FORMAT_FILE_SIZE,
    EncryptedContainer,
)
from biopgp.core.errors import ValidationError
from biopgp.localization import localize_widget_tree, tr
from biopgp.ui.icons import line_icon

MEBIBYTE = 1024 * 1024
GIBIBYTE = 1024 * MEBIBYTE
TEBIBYTE = 1024 * GIBIBYTE
UNIT_FACTORS = (("МБ", MEBIBYTE), ("ГБ", GIBIBYTE), ("ТБ", TEBIBYTE))
DEFAULT_SIZE = "20"


class ContainerCreationDialog(QDialog):
    def __init__(self, parent: object = None) -> None:
        super().__init__(parent)
        self._selected_path: Path | None = None
        self.setWindowTitle("Новый зашифрованный диск — Clever PGP")
        self.setMinimumWidth(640)
        self.resize(680, 720)
        self.setStyleSheet(CONTAINER_DIALOG_STYLESHEET)
        self._build_ui()

    @property
    def container_path(self) -> Path:
        if self._selected_path is not None:
            return self._selected_path
        return self._normalized_path()

    @property
    def data_capacity(self) -> int:
        return self._parsed_capacity()

    @property
    def volume_label(self) -> str:
        return self.label_input.text().strip() or "Clever PGP"

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 28)
        outer.setSpacing(18)

        brand_row = QHBoxLayout()
        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        badge = QLabel("ЗАШИФРОВАННЫЙ ДИСК")
        badge.setObjectName("badge")
        brand_row.addWidget(brand)
        brand_row.addStretch()
        brand_row.addWidget(badge)
        outer.addLayout(brand_row)

        title = QLabel("Создание защищённого контейнера")
        title.setObjectName("title")
        subtitle = QLabel(
            "После подключения контейнер появится в Проводнике как обычный диск. "
            "Файлы внутри шифруются автоматически."
        )
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        outer.addWidget(title)
        outer.addWidget(subtitle)

        path_title = QLabel("Где сохранить контейнер")
        path_title.setObjectName("fieldTitle")
        outer.addWidget(path_title)
        path_row = QHBoxLayout()
        self.path_input = QLineEdit(str(self._default_path()))
        self.path_input.setPlaceholderText("Путь к файлу .cpgv")
        browse_button = QPushButton("Обзор…")
        browse_button.setIcon(line_icon("folder"))
        browse_button.clicked.connect(self._browse)
        path_row.addWidget(self.path_input, 1)
        path_row.addWidget(browse_button)
        outer.addLayout(path_row)

        storage_card = QFrame()
        storage_card.setObjectName("storageCard")
        storage_layout = QVBoxLayout(storage_card)
        storage_layout.setContentsMargins(16, 12, 16, 12)
        storage_layout.setSpacing(4)
        self.storage_location = QLabel()
        self.storage_location.setObjectName("storageTitle")
        self.storage_space = QLabel()
        self.storage_space.setObjectName("muted")
        self.storage_space.setWordWrap(True)
        self.storage_warning = QLabel()
        self.storage_warning.setObjectName("capacityWarning")
        self.storage_warning.setWordWrap(True)
        self.storage_warning.hide()
        storage_layout.addWidget(self.storage_location)
        storage_layout.addWidget(self.storage_space)
        storage_layout.addWidget(self.storage_warning)
        outer.addWidget(storage_card)

        size_card = QFrame()
        size_card.setObjectName("sizeCard")
        shadow = QGraphicsDropShadowEffect(size_card)
        shadow.setBlurRadius(28)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(2, 132, 199, 70))
        size_card.setGraphicsEffect(shadow)
        size_layout = QVBoxLayout(size_card)
        size_layout.setContentsMargins(24, 22, 24, 22)
        size_layout.setSpacing(12)

        size_header = QHBoxLayout()
        size_caption = QLabel("Ёмкость зашифрованного диска")
        size_caption.setObjectName("fieldTitle")
        self.size_value = QLabel()
        self.size_value.setObjectName("sizeValue")
        size_header.addWidget(size_caption)
        size_header.addStretch()
        size_header.addWidget(self.size_value)
        size_layout.addLayout(size_header)

        exact_row = QHBoxLayout()
        exact_label = QLabel("Укажите объём")
        exact_label.setObjectName("muted")
        self.size_input = QLineEdit(DEFAULT_SIZE)
        self.size_input.setValidator(
            QRegularExpressionValidator(
                QRegularExpression(r"[0-9]{0,20}([\.,][0-9]{0,2})?")
            )
        )
        self.size_input.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.size_input.setPlaceholderText("Например, 20")
        self.unit_input = QComboBox()
        for unit, factor in UNIT_FACTORS:
            self.unit_input.addItem(unit, factor)
        self.unit_input.setCurrentIndex(0)
        self.unit_input.setMinimumWidth(90)
        exact_row.addWidget(exact_label)
        exact_row.addStretch()
        exact_row.addWidget(self.size_input, 1)
        exact_row.addWidget(self.unit_input)
        size_layout.addLayout(exact_row)

        self.size_hint = QLabel()
        self.size_hint.setObjectName("hint")
        self.size_hint.setWordWrap(True)
        size_layout.addWidget(self.size_hint)
        no_limit = QLabel(
            "Максимальный размер рассчитывается по свободному месту именно на "
            "выбранном накопителе."
        )
        no_limit.setObjectName("muted")
        no_limit.setWordWrap(True)
        size_layout.addWidget(no_limit)
        outer.addWidget(size_card)

        label_title = QLabel("Название диска")
        label_title.setObjectName("fieldTitle")
        self.label_input = QLineEdit("Clever PGP")
        self.label_input.setMaxLength(31)
        self.label_input.setPlaceholderText("Например, Личные документы")
        outer.addWidget(label_title)
        outer.addWidget(self.label_input)

        self.error_label = QLabel()
        self.error_label.setObjectName("error")
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        outer.addWidget(self.error_label)

        buttons = QHBoxLayout()
        cancel_button = QPushButton("Отмена")
        cancel_button.setIcon(line_icon("close"))
        cancel_button.clicked.connect(self.reject)
        self.create_button = QPushButton("Создать контейнер")
        self.create_button.setObjectName("primary")
        self.create_button.setIcon(line_icon("vault_add"))
        self.create_button.clicked.connect(self.accept)
        buttons.addStretch()
        buttons.addWidget(cancel_button)
        buttons.addWidget(self.create_button)
        outer.addLayout(buttons)

        self.size_input.textChanged.connect(self._update_size_summary)
        self.unit_input.currentTextChanged.connect(self._update_size_summary)
        self.path_input.textChanged.connect(self._update_storage_summary)
        localize_widget_tree(self)
        self._update_size_summary()

    def accept(self) -> None:
        try:
            path = self._normalized_path()
            if not path.parent.is_dir():
                raise ValueError("Выбранная папка не существует.")
            if path.exists():
                raise ValueError("Файл с таким именем уже существует. Выберите другое имя.")
            if not self.volume_label:
                raise ValueError("Введите название диска.")
            capacity = self._parsed_capacity()
            _, maximum_capacity = EncryptedContainer.storage_space(path)
            if capacity > maximum_capacity:
                raise ValueError(
                    "Недостаточно свободного места на выбранном накопителе."
                )
        except (OSError, ValueError, ValidationError) as error:
            self.error_label.setText(tr(str(error)))
            self.error_label.show()
            return
        self._selected_path = path
        super().accept()

    def _browse(self) -> None:
        selected, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить контейнер Clever PGP"),
            self.path_input.text(),
            tr("Контейнер Clever PGP (*.cpgv)"),
        )
        if selected:
            self.path_input.setText(selected)
            self.error_label.hide()

    def _normalized_path(self) -> Path:
        raw_path = self.path_input.text().strip()
        if not raw_path:
            raise ValueError("Выберите место для контейнера.")
        path = Path(raw_path).expanduser()
        if path.suffix.lower() != CONTAINER_SUFFIX:
            path = path.with_name(path.name + CONTAINER_SUFFIX)
        return path.resolve()

    def _parsed_capacity(self) -> int:
        raw_value = self.size_input.text().strip().replace(",", ".")
        try:
            value = Decimal(raw_value)
        except InvalidOperation as error:
            raise ValueError("Введите корректный объём диска.") from error
        if not value.is_finite() or value <= 0:
            raise ValueError("Объём диска должен быть больше нуля.")
        capacity = int(value * int(self.unit_input.currentData()))
        if capacity < MEBIBYTE:
            raise ValueError("Минимальная ёмкость зашифрованного диска — 1 МБ.")
        if capacity > MAX_FORMAT_FILE_SIZE - 2 * MEBIBYTE:
            raise ValueError("Такой объём не поддерживается выбранной файловой системой.")
        return capacity

    def _update_size_summary(self, *_: object) -> None:
        try:
            capacity = self._parsed_capacity()
            display = self._format_capacity(capacity)
            self.size_value.setText(display)
            self.size_hint.setText(tr(
                "Указана максимальная ёмкость диска. Контейнер не занимает всё "
                "место сразу и увеличивает фактически занятую область по мере "
                "добавления файлов."
            ))
        except ValueError:
            self.size_value.setText("—")
            self.size_hint.setText(
                tr("Введите желаемую ёмкость и выберите единицу измерения.")
            )
        self._update_storage_summary()

    def _update_storage_summary(self, *_: object) -> None:
        self.storage_warning.hide()
        try:
            path = self._normalized_path()
            free_bytes, maximum_capacity = EncryptedContainer.storage_space(path)
        except (OSError, ValueError, ValidationError):
            self.storage_location.setText(tr("Накопитель не выбран"))
            self.storage_space.setText(
                tr("Выберите существующую папку для контейнера.")
            )
            self.create_button.setEnabled(False)
            return

        drive_name = path.anchor.rstrip("\\/") or str(path.parent)
        self.storage_location.setText(
            tr("Выбранный накопитель: {drive}", drive=drive_name)
        )
        self.storage_space.setText(
            tr(
                "Свободно: {free}. Максимальный размер контейнера: {maximum}.",
                free=self._format_bytes(free_bytes),
                maximum=self._format_bytes(maximum_capacity),
            )
        )

        try:
            requested_capacity = self._parsed_capacity()
        except ValueError:
            self.create_button.setEnabled(False)
            return
        if requested_capacity > maximum_capacity:
            self.storage_warning.setText(
                tr(
                    "Указанный размер превышает свободное место на выбранном накопителе."
                )
            )
            self.storage_warning.show()
            self.create_button.setEnabled(False)
            return
        self.create_button.setEnabled(not path.exists())

    @staticmethod
    def _format_capacity(capacity: int) -> str:
        for unit, factor in ((tr("ТБ"), TEBIBYTE), (tr("ГБ"), GIBIBYTE)):
            if capacity >= factor and capacity % factor == 0:
                return f"{capacity // factor} {unit}"
        return f"{capacity / MEBIBYTE:g} {tr('МБ')}"

    @staticmethod
    def _format_bytes(size: int) -> str:
        for unit, factor in (
            (tr("ТБ"), TEBIBYTE),
            (tr("ГБ"), GIBIBYTE),
            (tr("МБ"), MEBIBYTE),
        ):
            if size >= factor:
                value = size / factor
                formatted = f"{value:.2f}".rstrip("0").rstrip(".")
                return f"{formatted} {unit}"
        return f"{size} {tr('байт')}"

    @staticmethod
    def _default_path() -> Path:
        documents = QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.DocumentsLocation
        )
        base = Path(documents) if documents else Path.cwd()
        return base / f"{tr('Защищённый диск')}{CONTAINER_SUFFIX}"


CONTAINER_DIALOG_STYLESHEET = """
QDialog {
    background: #0b1220;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
}
QLabel { background: transparent; }
QLabel#brand { color: #7dd3fc; font-size: 23px; font-weight: 750; }
QLabel#badge {
    background: #0c4a6e;
    border: 1px solid #0369a1;
    border-radius: 10px;
    color: #bae6fd;
    font-size: 10px;
    font-weight: 700;
    padding: 5px 10px;
}
QLabel#title { color: #f8fafc; font-size: 24px; font-weight: 700; }
QLabel#muted { color: #94a3b8; }
QLabel#fieldTitle { color: #e2e8f0; font-weight: 650; }
QLabel#storageTitle { color: #bae6fd; font-weight: 650; }
QLabel#sizeValue { color: #7dd3fc; font-size: 28px; font-weight: 750; }
QLabel#hint {
    background: #10233a;
    border-radius: 8px;
    color: #bae6fd;
    padding: 9px 11px;
}
QLabel#error {
    background: #3f151b;
    border: 1px solid #991b1b;
    border-radius: 8px;
    color: #fecaca;
    padding: 10px;
}
QLabel#capacityWarning {
    color: #fca5a5;
    padding-top: 4px;
}
QFrame#storageCard {
    background: #0d2135;
    border: 1px solid #1e4f70;
    border-radius: 10px;
}
QFrame#sizeCard {
    background: #111c2e;
    border: 1px solid #1e4f70;
    border-radius: 16px;
}
QLineEdit, QComboBox {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 9px;
    color: #f8fafc;
    min-height: 40px;
    padding: 0 12px;
    selection-background-color: #0284c7;
}
QLineEdit:focus, QComboBox:focus { border-color: #38bdf8; }
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
QPushButton#primary:hover { background: #0369a1; }
"""
