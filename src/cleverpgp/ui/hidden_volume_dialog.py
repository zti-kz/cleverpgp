from __future__ import annotations

import hmac
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QProgressBar,
    QSlider,
    QVBoxLayout,
)

from cleverpgp.core.block_volume import LOGICAL_BLOCK_SIZE
from cleverpgp.core.hidden_volume import HiddenBlockVolume
from cleverpgp.core.opaque_volume_header import (
    MAXIMUM_PASSWORD_BYTES,
    MINIMUM_PASSWORD_LENGTH,
)
from cleverpgp.core.winspd import MIN_WINDOWS_DISK_CAPACITY
from cleverpgp.localization import localize_widget_tree, tr
from cleverpgp.ui.adaptive import scrollable_dialog_layout
from cleverpgp.ui.container_dialog import ContainerCreationDialog
from cleverpgp.ui.icons import line_icon
from cleverpgp.ui.password_generator import add_password_generator_action


@dataclass(frozen=True, slots=True)
class HiddenVolumeCreationRequest:
    hidden_capacity: int
    outer_password: str
    hidden_password: str
    hidden_label: str


@dataclass(frozen=True, slots=True)
class OpaqueVolumeUnlockRequest:
    password: str


class HiddenVolumeCreationDialog(QDialog):
    """Second wizard step for a new outer/hidden file-hosted volume."""

    def __init__(
        self,
        outer_capacity: int,
        outer_label: str,
        parent: object = None,
    ) -> None:
        super().__init__(parent)
        outer_blocks = outer_capacity // LOGICAL_BLOCK_SIZE
        outer_minimum_blocks = MIN_WINDOWS_DISK_CAPACITY // LOGICAL_BLOCK_SIZE
        available_region_blocks = outer_blocks - outer_minimum_blocks
        if available_region_blocks <= 0:
            raise ValueError("Внешний диск слишком мал для скрытого диска.")
        maximum = HiddenBlockVolume.maximum_logical_capacity(
            available_region_blocks
        )
        if maximum < MIN_WINDOWS_DISK_CAPACITY:
            raise ValueError(
                "Увеличьте внешний диск: для внешней и скрытой файловых систем "
                "требуется больше места."
            )
        self._outer_capacity = outer_capacity
        self._outer_label = outer_label.strip() or "Clever PGP"
        self._maximum_hidden_capacity = maximum
        self._capacity_choices = ContainerCreationDialog._build_capacity_choices(
            maximum,
            minimum_capacity=MIN_WINDOWS_DISK_CAPACITY,
        )
        self.request: HiddenVolumeCreationRequest | None = None
        self.setWindowTitle("Скрытый диск — Clever PGP")
        self.setMinimumWidth(420)
        self.resize(700, 760)
        self.setStyleSheet(HIDDEN_DIALOG_STYLESHEET)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = scrollable_dialog_layout(self)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(12)

        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        title = QLabel("Внешний и скрытый диски")
        title.setObjectName("title")
        explanation = QLabel(
            "Один файл .cpgv получит два независимых пароля. Пароль внешнего "
            "диска открывает обычные данные, пароль скрытого — скрытый диск. "
            "Пароли не записываются в контейнер."
        )
        explanation.setObjectName("muted")
        explanation.setWordWrap(True)
        layout.addWidget(brand)
        layout.addWidget(title)
        layout.addWidget(explanation)

        summary = QFrame()
        summary.setObjectName("card")
        summary_layout = QVBoxLayout(summary)
        summary_layout.setContentsMargins(16, 12, 16, 12)
        summary_layout.addWidget(
            QLabel(
                tr(
                    "Внешний диск: {label}, {size}",
                    label=self._outer_label,
                    size=ContainerCreationDialog._format_capacity(
                        self._outer_capacity
                    ),
                )
            )
        )
        self.hidden_size_value = QLabel()
        self.hidden_size_value.setObjectName("sizeValue")
        summary_layout.addWidget(self.hidden_size_value)
        self.hidden_size_slider = QSlider(Qt.Orientation.Horizontal)
        self.hidden_size_slider.setObjectName("capacitySlider")
        self.hidden_size_slider.setRange(0, len(self._capacity_choices) - 1)
        self.hidden_size_slider.setValue(0)
        self.hidden_size_slider.valueChanged.connect(self._update_size)
        summary_layout.addWidget(self.hidden_size_slider)
        scale = QHBoxLayout()
        scale.addWidget(
            QLabel(
                tr(
                    "Минимум: {size}",
                    size=ContainerCreationDialog._format_capacity(
                        MIN_WINDOWS_DISK_CAPACITY
                    ),
                )
            )
        )
        scale.addStretch()
        maximum_label = QLabel(
            tr(
                "Максимум: {size}",
                size=ContainerCreationDialog._format_capacity(
                    self._maximum_hidden_capacity
                ),
            )
        )
        maximum_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        scale.addWidget(maximum_label)
        summary_layout.addLayout(scale)
        layout.addWidget(summary)

        self.outer_password = self._password_input("Пароль внешнего диска")
        self.outer_password_repeat = self._password_input(
            "Повторите пароль внешнего диска"
        )
        self.hidden_password = self._password_input("Пароль скрытого диска")
        self.hidden_password_repeat = self._password_input(
            "Повторите пароль скрытого диска"
        )
        layout.addWidget(self.outer_password)
        layout.addWidget(self.outer_password_repeat)
        add_password_generator_action(
            self.outer_password,
            self.outer_password_repeat,
        )
        layout.addWidget(self.hidden_password)
        layout.addWidget(self.hidden_password_repeat)
        add_password_generator_action(
            self.hidden_password,
            self.hidden_password_repeat,
        )

        self.hidden_label = QLineEdit(self._hidden_capacity_name())
        self.hidden_label.setMaxLength(31)
        self.hidden_label.setPlaceholderText("Название скрытого диска")
        layout.addWidget(self.hidden_label)

        warning = QLabel(
            "Используйте разные пароли длиной не менее 12 символов. Если оба "
            "пароля потеряны, восстановить скрытые данные невозможно."
        )
        warning.setObjectName("warning")
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self.error_label = QLabel()
        self.error_label.setObjectName("error")
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        layout.addWidget(self.error_label)

        buttons = QHBoxLayout()
        cancel = QPushButton("Отмена")
        cancel.setIcon(line_icon("close"))
        cancel.clicked.connect(self.reject)
        create = QPushButton("Создать скрытый диск")
        create.setObjectName("primary")
        create.setIcon(line_icon("vault_add"))
        create.clicked.connect(self.accept)
        buttons.addStretch()
        buttons.addWidget(cancel)
        buttons.addWidget(create)
        layout.addLayout(buttons)

        localize_widget_tree(self)
        self._update_size()
        self.outer_password.setFocus()

    @property
    def hidden_capacity(self) -> int:
        return self._capacity_choices[self.hidden_size_slider.value()]

    def accept(self) -> None:
        try:
            outer = self.outer_password.text()
            hidden = self.hidden_password.text()
            self._validate_password(outer)
            self._validate_password(hidden)
            if outer != self.outer_password_repeat.text():
                raise ValueError("Пароли внешнего диска не совпадают.")
            if hidden != self.hidden_password_repeat.text():
                raise ValueError("Пароли скрытого диска не совпадают.")
            if hmac.compare_digest(outer.encode(), hidden.encode()):
                raise ValueError(
                    "Пароли внешнего и скрытого дисков должны отличаться."
                )
            label = self.hidden_label.text().strip()
            if not label:
                raise ValueError("Введите название скрытого диска.")
            self.request = HiddenVolumeCreationRequest(
                self.hidden_capacity,
                outer,
                hidden,
                label,
            )
        except ValueError as error:
            self.error_label.setText(tr(str(error)))
            self.error_label.show()
            return
        self.outer_password_repeat.clear()
        self.hidden_password_repeat.clear()
        super().accept()

    def reject(self) -> None:
        self.request = None
        for field in (
            self.outer_password,
            self.outer_password_repeat,
            self.hidden_password,
            self.hidden_password_repeat,
        ):
            field.clear()
        super().reject()

    def _update_size(self, *_: object) -> None:
        self.hidden_size_value.setText(
            tr(
                "Скрытый диск: {size}",
                size=ContainerCreationDialog._format_capacity(
                    self.hidden_capacity
                ),
            )
        )
        if hasattr(self, "hidden_label") and not self.hidden_label.isModified():
            self.hidden_label.setText(self._hidden_capacity_name())

    def _hidden_capacity_name(self) -> str:
        capacity_name = ContainerCreationDialog._capacity_name(
            self.hidden_capacity
        ).removeprefix("CPGP_")
        return f"CPGP_HIDDEN_{capacity_name}"

    @staticmethod
    def _password_input(placeholder: str) -> QLineEdit:
        field = QLineEdit()
        field.setEchoMode(QLineEdit.EchoMode.Password)
        field.setPlaceholderText(placeholder)
        field.addAction(line_icon("lock"), QLineEdit.ActionPosition.LeadingPosition)
        return field

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < MINIMUM_PASSWORD_LENGTH:
            raise ValueError(
                f"Пароль диска должен содержать не менее "
                f"{MINIMUM_PASSWORD_LENGTH} символов."
            )
        if len(password.encode("utf-8")) > MAXIMUM_PASSWORD_BYTES:
            raise ValueError("Пароль диска слишком длинный.")


class OpaqueVolumeUnlockDialog(QDialog):
    """Ask for a v6 volume password without exposing which role it selects."""

    def __init__(self, source: Path, parent: object = None) -> None:
        super().__init__(parent)
        self.source = Path(source).expanduser().resolve()
        self.request: OpaqueVolumeUnlockRequest | None = None
        self.setWindowTitle("Разблокировка диска — Clever PGP")
        self.setMinimumWidth(420)
        self.resize(640, 350)
        self.setStyleSheet(HIDDEN_DIALOG_STYLESHEET)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = scrollable_dialog_layout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(13)
        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        title = QLabel("Разблокировать зашифрованный диск")
        title.setObjectName("title")
        source = QLabel(str(self.source))
        source.setObjectName("path")
        source.setWordWrap(True)
        layout.addWidget(brand)
        layout.addWidget(title)
        layout.addWidget(source)

        self.password = HiddenVolumeCreationDialog._password_input(
            "Пароль диска"
        )
        self.password.returnPressed.connect(self.accept)
        layout.addWidget(self.password)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.hide()
        layout.addWidget(self.progress)

        self.error_label = QLabel()
        self.error_label.setObjectName("error")
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        layout.addWidget(self.error_label)

        buttons = QHBoxLayout()
        self.cancel_button = QPushButton("Отмена")
        self.cancel_button.setIcon(line_icon("close"))
        self.cancel_button.clicked.connect(self.reject)
        self.unlock_button = QPushButton("Разблокировать диск")
        self.unlock_button.setObjectName("primary")
        self.unlock_button.setIcon(line_icon("unlock"))
        self.unlock_button.clicked.connect(self.accept)
        buttons.addStretch()
        buttons.addWidget(self.cancel_button)
        buttons.addWidget(self.unlock_button)
        layout.addLayout(buttons)
        localize_widget_tree(self)
        self.password.setFocus()

    def accept(self) -> None:
        try:
            password = self.password.text()
            HiddenVolumeCreationDialog._validate_password(password)
            self.request = OpaqueVolumeUnlockRequest(password)
        except ValueError as error:
            self.error_label.setText(tr(str(error)))
            self.error_label.show()
            return
        super().accept()

    def reject(self) -> None:
        if not self.cancel_button.isEnabled():
            return
        self.request = None
        self.password.clear()
        super().reject()

    def begin_operation(self) -> None:
        self.error_label.hide()
        self.password.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.unlock_button.setEnabled(False)
        self.progress.setValue(1)
        self.progress.setFormat(tr("1% — Проверка пароля и подключение"))
        self.progress.show()

    def update_progress(self, value: int, message: str) -> None:
        self.progress.setValue(value)
        suffix = f" — {tr(message)}" if message else ""
        self.progress.setFormat(f"{value}%{suffix}")

    def operation_failed(self, message: str) -> None:
        self.request = None
        self.password.clear()
        self.password.setEnabled(True)
        self.cancel_button.setEnabled(True)
        self.unlock_button.setEnabled(True)
        self.error_label.setText(tr(message or "Неверный пароль диска."))
        self.error_label.show()
        self.password.setFocus()

    def operation_succeeded(self) -> None:
        self.progress.setValue(100)
        self.progress.setFormat(tr("100% — Диск подключён"))
        self.password.clear()
        self.cancel_button.setEnabled(True)
        self.close()

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self.cancel_button.isEnabled():
            event.ignore()
            return
        super().closeEvent(event)


HIDDEN_DIALOG_STYLESHEET = """
QDialog {
    background: #0b1220;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
}
QLabel { background: transparent; }
QLabel#brand { color: #7dd3fc; font-size: 23px; font-weight: 750; }
QLabel#title { color: #f8fafc; font-size: 23px; font-weight: 700; }
QLabel#muted { color: #94a3b8; }
QLabel#warning {
    background: #302411;
    border: 1px solid #854d0e;
    border-radius: 9px;
    color: #fde68a;
    padding: 10px;
}
QLabel#error {
    background: #3f151b;
    border: 1px solid #991b1b;
    border-radius: 8px;
    color: #fecaca;
    padding: 10px;
}
QLabel#path, QFrame#card {
    background: #0d2135;
    border: 1px solid #1e4f70;
    border-radius: 10px;
    padding: 9px;
}
QLabel#sizeValue { color: #7dd3fc; font-size: 22px; font-weight: 750; }
QLineEdit {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 9px;
    color: #f8fafc;
    min-height: 40px;
    padding: 0 12px;
}
QLineEdit:focus { border-color: #38bdf8; }
QCheckBox { color: #e2e8f0; spacing: 9px; }
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
QSlider#capacitySlider { min-height: 34px; }
QSlider#capacitySlider::groove:horizontal {
    background: #243247;
    border-radius: 4px;
    height: 8px;
}
QSlider#capacitySlider::sub-page:horizontal {
    background: #0ea5e9;
    border-radius: 4px;
}
QSlider#capacitySlider::handle:horizontal {
    background: #e0f2fe;
    border: 3px solid #0284c7;
    border-radius: 11px;
    height: 22px;
    width: 22px;
    margin: -8px 0;
}
QProgressBar {
    background: #1e293b;
    border: 1px solid #475569;
    border-radius: 8px;
    color: #f8fafc;
    min-height: 28px;
    text-align: center;
    font-weight: 650;
}
QProgressBar::chunk { background: #0284c7; border-radius: 7px; }
"""
