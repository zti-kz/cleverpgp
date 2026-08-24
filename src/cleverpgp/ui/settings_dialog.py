from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from cleverpgp.core.models import UnlockMode
from cleverpgp.localization import (
    available_languages,
    current_language,
    localize_widget_tree,
    tr,
)
from cleverpgp.ui.adaptive import scrollable_dialog_layout
from cleverpgp.ui.icons import line_icon


@dataclass(frozen=True, slots=True)
class AccessSettingsRequest:
    operation: str
    unlock_mode: UnlockMode | None = None
    current_password: str = ""
    new_password: str = ""
    language_code: str = ""
    language_pack_path: Path | None = None


class AccessSettingsDialog(QDialog):
    """Compact access controls; the title-bar X is the only close control."""

    def __init__(
        self,
        current_mode: UnlockMode,
        *,
        biometric_enrolled: bool,
        drive: str | None = None,
        selected_language: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._biometric_enrolled = biometric_enrolled
        self.request: AccessSettingsRequest | None = None
        self.setWindowTitle("Настройки доступа — Clever PGP")
        self.setModal(True)
        self.setMinimumWidth(420)
        self.resize(760, 760)
        self.setStyleSheet(SETTINGS_STYLESHEET)
        self._build_ui(
            current_mode,
            drive=drive,
            selected_language=selected_language or current_language(),
        )
        localize_widget_tree(self)

    def _build_ui(
        self,
        current_mode: UnlockMode,
        *,
        drive: str | None,
        selected_language: str,
    ) -> None:
        outer = scrollable_dialog_layout(self)
        outer.setContentsMargins(30, 26, 30, 28)
        outer.setSpacing(14)

        header = QHBoxLayout()
        identity = QVBoxLayout()
        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        title = QLabel("Настройки доступа")
        title.setObjectName("title")
        identity.addWidget(brand)
        identity.addWidget(title)
        header.addLayout(identity)
        header.addStretch()
        icon = QLabel()
        icon.setPixmap(line_icon("settings", "#7dd3fc").pixmap(42, 42))
        header.addWidget(icon)
        outer.addLayout(header)

        if drive is not None:
            selected_disk = QLabel(tr("Подключённый диск: {drive}", drive=drive))
            selected_disk.setObjectName("path")
            outer.addWidget(selected_disk)

        scope_note = QLabel(
            "Эти настройки относятся к локальному профилю Clever PGP. "
            "Пароли внешнего и скрытого дисков изменяются "
            "отдельной командой в контекстном меню."
        )
        scope_note.setObjectName("muted")
        scope_note.setWordWrap(True)
        outer.addWidget(scope_note)

        language_card = self._card()
        language_layout = QVBoxLayout(language_card)
        language_layout.setContentsMargins(18, 16, 18, 18)
        language_layout.setSpacing(10)
        language_layout.addWidget(
            self._section_title("Язык интерфейса", "language")
        )
        language_note = QLabel(
            "Выбранный язык будет использован после следующего запуска "
            "Clever PGP. Текущие операции при этом не прерываются."
        )
        language_note.setObjectName("muted")
        language_note.setWordWrap(True)
        language_layout.addWidget(language_note)
        self.language_input = QComboBox()
        self.language_input.setObjectName("languageSelector")
        for language in available_languages():
            self.language_input.addItem(language.native_name, language.code)
        self.language_input.setCurrentIndex(
            max(0, self.language_input.findData(selected_language))
        )
        language_layout.addWidget(self.language_input)
        language_button = QPushButton("Сохранить язык")
        language_button.setIcon(line_icon("language"))
        language_button.clicked.connect(self._request_language_change)
        language_layout.addWidget(language_button)
        add_language_button = QPushButton("Добавить язык…")
        add_language_button.setIcon(line_icon("language"))
        add_language_button.clicked.connect(self._request_language_installation)
        language_layout.addWidget(add_language_button)
        outer.addWidget(language_card)

        mode_card = self._card()
        mode_layout = QVBoxLayout(mode_card)
        mode_layout.setContentsMargins(18, 16, 18, 18)
        mode_layout.setSpacing(10)
        mode_layout.addWidget(self._section_title("Способ разблокировки", "unlock"))
        mode_note = QLabel(
            "Выберите, какие факторы требуются при следующей разблокировке. "
            "Мастер-пароль сохраняется как локальный аварийный способ доступа."
        )
        mode_note.setObjectName("muted")
        mode_note.setWordWrap(True)
        mode_layout.addWidget(mode_note)
        self.mode_input = QComboBox()
        for mode in UnlockMode:
            self.mode_input.addItem(mode.display_name, mode.value)
        self.mode_input.setCurrentIndex(
            max(0, self.mode_input.findData(current_mode.value))
        )
        mode_layout.addWidget(self.mode_input)
        mode_button = QPushButton("Применить режим")
        mode_button.setIcon(line_icon("shield"))
        mode_button.clicked.connect(self._request_mode_change)
        mode_layout.addWidget(mode_button)
        outer.addWidget(mode_card)

        face_card = self._card()
        face_layout = QHBoxLayout(face_card)
        face_layout.setContentsMargins(18, 15, 18, 15)
        face_text = QVBoxLayout()
        face_title = QLabel("Биометрическое управление")
        face_title.setObjectName("sectionTitle")
        face_status = QLabel(
            "Лицо зарегистрировано"
            if self._biometric_enrolled
            else "Лицо ещё не зарегистрировано"
        )
        face_status.setObjectName("success" if self._biometric_enrolled else "muted")
        face_text.addWidget(face_title)
        face_text.addWidget(face_status)
        face_layout.addLayout(face_text, 1)
        face_button = QPushButton(
            "Обновить данные лица"
            if self._biometric_enrolled
            else "Зарегистрировать лицо"
        )
        face_button.setIcon(line_icon("face"))
        face_button.clicked.connect(self._request_face_enrollment)
        face_layout.addWidget(face_button)
        outer.addWidget(face_card)

        password_card = self._card()
        password_layout = QVBoxLayout(password_card)
        password_layout.setContentsMargins(18, 16, 18, 18)
        password_layout.setSpacing(10)
        password_layout.addWidget(self._section_title("Смена мастер-пароля", "lock"))
        password_note = QLabel(
            "Мастер-ключ не изменяется. Файлы и зашифрованные диски продолжат "
            "открываться после смены пароля."
        )
        password_note.setObjectName("muted")
        password_note.setWordWrap(True)
        password_layout.addWidget(password_note)
        self.current_password_input = self._password_input("Текущий мастер-пароль")
        self.new_password_input = self._password_input("Новый мастер-пароль")
        self.repeat_password_input = self._password_input("Повторите новый пароль")
        password_layout.addWidget(self.current_password_input)
        password_layout.addWidget(self.new_password_input)
        password_layout.addWidget(self.repeat_password_input)
        password_button = QPushButton("Изменить мастер-пароль")
        password_button.setObjectName("primary")
        password_button.setIcon(line_icon("lock"))
        password_button.clicked.connect(self._request_password_change)
        password_layout.addWidget(password_button)
        outer.addWidget(password_card)

        self.error_label = QLabel()
        self.error_label.setObjectName("error")
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        outer.addWidget(self.error_label)

    @staticmethod
    def _card() -> QFrame:
        card = QFrame()
        card.setObjectName("settingsCard")
        return card

    @staticmethod
    def _section_title(text: str, icon_name: str) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        icon = QLabel()
        icon.setPixmap(line_icon(icon_name, "#7dd3fc").pixmap(21, 21))
        title = QLabel(text)
        title.setObjectName("sectionTitle")
        layout.addWidget(icon)
        layout.addWidget(title)
        layout.addStretch()
        return row

    @staticmethod
    def _password_input(placeholder: str) -> QLineEdit:
        field = QLineEdit()
        field.setEchoMode(QLineEdit.EchoMode.Password)
        field.setPlaceholderText(placeholder)
        field.addAction(line_icon("lock"), QLineEdit.ActionPosition.LeadingPosition)
        return field

    def _request_mode_change(self) -> None:
        try:
            mode = UnlockMode(str(self.mode_input.currentData()))
        except ValueError:
            self._show_error("Неизвестный режим разблокировки.")
            return
        if mode in (UnlockMode.FACE_ONLY, UnlockMode.PASSWORD_AND_FACE) and not (
            self._biometric_enrolled
        ):
            self._show_error(
                "Сначала зарегистрируйте лицо, затем включите выбранный режим."
            )
            return
        self.request = AccessSettingsRequest("unlock_mode", unlock_mode=mode)
        self.accept()

    def _request_face_enrollment(self) -> None:
        self.request = AccessSettingsRequest("face")
        self.accept()

    def _request_language_change(self) -> None:
        language_code = str(self.language_input.currentData() or "")
        supported = {language.code for language in available_languages()}
        if language_code not in supported:
            self._show_error("Неизвестный язык интерфейса.")
            return
        self.request = AccessSettingsRequest(
            "language",
            language_code=language_code,
        )
        self.accept()

    def _request_language_installation(self) -> None:
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            tr("Добавить язык Clever PGP"),
            "",
            tr("Языковой пакет Clever PGP (*.cpg-lang *.json)"),
        )
        if not selected:
            return
        self.request = AccessSettingsRequest(
            "install_language",
            language_pack_path=Path(selected).expanduser().resolve(),
        )
        self.accept()

    def _request_password_change(self) -> None:
        current_password = self.current_password_input.text()
        new_password = self.new_password_input.text()
        if not current_password:
            self._show_error("Введите текущий мастер-пароль.")
            return
        if new_password != self.repeat_password_input.text():
            self._show_error("Новые мастер-пароли не совпадают.")
            return
        self.request = AccessSettingsRequest(
            "password",
            current_password=current_password,
            new_password=new_password,
        )
        self.current_password_input.clear()
        self.new_password_input.clear()
        self.repeat_password_input.clear()
        self.accept()

    def _show_error(self, message: str) -> None:
        self.error_label.setText(tr(message))
        self.error_label.show()


SETTINGS_STYLESHEET = """
QDialog, QWidget {
    background: #111827;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
}
QLabel { background: transparent; }
QLabel#brand { color: #7dd3fc; font-size: 17px; font-weight: 700; }
QLabel#title { color: #f9fafb; font-size: 24px; font-weight: 650; }
QLabel#sectionTitle { color: #f9fafb; font-size: 16px; font-weight: 650; }
QLabel#muted { color: #9ca3af; }
QLabel#success { color: #86efac; }
QLabel#path {
    background: #0d2135;
    border: 1px solid #1e4f70;
    border-radius: 9px;
    color: #cbd5e1;
    padding: 10px;
}
QLabel#error {
    color: #fecaca;
    background: #3f1d2b;
    border: 1px solid #7f1d1d;
    border-radius: 9px;
    padding: 9px 12px;
}
QFrame#settingsCard {
    background: #172033;
    border: 1px solid #2b3a55;
    border-radius: 13px;
}
QLineEdit, QComboBox {
    min-height: 42px;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 9px;
    padding: 0 12px;
    selection-background-color: #0284c7;
}
QLineEdit:focus, QComboBox:focus { border-color: #38bdf8; }
QPushButton {
    min-height: 40px;
    background: #243247;
    border: 1px solid #3b4b65;
    border-radius: 9px;
    padding: 0 15px;
}
QPushButton:hover { background: #2d3d55; border-color: #5b708f; }
QPushButton#primary {
    background: #0284c7;
    border-color: #0ea5e9;
    color: white;
    font-weight: 600;
}
QPushButton#primary:hover { background: #0ea5e9; }
"""
