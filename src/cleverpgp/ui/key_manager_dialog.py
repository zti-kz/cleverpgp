from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from cleverpgp.core.errors import BioPGPError
from cleverpgp.core.identity import IdentityService, formatted_fingerprint
from cleverpgp.core.key_validity import (
    DEFAULT_KEY_VALIDITY_DAYS,
    key_is_expired,
)
from cleverpgp.core.portable_keys import (
    MINIMUM_KEY_PASSWORD_LENGTH,
    PRIVATE_KEY_EXTENSION,
    PortableKeyService,
)
from cleverpgp.core.storage import ProfileRepository
from cleverpgp.localization import localize_widget_tree, tr
from cleverpgp.ui.adaptive import scrollable_dialog_layout
from cleverpgp.ui.icons import line_icon
from cleverpgp.ui.password_generator import add_password_generator_action


class KeyPasswordDialog(QDialog):
    def __init__(
        self,
        title: str,
        *,
        create: bool,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.create = create
        self.password = ""
        self.display_name = ""
        self.validity_days: int | None = DEFAULT_KEY_VALIDITY_DAYS
        self.setWindowTitle(title)
        self.setMinimumWidth(500)
        self.setStyleSheet(KEY_MANAGER_STYLESHEET)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 24)
        layout.setSpacing(12)
        heading = QLabel(title)
        heading.setObjectName("title")
        layout.addWidget(heading)
        form = QFormLayout()
        form.setSpacing(10)
        self.name_input: QLineEdit | None = None
        if create:
            self.name_input = QLineEdit()
            self.name_input.setPlaceholderText("Например: Almas Oskenbay")
            form.addRow("Владелец ключа", self.name_input)
            self.validity_input = QComboBox()
            self.validity_input.addItem("1 год", 365)
            self.validity_input.addItem("2 года (рекомендуется)", 730)
            self.validity_input.addItem("3 года", 1095)
            self.validity_input.addItem("5 лет", 1825)
            self.validity_input.addItem("Без ограничения срока", None)
            self.validity_input.setCurrentIndex(
                self.validity_input.findData(DEFAULT_KEY_VALIDITY_DAYS)
            )
            form.addRow("Срок действия", self.validity_input)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText(
            f"Не менее {MINIMUM_KEY_PASSWORD_LENGTH} символов"
        )
        form.addRow("Пароль ключа", self.password_input)
        self.repeat_input: QLineEdit | None = None
        if create:
            self.repeat_input = QLineEdit()
            self.repeat_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.repeat_input.setPlaceholderText("Повторите пароль")
            form.addRow("Повтор пароля", self.repeat_input)
            add_password_generator_action(self.password_input, self.repeat_input)
        layout.addLayout(form)
        self.status = QLabel()
        self.status.setObjectName("error")
        self.status.setWordWrap(True)
        self.status.setContentsMargins(12, 9, 12, 9)
        self.status.hide()
        layout.addWidget(self.status)
        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("Отмена")
        cancel.clicked.connect(self.reject)
        accept = QPushButton("Создать ключ" if create else "Продолжить")
        accept.setObjectName("primary")
        accept.clicked.connect(self._accept)
        buttons.addWidget(cancel)
        buttons.addWidget(accept)
        layout.addLayout(buttons)
        self.password_input.returnPressed.connect(self._accept)
        localize_widget_tree(self)

    def _accept(self) -> None:
        password = self.password_input.text()
        name = self.name_input.text().strip() if self.name_input is not None else ""
        if self.create and not name:
            self._error("Укажите имя владельца ключа.")
            return
        if len(password) < MINIMUM_KEY_PASSWORD_LENGTH:
            self._error(
                f"Пароль ключа должен содержать не менее {MINIMUM_KEY_PASSWORD_LENGTH} символов."
            )
            return
        if self.repeat_input is not None and password != self.repeat_input.text():
            self._error("Пароли ключа не совпадают.")
            return
        self.display_name = name
        if self.create:
            selected_validity = self.validity_input.currentData()
            self.validity_days = (
                None if selected_validity is None else int(selected_validity)
            )
        self.password = password
        self.password_input.clear()
        if self.repeat_input is not None:
            self.repeat_input.clear()
        self.accept()

    def _error(self, message: str) -> None:
        self.status.setText(tr(message))
        self.status.show()


class KeyManagerDialog(QDialog):
    def __init__(
        self,
        repository: ProfileRepository,
        parent=None,
        *,
        import_private_path: Path | None = None,
    ) -> None:
        super().__init__(parent)
        self.repository = repository
        self.service = PortableKeyService(repository)
        self.import_private_path = import_private_path
        self.setWindowTitle("Цифровые ключи — Clever PGP")
        self.setMinimumSize(760, 560)
        self.resize(920, 680)
        self.setStyleSheet(KEY_MANAGER_STYLESHEET)
        self._build_ui()
        self._reload()
        localize_widget_tree(self)
        if self.import_private_path is not None:
            from PySide6.QtCore import QTimer

            QTimer.singleShot(
                0, lambda: self._import_private(self.import_private_path)
            )

    def _build_ui(self) -> None:
        layout = scrollable_dialog_layout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)
        title = QLabel("Цифровые ключи")
        title.setObjectName("title")
        description = QLabel(
            "Закрытая часть каждого ключа защищена собственным паролем. "
            "Открытые ключи предназначены для обмена и шифрования файлов получателям."
        )
        description.setObjectName("muted")
        description.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(description)
        tabs = QTabWidget()
        tabs.addTab(self._keys_tab(), "Мои ключи")
        tabs.addTab(self._contacts_tab(), "Получатели")
        layout.addWidget(tabs, 1)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(48)
        self.status.setContentsMargins(14, 10, 14, 10)
        self.status.hide()
        layout.addWidget(self.status)

    def _keys_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 16, 14, 14)
        layout.setSpacing(10)
        self.key_list = QListWidget()
        self.key_list.setWordWrap(True)
        self.key_list.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.key_list.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        self.key_list.customContextMenuRequested.connect(
            self._show_key_context_menu
        )
        layout.addWidget(self.key_list, 1)
        hint = QLabel(
            "Щёлкните ключ правой кнопкой мыши, чтобы экспортировать или удалить его."
        )
        hint.setObjectName("muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        row = QHBoxLayout()
        create = QPushButton("Создать ключ")
        create.setIcon(line_icon("key"))
        create.clicked.connect(self._create_key)
        import_private = QPushButton("Импорт закрытого ключа")
        import_private.setIcon(line_icon("file_open"))
        import_private.clicked.connect(lambda: self._import_private())
        row.addWidget(create)
        row.addWidget(import_private)
        row.addStretch()
        layout.addLayout(row)
        return page

    def _contacts_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 16, 14, 14)
        layout.setSpacing(10)
        self.contact_list = QListWidget()
        self.contact_list.setWordWrap(True)
        self.contact_list.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.contact_list.currentItemChanged.connect(
            lambda current, _previous: self.delete_contact_button.setEnabled(
                current is not None
                and bool(current.data(Qt.ItemDataRole.UserRole))
            )
        )
        layout.addWidget(self.contact_list, 1)
        row = QHBoxLayout()
        import_public = QPushButton("Импорт открытого ключа получателя")
        import_public.setIcon(line_icon("contact_add"))
        import_public.clicked.connect(self._import_public)
        self.delete_contact_button = QPushButton("Удалить получателя")
        self.delete_contact_button.setIcon(line_icon("trash"))
        self.delete_contact_button.clicked.connect(self._delete_contact)
        row.addWidget(import_public)
        row.addStretch()
        row.addWidget(self.delete_contact_button)
        layout.addLayout(row)
        return page

    def _reload(self) -> None:
        self.key_list.clear()
        for key in self.repository.list_user_keys():
            validity = self._validity_text(key.expires_at)
            item = QListWidgetItem(
                f"{key.display_name}\n{formatted_fingerprint(key.fingerprint)}\n{validity}"
            )
            item.setData(Qt.ItemDataRole.UserRole, key.key_id)
            self.key_list.addItem(item)
        if self.key_list.count() == 0:
            item = QListWidgetItem("Цифровые ключи ещё не созданы")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.key_list.addItem(item)
        self.contact_list.clear()
        for contact in self.repository.list_contacts():
            validity = self._validity_text(contact.expires_at)
            item = QListWidgetItem(
                f"{contact.display_name}\n"
                f"{formatted_fingerprint(contact.fingerprint)}\n{validity}"
            )
            item.setData(Qt.ItemDataRole.UserRole, contact.contact_id)
            self.contact_list.addItem(item)
        if self.contact_list.count() == 0:
            item = QListWidgetItem("Открытые ключи получателей ещё не импортированы")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.contact_list.addItem(item)
        self.delete_contact_button.setEnabled(False)

    def _selected_key_id(self) -> str | None:
        item = self.key_list.currentItem()
        return None if item is None else item.data(Qt.ItemDataRole.UserRole)

    def _show_key_context_menu(self, position) -> None:
        item = self.key_list.itemAt(position)
        if item is None or not item.data(Qt.ItemDataRole.UserRole):
            return
        self.key_list.setCurrentItem(item)
        menu = QMenu(self)
        export_public = menu.addAction(tr("Экспорт открытого ключа"))
        export_public.setIcon(line_icon("key"))
        export_private = menu.addAction(tr("Экспорт закрытого ключа"))
        export_private.setIcon(line_icon("file_lock"))
        menu.addSeparator()
        delete_key = menu.addAction(tr("Удалить цифровой ключ"))
        delete_key.setIcon(line_icon("trash"))
        selected = menu.exec(self.key_list.viewport().mapToGlobal(position))
        if selected is export_public:
            self._export_public()
        elif selected is export_private:
            self._export_private()
        elif selected is delete_key:
            self._delete_key()

    def _create_key(self) -> None:
        dialog = KeyPasswordDialog("Создание цифрового ключа", create=True, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            key = self.service.create_key(
                dialog.display_name,
                dialog.password,
                validity_days=dialog.validity_days,
            )
        except (BioPGPError, OSError) as error:
            self._show_status(str(error), error=True)
            return
        finally:
            dialog.password = ""
        self._reload()
        self._show_status(
            f"Цифровой ключ создан: {formatted_fingerprint(key.fingerprint)}",
            error=False,
        )

    def _password_for_key(self, title: str) -> str | None:
        dialog = KeyPasswordDialog(title, create=False, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        password = dialog.password
        dialog.password = ""
        return password

    def _export_private(self) -> None:
        key_id = self._selected_key_id()
        if not key_id:
            return
        password = self._password_for_key("Экспорт закрытого ключа")
        if password is None:
            return
        key = self.repository.get_user_key(key_id)
        default = f"{key.display_name if key else 'cleverpgp'}{PRIVATE_KEY_EXTENSION}"
        selected, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить защищённый закрытый ключ",
            str(Path.home() / default),
            "Закрытый ключ Clever PGP (*.cpgx)",
        )
        if not selected:
            return
        try:
            result = self.service.export_private_key(
                key_id, password, Path(selected), overwrite=True
            )
            self._show_status(f"Закрытый ключ сохранён: {result}", error=False)
        except (BioPGPError, OSError) as error:
            self._show_status(str(error), error=True)

    def _export_public(self) -> None:
        key_id = self._selected_key_id()
        if not key_id:
            return
        password = self._password_for_key("Экспорт открытого ключа")
        if password is None:
            return
        key = self.repository.get_user_key(key_id)
        default = f"{key.display_name if key else 'cleverpgp'}.cpgk"
        selected, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить открытый ключ",
            str(Path.home() / default),
            "Открытый ключ Clever PGP (*.cpgk)",
        )
        if not selected:
            return
        try:
            result = self.service.export_public_key(
                key_id, password, Path(selected), overwrite=True
            )
            self._show_status(f"Открытый ключ сохранён: {result}", error=False)
        except (BioPGPError, OSError) as error:
            self._show_status(str(error), error=True)

    def _import_private(self, source: Path | None = None) -> None:
        if source is None:
            selected, _ = QFileDialog.getOpenFileName(
                self,
                "Выберите закрытый ключ",
                filter="Закрытый ключ Clever PGP (*.cpgx)",
            )
            if not selected:
                return
            source = Path(selected)
        password = self._password_for_key("Импорт закрытого ключа")
        if password is None:
            return
        try:
            key = self.service.import_private_key(source, password)
            self._reload()
            self._show_status(
                f"Закрытый ключ импортирован: {key.display_name}", error=False
            )
        except (BioPGPError, OSError) as error:
            self._show_status(str(error), error=True)

    def _import_public(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите открытый ключ получателя",
            filter="Открытый ключ Clever PGP (*.cpgk)",
        )
        if not selected:
            return
        try:
            contact = IdentityService(self.repository).import_contact(Path(selected))
            self._reload()
            self._show_status(
                f"Получатель добавлен: {contact.display_name}", error=False
            )
        except (BioPGPError, OSError) as error:
            self._show_status(str(error), error=True)

    def _delete_key(self) -> None:
        key_id = self._selected_key_id()
        if not key_id:
            return
        key = self.repository.get_user_key(key_id)
        if key is None:
            self._show_status("Цифровой ключ не найден.", error=True)
            return
        confirmation = QMessageBox.question(
            self,
            tr("Удалить цифровой ключ"),
            tr(
                "Удалить ключ «{name}»? Без его закрытой части файлы, "
                "зашифрованные только для этого ключа, открыть будет невозможно.",
                name=key.display_name,
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirmation != QMessageBox.StandardButton.Yes:
            return
        password = self._password_for_key("Удаление цифрового ключа")
        if password is None:
            return
        try:
            deleted = self.service.delete_key(key_id, password)
        except (BioPGPError, OSError) as error:
            self._show_status(str(error), error=True)
            return
        finally:
            password = ""
        if not deleted:
            self._show_status("Цифровой ключ не найден.", error=True)
            return
        self._reload()
        self._show_status("Цифровой ключ удалён.", error=False)

    def _delete_contact(self) -> None:
        item = self.contact_list.currentItem()
        contact_id = None if item is None else item.data(Qt.ItemDataRole.UserRole)
        if contact_id and self.repository.delete_contact(str(contact_id)):
            self._reload()
            self._show_status("Открытый ключ получателя удалён.", error=False)

    def _show_status(self, message: str, *, error: bool) -> None:
        self.status.setObjectName("error" if error else "success")
        self.status.setText(tr(message))
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.show()

    @staticmethod
    def _validity_text(expires_at: str | None) -> str:
        if expires_at is None:
            return tr("Срок действия: без ограничения")
        try:
            date_text = datetime.fromisoformat(expires_at).date().isoformat()
        except ValueError:
            return tr("Срок действия: неизвестен")
        if key_is_expired(expires_at):
            return tr("Срок действия истёк: {date}", date=date_text)
        return tr("Действует до: {date}", date=date_text)


KEY_MANAGER_STYLESHEET = """
QDialog, QWidget { background: #111827; color: #e5e7eb; font-family: "Segoe UI"; font-size: 14px; }
QLabel { background: transparent; }
QLabel#title { color: #f8fafc; font-size: 22px; font-weight: 700; }
QLabel#muted { color: #94a3b8; }
QLabel#success { color: #99f6e4; background: #052e2b; border: 1px solid #0f766e; border-radius: 9px; padding: 10px 14px; }
QLabel#error { color: #fca5a5; background: #3f151b; border: 1px solid #991b1b; border-radius: 9px; padding: 10px 14px; }
QLineEdit, QListWidget { background: #0f172a; border: 1px solid #475569; border-radius: 8px; color: #f9fafb; padding: 8px 12px; }
QLineEdit { min-height: 38px; }
QListWidget::item { padding: 10px; margin: 2px; border-radius: 7px; }
QListWidget::item:selected { background: #1e3a5f; }
QTabWidget::pane { border: 1px solid #334155; border-radius: 10px; }
QTabBar::tab { background: #1e293b; color: #cbd5e1; padding: 10px 18px; }
QTabBar::tab:selected { background: #075985; color: #f8fafc; }
QPushButton { background: #263449; border: 1px solid #475569; border-radius: 8px; color: #f9fafb; min-height: 40px; padding: 0 14px; font-weight: 600; }
QPushButton:hover { background: #334155; }
QPushButton:disabled { color: #64748b; background: #1e293b; }
QPushButton#primary { background: #0284c7; border-color: #0ea5e9; }
"""


__all__ = ["KeyManagerDialog", "KeyPasswordDialog"]
