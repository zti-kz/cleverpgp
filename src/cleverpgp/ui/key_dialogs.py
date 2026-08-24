from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from cleverpgp.core.errors import BioPGPError
from cleverpgp.core.identity import (
    IdentityService,
    PUBLIC_KEY_EXTENSION,
    formatted_fingerprint,
    read_public_identity,
)
from cleverpgp.core.models import Contact, PublicIdentity
from cleverpgp.core.storage import ProfileRepository
from cleverpgp.localization import localize_widget_tree, tr
from cleverpgp.ui.adaptive import scrollable_dialog_layout
from cleverpgp.ui.icons import line_icon


class RecipientSelectionDialog(QDialog):
    def __init__(
        self,
        contacts: tuple[Contact, ...],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.contacts = contacts
        self.selected_contacts: tuple[Contact, ...] = ()
        self.setWindowTitle("Получатели файла — Clever PGP")
        self.setMinimumSize(420, 320)
        self.setStyleSheet(KEY_DIALOG_STYLESHEET)
        self._build_ui()
        localize_widget_tree(self)

    def _build_ui(self) -> None:
        layout = scrollable_dialog_layout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("Кому зашифровать файл")
        title.setObjectName("title")
        explanation = QLabel(
            "Текущий профиль добавляется всегда, поэтому отправитель сможет открыть "
            "свою копию. Отметьте дополнительные открытые ключи получателей."
        )
        explanation.setWordWrap(True)
        explanation.setObjectName("muted")
        layout.addWidget(title)
        layout.addWidget(explanation)

        own = QFrame()
        own.setObjectName("ownKeyCard")
        own_layout = QHBoxLayout(own)
        own_layout.setContentsMargins(14, 12, 14, 12)
        own_icon = QLabel()
        own_icon.setPixmap(line_icon("shield", "#67e8f9").pixmap(24, 24))
        own_label = QLabel("✓ Текущий профиль — обязательный получатель")
        own_label.setObjectName("success")
        own_layout.addWidget(own_icon)
        own_layout.addWidget(own_label, 1)
        layout.addWidget(own)

        self.contact_list = QListWidget()
        self.contact_list.setObjectName("contactList")
        self.contact_list.setSelectionMode(
            QAbstractItemView.SelectionMode.NoSelection
        )
        for contact in self.contacts:
            item = QListWidgetItem(
                f"{contact.display_name}\n{formatted_fingerprint(contact.fingerprint)}"
            )
            item.setData(Qt.ItemDataRole.UserRole, contact.contact_id)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            self.contact_list.addItem(item)
        layout.addWidget(self.contact_list, 1)

        continue_button = QPushButton("Продолжить шифрование")
        continue_button.setObjectName("primary")
        continue_button.setIcon(line_icon("file_lock"))
        continue_button.clicked.connect(self._accept_selection)
        button_row = QHBoxLayout()
        button_row.addStretch()
        button_row.addWidget(continue_button)
        layout.addLayout(button_row)

    def _accept_selection(self) -> None:
        selected_ids = {
            str(item.data(Qt.ItemDataRole.UserRole))
            for index in range(self.contact_list.count())
            if (item := self.contact_list.item(index)).checkState()
            == Qt.CheckState.Checked
        }
        self.selected_contacts = tuple(
            contact for contact in self.contacts if contact.contact_id in selected_ids
        )
        self.accept()


class PublicKeyImportDialog(QDialog):
    def __init__(
        self,
        repository: ProfileRepository,
        source_path: Path,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.repository = repository
        self.identity_service = IdentityService(repository)
        self.source_path = Path(source_path).expanduser().resolve()
        self.public_identity: PublicIdentity | None = None
        self.preview_error = ""
        try:
            self.public_identity = read_public_identity(self.source_path)
        except (BioPGPError, OSError) as error:
            self.preview_error = str(error)
        self.setWindowTitle("Импорт открытого ключа — Clever PGP")
        self.setMinimumSize(420, 320)
        self.setStyleSheet(KEY_DIALOG_STYLESHEET)
        self._build_ui()
        localize_widget_tree(self)

    def _build_ui(self) -> None:
        layout = scrollable_dialog_layout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title_row = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(line_icon("contact_add", "#67e8f9").pixmap(30, 30))
        title = QLabel("Импорт открытого ключа")
        title.setObjectName("title")
        title_row.addWidget(icon)
        title_row.addWidget(title, 1)
        layout.addLayout(title_row)

        explanation = QLabel(
            "Проверьте имя и полный отпечаток ключа по независимому каналу. "
            "Импорт подтверждает только выбранный вами контакт."
        )
        explanation.setWordWrap(True)
        explanation.setObjectName("muted")
        layout.addWidget(explanation)

        source = QLabel(str(self.source_path))
        source.setObjectName("fingerprint")
        source.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        source.setWordWrap(True)
        layout.addWidget(source)

        card = QFrame()
        card.setObjectName("ownKeyCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 14, 16, 14)
        if self.public_identity is not None:
            name = QLabel(self.public_identity.display_name)
            name.setObjectName("keyName")
            fingerprint_title = QLabel("Полный отпечаток открытого ключа")
            fingerprint_title.setObjectName("sectionTitle")
            fingerprint = QLabel(
                formatted_fingerprint(self.public_identity.fingerprint)
            )
            fingerprint.setObjectName("fingerprint")
            fingerprint.setWordWrap(True)
            fingerprint.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            card_layout.addWidget(name)
            card_layout.addWidget(fingerprint_title)
            card_layout.addWidget(fingerprint)
        else:
            error = QLabel(self.preview_error or "Открытый ключ невозможно прочитать.")
            error.setObjectName("error")
            error.setWordWrap(True)
            card_layout.addWidget(error)
        layout.addWidget(card, 1)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.hide()
        layout.addWidget(self.status)

        button_row = QHBoxLayout()
        button_row.addStretch()
        self.import_button = QPushButton("Добавить в контакты")
        self.import_button.setObjectName("primary")
        self.import_button.setIcon(line_icon("contact_add"))
        self.import_button.setEnabled(self.public_identity is not None)
        self.import_button.clicked.connect(self._import_key)
        button_row.addWidget(self.import_button)
        layout.addLayout(button_row)

    def _import_key(self) -> None:
        if self.public_identity is None:
            return
        try:
            contact = self.identity_service.add_contact(self.public_identity)
        except (BioPGPError, OSError) as error:
            self._show_status(tr(str(error)), error=True)
            return
        self._show_status(
            tr(
                "Открытый ключ {name} добавлен в контакты.",
                name=contact.display_name,
            ),
            error=False,
        )
        self.import_button.setText(tr("Импортировано"))
        self.import_button.setEnabled(False)

    def _show_status(self, message: str, *, error: bool) -> None:
        self.status.setObjectName("error" if error else "success")
        self.status.setText(message)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.show()


class ContactsDialog(QDialog):
    def __init__(
        self,
        repository: ProfileRepository,
        master_key: bytes,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.repository = repository
        self.identity_service = IdentityService(repository)
        self._master_key: bytearray | None = bytearray(master_key)
        self.setWindowTitle("Открытые ключи и контакты — Clever PGP")
        self.setMinimumSize(420, 320)
        self.setStyleSheet(KEY_DIALOG_STYLESHEET)
        self._build_ui()
        self._reload_contacts()
        localize_widget_tree(self)

    def _build_ui(self) -> None:
        layout = scrollable_dialog_layout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        title = QLabel("Открытые ключи и контакты")
        title.setObjectName("title")
        explanation = QLabel(
            "Открытым ключом можно безопасно обмениваться. Сверяйте его полный "
            "отпечаток по независимому каналу перед первым использованием."
        )
        explanation.setObjectName("muted")
        explanation.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(explanation)

        own_identity = self.identity_service.public_identity(self._key_copy())
        own_card = QFrame()
        own_card.setObjectName("ownKeyCard")
        own_layout = QVBoxLayout(own_card)
        own_layout.setContentsMargins(16, 14, 16, 14)
        own_title = QLabel("Мой открытый ключ")
        own_title.setObjectName("sectionTitle")
        own_name = QLabel(own_identity.display_name)
        own_name.setObjectName("keyName")
        own_fingerprint = QLabel(formatted_fingerprint(own_identity.fingerprint))
        own_fingerprint.setObjectName("fingerprint")
        own_fingerprint.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        own_fingerprint.setWordWrap(True)
        export_button = QPushButton("Экспортировать мой открытый ключ")
        export_button.setIcon(line_icon("key"))
        export_button.clicked.connect(self._export_key)
        own_layout.addWidget(own_title)
        own_layout.addWidget(own_name)
        own_layout.addWidget(own_fingerprint)
        own_layout.addWidget(export_button)
        layout.addWidget(own_card)

        contacts_header = QHBoxLayout()
        contacts_title = QLabel("Сохранённые контакты")
        contacts_title.setObjectName("sectionTitle")
        import_button = QPushButton("Импортировать открытый ключ")
        import_button.setIcon(line_icon("contact_add"))
        import_button.clicked.connect(self._import_key)
        contacts_header.addWidget(contacts_title)
        contacts_header.addStretch()
        contacts_header.addWidget(import_button)
        layout.addLayout(contacts_header)

        self.contact_list = QListWidget()
        self.contact_list.setObjectName("contactList")
        self.contact_list.currentItemChanged.connect(self._selection_changed)
        layout.addWidget(self.contact_list, 1)

        bottom = QHBoxLayout()
        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.hide()
        self.delete_button = QPushButton("Удалить выбранный контакт")
        self.delete_button.setIcon(line_icon("trash"))
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self._delete_contact)
        bottom.addWidget(self.status, 1)
        bottom.addWidget(self.delete_button)
        layout.addLayout(bottom)

    def _reload_contacts(self) -> None:
        self.contact_list.clear()
        for contact in self.repository.list_contacts():
            item = QListWidgetItem(
                f"{contact.display_name}\n{formatted_fingerprint(contact.fingerprint)}"
            )
            item.setData(Qt.ItemDataRole.UserRole, contact.contact_id)
            self.contact_list.addItem(item)
        if self.contact_list.count() == 0:
            item = QListWidgetItem(tr("Контакты ещё не добавлены"))
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.contact_list.addItem(item)
        self.delete_button.setEnabled(False)

    def _export_key(self) -> None:
        profile = self.repository.get_profile()
        default_name = (
            f"{profile.display_name}{PUBLIC_KEY_EXTENSION}"
            if profile is not None
            else f"cleverpgp{PUBLIC_KEY_EXTENSION}"
        )
        selected, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить открытый ключ"),
            str(Path.home() / default_name),
            tr("Открытый ключ Clever PGP (*.cpgk)"),
        )
        if not selected:
            return
        try:
            result = self.identity_service.export_public_identity(
                Path(selected),
                self._key_copy(),
                overwrite=True,
            )
            self._show_status(
                tr("Открытый ключ сохранён: {path}", path=result),
                error=False,
            )
        except (BioPGPError, OSError) as error:
            self._show_status(tr(str(error)), error=True)

    def _import_key(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self,
            tr("Выберите открытый ключ"),
            filter=tr("Открытый ключ Clever PGP (*.cpgk);;Все файлы (*)"),
        )
        if not selected:
            return
        try:
            contact = self.identity_service.import_contact(Path(selected))
            self._reload_contacts()
            self._show_status(
                tr(
                    "Контакт {name} добавлен. Сверьте отпечаток перед использованием.",
                    name=contact.display_name,
                ),
                error=False,
            )
        except (BioPGPError, OSError) as error:
            self._show_status(tr(str(error)), error=True)

    def _delete_contact(self) -> None:
        item = self.contact_list.currentItem()
        if item is None:
            return
        contact_id = item.data(Qt.ItemDataRole.UserRole)
        if not contact_id:
            return
        answer = QMessageBox.question(
            self,
            tr("Удалить контакт"),
            tr(
                "Удалить выбранный открытый ключ из контактов? "
                "Зашифрованные ранее файлы не изменятся."
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer is not QMessageBox.StandardButton.Yes:
            return
        if self.repository.delete_contact(str(contact_id)):
            self._reload_contacts()
            self._show_status(tr("Контакт удалён."), error=False)

    def _selection_changed(self, current: QListWidgetItem | None, _previous) -> None:
        self.delete_button.setEnabled(
            current is not None
            and bool(current.data(Qt.ItemDataRole.UserRole))
        )

    def _show_status(self, message: str, *, error: bool) -> None:
        self.status.setObjectName("error" if error else "success")
        self.status.setText(message)
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.show()

    def _key_copy(self) -> bytes:
        if self._master_key is None:
            raise RuntimeError("Contacts dialog is already closed.")
        return bytes(self._master_key)

    def _wipe_key(self) -> None:
        if self._master_key is not None:
            for index in range(len(self._master_key)):
                self._master_key[index] = 0
            self._master_key = None

    def done(self, result: int) -> None:
        self._wipe_key()
        super().done(result)

    def closeEvent(self, event: QCloseEvent) -> None:
        self._wipe_key()
        super().closeEvent(event)


KEY_DIALOG_STYLESHEET = """
QDialog {
    background: #111827;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
}
QLabel { background: transparent; }
QLabel#title { color: #f8fafc; font-size: 22px; font-weight: 700; }
QLabel#sectionTitle { color: #e0f2fe; font-size: 15px; font-weight: 700; }
QLabel#keyName { color: #f8fafc; font-size: 17px; font-weight: 650; }
QLabel#muted { color: #94a3b8; }
QLabel#fingerprint {
    color: #bae6fd;
    font-family: "Cascadia Mono", "Consolas";
    font-size: 13px;
}
QLabel#success { color: #99f6e4; }
QLabel#error { color: #fca5a5; }
QFrame#ownKeyCard {
    background: #172236;
    border: 1px solid #31506f;
    border-radius: 12px;
}
QListWidget#contactList {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 10px;
    color: #e2e8f0;
    padding: 6px;
    outline: none;
}
QListWidget#contactList::item {
    border-radius: 8px;
    padding: 10px;
    margin: 2px;
}
QListWidget#contactList::item:selected { background: #1e3a5f; }
QPushButton {
    background: #263449;
    border: 1px solid #475569;
    border-radius: 8px;
    color: #f9fafb;
    min-height: 40px;
    padding: 0 16px;
    font-weight: 600;
}
QPushButton:hover { background: #334155; }
QPushButton:disabled { color: #64748b; background: #1e293b; }
QPushButton#primary { background: #0284c7; border-color: #0ea5e9; }
QPushButton#primary:hover { background: #0369a1; }
"""


__all__ = [
    "ContactsDialog",
    "PublicKeyImportDialog",
    "RecipientSelectionDialog",
]
