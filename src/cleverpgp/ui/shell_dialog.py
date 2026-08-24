from __future__ import annotations

from pathlib import Path
from typing import Literal

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from cleverpgp.core.file_crypto import FileCryptoService
from cleverpgp.core.identity import formatted_fingerprint
from cleverpgp.core.models import Contact
from cleverpgp.core.profile_service import ProfileService
from cleverpgp.core.storage import ProfileRepository
from cleverpgp.localization import localize_widget_tree, set_language, tr
from cleverpgp.ui.adaptive import scrollable_dialog_layout
from cleverpgp.ui.icons import line_icon
from cleverpgp.ui.key_dialogs import RecipientSelectionDialog

Operation = Literal["encrypt", "decrypt"]


class ShellFileWorker(QObject):
    succeeded = Signal(str)
    failed = Signal(str)
    finished = Signal()
    progress = Signal(int, str)

    def __init__(
        self,
        repository: ProfileRepository,
        operation: Operation,
        source: Path,
        target: Path,
        password: str,
        overwrite: bool,
        recipients: tuple[Contact, ...] = (),
    ) -> None:
        super().__init__()
        self.repository = repository
        stored_language = self.repository.get_setting("language")
        if stored_language:
            set_language(stored_language)
        self.operation = operation
        self.source = source
        self.target = target
        self.password = password
        self.overwrite = overwrite
        self.recipients = recipients

    @Slot()
    def run(self) -> None:
        session = None
        try:
            session = ProfileService(self.repository).unlock_with_password(self.password)
            self.password = ""
            master_key = session.master_key_copy()
            service = FileCryptoService(self.repository)
            try:
                if self.operation == "encrypt":
                    result = service.encrypt_file(
                        self.source,
                        self.target,
                        master_key,
                        recipients=self.recipients,
                        overwrite=self.overwrite,
                        progress=self._report_progress,
                    )
                else:
                    detailed = service.decrypt_file_detailed(
                        self.source,
                        self.target,
                        master_key,
                        overwrite=self.overwrite,
                        progress=self._report_progress,
                    )
                    if detailed.sender_is_self:
                        verification = tr(
                            "Подпись текущего профиля подтверждена."
                        )
                    elif detailed.sender_is_known:
                        verification = tr(
                            "Подпись контакта {name} подтверждена.",
                            name=detailed.sender.display_name,
                        )
                    else:
                        verification = tr(
                            "Подпись математически верна, но отправитель {name} ещё не "
                            "сохранён в контактах. Сверьте полный отпечаток по "
                            "независимому каналу:\n{fingerprint}",
                            name=detailed.sender.display_name,
                            fingerprint=formatted_fingerprint(
                                detailed.sender.fingerprint
                            ),
                        )
                    result = f"{detailed.path}\n{verification}"
            finally:
                del master_key
            self.succeeded.emit(str(result))
        except Exception as error:
            self.failed.emit(str(error))
        finally:
            self.password = ""
            if session is not None:
                session.lock()
            self.finished.emit()

    def _report_progress(self, value: int, message: str) -> None:
        self.progress.emit(max(0, min(100, int(value))), message)


class ShellOperationDialog(QDialog):
    def __init__(
        self,
        repository: ProfileRepository,
        operation: Operation,
        source: Path,
    ) -> None:
        super().__init__()
        self.repository = repository
        self.operation = operation
        self.source = source.expanduser().resolve()
        self.file_crypto = FileCryptoService(repository)
        self.target = self._default_target()
        self.thread: QThread | None = None
        self.worker: ShellFileWorker | None = None
        self.selected_contacts: tuple[Contact, ...] = ()
        self.running = False
        self.operation_succeeded: bool | None = None

        action_name = tr("Шифрование" if operation == "encrypt" else "Расшифрование")
        self.setWindowTitle(f"{action_name} — Clever PGP")
        self.setMinimumSize(560, 440)
        self.resize(760, 560)
        self.setStyleSheet(SHELL_STYLESHEET)
        self._build_ui()
        localize_widget_tree(self)

    def _build_ui(self) -> None:
        layout = scrollable_dialog_layout(self)
        layout.setContentsMargins(28, 26, 28, 26)
        layout.setSpacing(14)

        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        title = QLabel(
            "Зашифровать выбранный файл"
            if self.operation == "encrypt"
            else "Расшифровать файл Clever PGP"
        )
        title.setObjectName("title")
        layout.addWidget(brand)
        layout.addWidget(title)

        source_label = QLabel(tr("Исходный файл:\n{path}", path=self.source))
        source_label.setWordWrap(True)
        source_label.setObjectName("path")
        layout.addWidget(source_label)

        target_row = QHBoxLayout()
        self.target_label = QLabel(str(self.target))
        self.target_label.setWordWrap(True)
        self.target_label.setObjectName("path")
        self.choose_button = QPushButton("Изменить…")
        self.choose_button.setIcon(line_icon("folder"))
        self.choose_button.clicked.connect(self._choose_target)
        target_row.addWidget(self.target_label, 1)
        target_row.addWidget(self.choose_button)
        layout.addWidget(QLabel("Результат:"))
        layout.addLayout(target_row)

        self.recipient_button: QPushButton | None = None
        self.recipient_label: QLabel | None = None
        if self.operation == "encrypt":
            recipient_row = QHBoxLayout()
            self.recipient_label = QLabel()
            self.recipient_label.setObjectName("path")
            self.recipient_label.setWordWrap(True)
            self.recipient_button = QPushButton("Выбрать получателей…")
            self.recipient_button.setIcon(line_icon("contact_add"))
            self.recipient_button.clicked.connect(self._choose_recipients)
            recipient_row.addWidget(self.recipient_label, 1)
            recipient_row.addWidget(self.recipient_button)
            layout.addWidget(QLabel("Получатели:"))
            layout.addLayout(recipient_row)
            self._update_recipient_summary()

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Мастер-пароль Clever PGP")
        self.password_input.returnPressed.connect(self._start)
        layout.addWidget(self.password_input)

        note = QLabel(
            "Оригинальный файл останется без изменений. "
            "Результат создаётся атомарно и не появится при ошибке."
        )
        note.setWordWrap(True)
        note.setObjectName("muted")
        layout.addWidget(note)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(1)
        self.progress.setFormat(tr("1% — Запуск операции"))
        self.progress.hide()
        layout.addWidget(self.progress)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.hide()
        layout.addWidget(self.status)

        buttons = QHBoxLayout()
        self.cancel_button = QPushButton("Отмена")
        self.cancel_button.setIcon(line_icon("close"))
        self.cancel_button.clicked.connect(self.reject)
        self.action_button = QPushButton(
            "Зашифровать" if self.operation == "encrypt" else "Расшифровать"
        )
        self.action_button.setObjectName("primary")
        self.action_button.setIcon(
            line_icon("file_lock" if self.operation == "encrypt" else "file_open")
        )
        self.action_button.clicked.connect(self._start)
        buttons.addStretch()
        buttons.addWidget(self.cancel_button)
        buttons.addWidget(self.action_button)
        layout.addLayout(buttons)
        self.password_input.setFocus()

    def _default_target(self) -> Path:
        if self.operation == "encrypt":
            return self.file_crypto.default_encrypted_path(self.source)
        return self.file_crypto.default_decrypted_path(self.source)

    def _choose_target(self) -> None:
        if self.running:
            return
        if self.operation == "encrypt":
            selected, _ = QFileDialog.getSaveFileName(
                self,
                tr("Сохранить зашифрованный файл"),
                str(self.target),
                "Clever PGP (*.cpgp)",
            )
        else:
            selected, _ = QFileDialog.getSaveFileName(
                self, tr("Сохранить расшифрованный файл"), str(self.target)
            )
        if selected:
            self.target = Path(selected).expanduser().resolve()
            self.target_label.setText(str(self.target))

    def _choose_recipients(self) -> None:
        if self.running:
            return
        contacts = self.repository.list_contacts()
        if not contacts:
            self.status.setObjectName("error")
            self.status.setText(
                tr(
                    "Контакты ещё не добавлены. Импортируйте открытый ключ "
                    "получателя в главном окне Clever PGP."
                )
            )
            self.status.style().unpolish(self.status)
            self.status.style().polish(self.status)
            self.status.show()
            return
        dialog = RecipientSelectionDialog(contacts, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.selected_contacts = dialog.selected_contacts
            self._update_recipient_summary()

    def _update_recipient_summary(self) -> None:
        if self.recipient_label is None:
            return
        if not self.selected_contacts:
            self.recipient_label.setText(tr("Только текущий профиль"))
            return
        names = ", ".join(contact.display_name for contact in self.selected_contacts)
        self.recipient_label.setText(
            tr("Текущий профиль и: {names}", names=names)
        )

    def _start(self) -> None:
        if self.running:
            return
        password = self.password_input.text()
        if not password:
            self.status.setObjectName("error")
            self.status.setText(tr("Введите мастер-пароль."))
            self.status.style().unpolish(self.status)
            self.status.style().polish(self.status)
            self.status.show()
            return
        overwrite = False
        if self.target.exists():
            answer = QMessageBox.question(
                self,
                "Clever PGP",
                tr(
                    "Файл уже существует:\n{path}\n\nЗаменить его?",
                    path=self.target,
                ),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer is not QMessageBox.StandardButton.Yes:
                return
            overwrite = True

        self.running = True
        self.operation_succeeded = None
        self.password_input.clear()
        self.password_input.setEnabled(False)
        self.choose_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.action_button.setEnabled(False)
        if self.recipient_button is not None:
            self.recipient_button.setEnabled(False)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self.show()
        self.progress.show()
        self.progress.setValue(1)
        self.progress.setFormat(tr("1% — Запуск операции"))
        self.status.hide()

        self.thread = QThread(self)
        self.worker = ShellFileWorker(
            self.repository,
            self.operation,
            self.source,
            self.target,
            password,
            overwrite,
            self.selected_contacts,
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

    @Slot(str)
    def _succeeded(self, result: str) -> None:
        self.status.setObjectName("success")
        self.status.setText(tr("Готово:\n{result}", result=result))
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.show()
        self.action_button.setText(tr("Закрыть"))
        self.action_button.clicked.disconnect()
        self.action_button.clicked.connect(self.accept)
        self.operation_succeeded = True

    @Slot(str)
    def _failed(self, message: str) -> None:
        self.status.setObjectName("error")
        self.status.setText(tr(message or "Операция завершилась ошибкой."))
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.status.show()
        self.operation_succeeded = False

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
        self.cancel_button.setEnabled(True)
        if self.recipient_button is not None:
            self.recipient_button.setEnabled(True)
        if self.operation_succeeded:
            self.action_button.setEnabled(True)
        else:
            self.password_input.setEnabled(True)
            self.choose_button.setEnabled(True)
            self.action_button.setEnabled(True)
            self.password_input.setFocus()

    def reject(self) -> None:
        if self.running:
            return
        super().reject()


SHELL_STYLESHEET = """
QDialog {
    background: #111827;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
}
QLabel { background: transparent; }
QLabel#brand { color: #7dd3fc; font-size: 22px; font-weight: 700; }
QLabel#title { color: #f9fafb; font-size: 20px; font-weight: 650; }
QLabel#path {
    background: #182235;
    border: 1px solid #2d3b52;
    border-radius: 8px;
    padding: 10px;
    color: #cbd5e1;
}
QLabel#muted { color: #9ca3af; }
QLabel#success { color: #99f6e4; }
QLabel#error { color: #fca5a5; }
QLineEdit {
    background: #0f172a;
    border: 1px solid #475569;
    border-radius: 8px;
    color: #f9fafb;
    min-height: 40px;
    padding: 0 12px;
}
QLineEdit:focus { border-color: #38bdf8; }
QPushButton {
    background: #263449;
    border: 1px solid #475569;
    border-radius: 8px;
    color: #f9fafb;
    min-height: 40px;
    padding: 0 18px;
    font-weight: 600;
}
QPushButton#primary { background: #0284c7; border-color: #0ea5e9; }
QPushButton:hover { background: #334155; }
QPushButton#primary:hover { background: #0369a1; }
QProgressBar {
    border: 1px solid #475569;
    border-radius: 8px;
    background: #1e293b;
    color: #f8fafc;
    min-height: 28px;
    max-height: 28px;
    text-align: center;
    font-weight: 650;
}
QProgressBar::chunk { background: #0284c7; border-radius: 7px; }
"""
