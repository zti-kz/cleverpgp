from __future__ import annotations

import os
import re

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nacl import pwhash  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QAbstractButton,
    QApplication,
    QDialog,
    QLabel,
    QComboBox,
    QLineEdit,
    QPushButton,
    QWidget,
)

from cleverpgp.core.file_crypto import FileCryptoService  # noqa: E402
from cleverpgp.core.identity import IdentityService  # noqa: E402
from cleverpgp.core.profile_service import KdfParameters, ProfileService  # noqa: E402
from cleverpgp.core.storage import ProfileRepository  # noqa: E402
from cleverpgp.localization import available_languages, set_language, tr  # noqa: E402
from cleverpgp.ui.about_dialog import AboutDialog  # noqa: E402
from cleverpgp.ui.container_dialog import ContainerCreationDialog  # noqa: E402
from cleverpgp.ui.disk_algorithm_dialog import (  # noqa: E402
    DiskAlgorithmChangeDialog,
)
from cleverpgp.ui.disk_password_dialog import (  # noqa: E402
    DiskPasswordChangeDialog,
)
from cleverpgp.ui.main_window import MainWindow  # noqa: E402
from cleverpgp.ui import main_window as main_window_module  # noqa: E402
from cleverpgp.ui.hidden_volume_dialog import (  # noqa: E402
    HiddenVolumeCreationDialog,
    OpaqueVolumeUnlockDialog,
)
from cleverpgp.ui.key_dialogs import (  # noqa: E402
    ContactsDialog,
    PublicKeyImportDialog,
    RecipientSelectionDialog,
)
from cleverpgp.ui.settings_dialog import (  # noqa: E402
    AccessSettingsDialog,
    AccessSettingsRequest,
)
from cleverpgp.ui.shell_dialog import ShellOperationDialog  # noqa: E402
from cleverpgp.core.disk_crypto import XCHACHA20_POLY1305  # noqa: E402


def _dialog_text() -> str:
    application = QApplication.instance() or QApplication([])
    dialog = AboutDialog()
    text = "\n".join(label.text() for label in dialog.findChildren(QLabel))
    dialog.close()
    application.processEvents()
    return text


def test_three_extensible_language_catalogs_are_available() -> None:
    assert [(item.code, item.native_name) for item in available_languages()] == [
        ("en", "English"),
        ("ru", "Русский"),
        ("kk", "Қазақша"),
    ]


def test_author_and_institute_names_are_localized_exactly() -> None:
    set_language("en")
    assert (
        "© 2026 Almas Oskenbay, Institute of Intellectual Technologies. "
        "All rights reserved."
    ) in _dialog_text()
    assert "Free software: GNU GPL v3 or any later version." in _dialog_text()

    set_language("ru")
    assert (
        "© 2026 Алмас Оскенбаев, Институт интеллектуальных технологий. "
        "Все права защищены."
    ) in _dialog_text()
    assert "GNU GPL v3 или более поздняя версия" in _dialog_text()

    set_language("kk")
    assert (
        "© 2026 Алмас Өскенбай, Зияткерлік технологиялар институты. "
        "Барлық құқықтар қорғалған."
    ) in _dialog_text()
    assert "GNU GPL v3 немесе одан кейінгі нұсқа" in _dialog_text()


def test_language_catalog_translates_primary_action() -> None:
    set_language("en")
    assert tr("Зашифровать файл") == "Encrypt file"
    set_language("kk")
    assert tr("Зашифровать файл") == "Файлды шифрлау"


def test_backend_detection_messages_are_localized() -> None:
    set_language("en")
    assert (
        tr("Проверка типа зашифрованного диска")
        == "Checking encrypted disk type"
    )
    set_language("kk")
    assert (
        tr(
            "Назначение зашифрованного диска не поддерживается "
            "этой версией Clever PGP."
        )
        == "Шифрланған дискінің бұл түрін Clever PGP-дің осы нұсқасы қолдамайды."
    )


def test_virtual_disk_formatting_messages_are_localized() -> None:
    set_language("en")
    assert (
        tr("Форматирование виртуального диска завершено")
        == "Virtual disk formatting completed"
    )
    assert (
        tr("Windows не запустила форматирование диска (код 5).")
        == "Windows did not start disk formatting (error 5)."
    )
    set_language("kk")
    assert (
        tr("Форматирование не получило разрешение администратора Windows.")
        == "Дискіні пішімдеу Windows әкімшісінің рұқсатын алмады."
    )


def test_virtual_disk_extension_messages_are_localized() -> None:
    set_language("en")
    assert (
        tr("Расширение не получило разрешение администратора Windows.")
        == "Disk extension did not receive Windows administrator permission."
    )
    assert (
        tr("Windows не запустила защищённую операцию (код 5).")
        == "Windows did not start the protected operation (error 5)."
    )
    set_language("kk")
    assert (
        tr("Windows не завершила расширение раздела вовремя.")
        == "Windows бөлімді кеңейтуді уақытында аяқтамады."
    )


def test_new_disk_backend_choice_is_localized() -> None:
    set_language("en")
    assert (
        tr("Виртуальный диск Windows — быстрый (рекомендуется)")
        == "Windows virtual disk — fast (recommended)"
    )
    set_language("kk")
    assert (
        tr("Универсальный диск Clever PGP")
        == "Әмбебап Clever PGP дискі"
    )


def test_language_is_only_saved_from_settings_and_applies_after_restart(
    monkeypatch,
    tmp_path,
) -> None:
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    repository.set_setting("language", "ru")
    profiles = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profiles.create_profile("Test", password)
    window = MainWindow(repository, profiles, FileCryptoService())
    window.session = profiles.unlock_with_password(password)
    window._show_dashboard()

    assert window.centralWidget().findChild(QComboBox, "languageSelector") is None

    class LanguageSettingsDialog:
        request = AccessSettingsRequest("language", language_code="en")

        def __init__(self, *_args: object, **kwargs: object) -> None:
            assert kwargs["selected_language"] == "ru"

        @staticmethod
        def exec() -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

    monkeypatch.setattr(
        main_window_module,
        "AccessSettingsDialog",
        LanguageSettingsDialog,
    )
    restart_calls: list[bool] = []
    window._restart_application = lambda: restart_calls.append(True)  # type: ignore[method-assign]
    window._show_access_settings()
    application.processEvents()

    assert repository.get_setting("language") == "en"
    # The live page is intentionally not rebuilt during the current process.
    assert any(
        button.text() == "Зашифровать файл"
        for button in window.centralWidget().findChildren(QPushButton)
    )
    assert "перезапускается" in window.dashboard_status.text()
    assert restart_calls == [True]
    window.close()
    application.processEvents()


def _visible_strings(widget: QWidget) -> list[str]:
    strings = [widget.windowTitle()]
    strings.extend(label.text() for label in widget.findChildren(QLabel))
    strings.extend(button.text() for button in widget.findChildren(QAbstractButton))
    strings.extend(line.placeholderText() for line in widget.findChildren(QLineEdit))
    strings.extend(
        combo.itemText(index)
        for combo in widget.findChildren(QComboBox)
        if combo.objectName() != "languageSelector"
        for index in range(combo.count())
    )
    strings.extend(
        button.toolTip() for button in widget.findChildren(QAbstractButton)
    )
    return [value for value in strings if value]


def test_english_windows_have_no_untranslated_russian_interface_text(tmp_path) -> None:
    application = QApplication.instance() or QApplication([])
    set_language("en")
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    repository.set_setting("language", "en")
    profiles = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profiles.create_profile("Test", password)
    window = MainWindow(repository, profiles, FileCryptoService())
    window.session = profiles.unlock_with_password(password)
    window._show_dashboard()
    about = AboutDialog(window)
    container = ContainerCreationDialog(
        window,
        minimum_capacity=32 * 1024 * 1024,
        allow_backend_choice=True,
        system_backend_available=True,
        winfsp_backend_available=True,
        hidden_volume_available=True,
    )
    hidden = HiddenVolumeCreationDialog(
        96 * 1024 * 1024,
        "Outer",
        window,
    )
    opaque_unlock = OpaqueVolumeUnlockDialog(
        tmp_path / "hidden.cpgv",
        window,
    )
    disk_password = DiskPasswordChangeDialog(
        "Z:",
        object(),  # type: ignore[arg-type]
        window,
    )
    settings = AccessSettingsDialog(
        window.repository.get_profile().unlock_mode,
        biometric_enrolled=False,
        parent=window,
    )
    source = tmp_path / "report.txt"
    source.write_text("test", encoding="utf-8")
    shell = ShellOperationDialog(repository, "encrypt", source)
    contacts = ContactsDialog(
        repository,
        window.session.master_key_copy(),
        window,
    )
    recipients = RecipientSelectionDialog((), window)
    public_key_path = tmp_path / "test.cpgk"
    IdentityService(repository).export_public_identity(
        public_key_path,
        window.session.master_key_copy(),
    )
    public_key_import = PublicKeyImportDialog(
        repository,
        public_key_path,
        window,
    )
    algorithm_container = tmp_path / "algorithm.cpgv"
    algorithm_container.write_bytes(b"ciphertext")
    algorithm_dialog = DiskAlgorithmChangeDialog(
        algorithm_container,
        XCHACHA20_POLY1305,
        window,
    )

    russian_letters = re.compile(r"[А-Яа-яЁё]")
    untranslated = [
        value
        for dialog in (
            window,
            about,
            container,
            hidden,
            opaque_unlock,
            disk_password,
            settings,
            shell,
            contacts,
            recipients,
            public_key_import,
            algorithm_dialog,
        )
        for value in _visible_strings(dialog)
        if russian_letters.search(value)
    ]
    assert untranslated == []

    algorithm_dialog.close()
    public_key_import.close()
    recipients.close()
    contacts.close()
    shell.close()
    settings.close()
    disk_password.close()
    opaque_unlock.close()
    hidden.close()
    container.close()
    about.close()
    window.close()
    application.processEvents()


def test_hidden_disk_primary_actions_are_available_in_kazakh() -> None:
    set_language("kk")

    assert tr("Создать скрытый диск") == "Жасырын диск жасау"
    assert tr("Разблокировать диск") == "Дискіні бұғаттан шығару"
    assert tr("Изменить пароль диска") == "Диск құпиясөзін өзгерту"
