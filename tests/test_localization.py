from __future__ import annotations

import os
import re

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nacl import pwhash  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QLabel,
    QComboBox,
    QLineEdit,
    QPushButton,
    QWidget,
)

from biopgp.core.file_crypto import FileCryptoService  # noqa: E402
from biopgp.core.profile_service import KdfParameters, ProfileService  # noqa: E402
from biopgp.core.storage import ProfileRepository  # noqa: E402
from biopgp.localization import available_languages, set_language, tr  # noqa: E402
from biopgp.ui.about_dialog import AboutDialog  # noqa: E402
from biopgp.ui.container_dialog import ContainerCreationDialog  # noqa: E402
from biopgp.ui.main_window import MainWindow  # noqa: E402
from biopgp.ui.settings_dialog import AccessSettingsDialog  # noqa: E402
from biopgp.ui.shell_dialog import ShellOperationDialog  # noqa: E402


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


def test_system_disk_formatting_messages_are_localized() -> None:
    set_language("en")
    assert (
        tr("Форматирование системного диска завершено")
        == "System disk formatting completed"
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


def test_header_language_selector_applies_and_saves_language(tmp_path) -> None:
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
    window = MainWindow(repository, profiles, FileCryptoService())
    selector = window.centralWidget().findChild(QComboBox, "languageSelector")

    assert selector is not None
    selector.setCurrentIndex(selector.findData("en"))
    application.processEvents()

    assert repository.get_setting("language") == "en"
    assert any(
        button.text() == "Create protected profile"
        for button in window.centralWidget().findChildren(QPushButton)
    )
    about_button = next(
        button
        for button in window.centralWidget().findChildren(QPushButton)
        if button.toolTip() == "About"
    )
    assert about_button.text() == ""
    window.close()
    application.processEvents()


def _visible_strings(widget: QWidget) -> list[str]:
    strings = [widget.windowTitle()]
    strings.extend(label.text() for label in widget.findChildren(QLabel))
    strings.extend(button.text() for button in widget.findChildren(QPushButton))
    strings.extend(line.placeholderText() for line in widget.findChildren(QLineEdit))
    strings.extend(
        combo.itemText(index)
        for combo in widget.findChildren(QComboBox)
        if combo.objectName() != "languageSelector"
        for index in range(combo.count())
    )
    strings.extend(button.toolTip() for button in widget.findChildren(QPushButton))
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
        system_disk=True,
    )
    settings = AccessSettingsDialog(
        window.repository.get_profile().unlock_mode,
        biometric_enrolled=False,
        parent=window,
    )
    source = tmp_path / "report.txt"
    source.write_text("test", encoding="utf-8")
    shell = ShellOperationDialog(repository, "encrypt", source)

    russian_letters = re.compile(r"[А-Яа-яЁё]")
    untranslated = [
        value
        for dialog in (window, about, container, settings, shell)
        for value in _visible_strings(dialog)
        if russian_letters.search(value)
    ]
    assert untranslated == []

    shell.close()
    settings.close()
    container.close()
    about.close()
    window.close()
    application.processEvents()
