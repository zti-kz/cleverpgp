import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QPushButton  # noqa: E402

from biopgp.ui.about_dialog import AboutDialog  # noqa: E402


def test_about_dialog_contains_product_and_developer_information() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = AboutDialog()
    text = "\n".join(label.text() for label in dialog.findChildren(QLabel))

    assert "Clever PGP" in text
    assert "Версия 0.9.0" in text
    assert ".cpgp" in text
    assert ".cpgv" in text
    assert "Алмас Оскенбаев" in text
    assert (
        "© 2026 Алмас Оскенбаев, Институт интеллектуальных технологий. "
        "Все права защищены."
    ) in text
    assert "GNU GPL v3 или более поздняя версия" in text
    assert "WinFsp - Windows File System Proxy" in text
    assert "WinSpd - Windows Storage Proxy Driver" in text
    assert "Bill Zissimopoulos" in text
    assert "Автор и разработчик:" not in text
    assert "Криптографическая защита файлов и дисков" in text
    assert "материал" not in text.lower()
    assert "Научная основа проекта" not in text
    assert "криптографически стойкий генератор" in text
    assert "аутентифицированным шифрованием" in text
    assert "только для затронутых логических блоков" in text
    assert "предыдущее завершённое состояние" in text
    assert "Argon2id" not in text
    assert "XChaCha20" not in text
    assert "libsodium" not in text
    assert "лицо не превращается в криптографический ключ" in text.lower()
    assert dialog.findChildren(QPushButton) == []

    dialog.close()
    application.processEvents()
