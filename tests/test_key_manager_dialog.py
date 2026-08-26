from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nacl import pwhash  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

from cleverpgp.core.portable_keys import PortableKeyService  # noqa: E402
from cleverpgp.core.storage import ProfileRepository  # noqa: E402
from cleverpgp.ui.key_manager_dialog import KeyManagerDialog  # noqa: E402


def test_key_actions_are_in_context_menu_and_validity_is_visible(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    PortableKeyService(
        repository,
        opslimit=pwhash.argon2id.OPSLIMIT_MIN,
        memlimit=pwhash.argon2id.MEMLIMIT_MIN,
    ).create_key("Almas Oskenbay", "Personality@2026")

    dialog = KeyManagerDialog(repository)
    button_texts = {
        button.text() for button in dialog.findChildren(QPushButton)
    }

    assert "Создать ключ" in button_texts
    assert "Импорт закрытого ключа" in button_texts
    assert "Экспорт закрытого ключа" not in button_texts
    assert "Экспорт открытого ключа" not in button_texts
    assert "Удалить цифровой ключ" not in button_texts
    assert (
        dialog.key_list.contextMenuPolicy()
        == Qt.ContextMenuPolicy.CustomContextMenu
    )
    assert "Действует до:" in dialog.key_list.item(0).text()

    dialog.close()
    application.processEvents()
