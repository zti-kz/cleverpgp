from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nacl import pwhash, utils  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QFileDialog,
    QMessageBox,
    QPushButton,
)

from cleverpgp.core.models import Contact  # noqa: E402
from cleverpgp.core.profile_service import KdfParameters, ProfileService  # noqa: E402
from cleverpgp.core.storage import ProfileRepository  # noqa: E402
from cleverpgp.ui.key_dialogs import (  # noqa: E402
    ContactsDialog,
    PublicKeyImportDialog,
    RecipientSelectionDialog,
)


def _profile(tmp_path: Path, name: str) -> tuple[ProfileRepository, bytes]:
    repository = ProfileRepository(tmp_path / f"{name}.sqlite3")
    repository.initialize()
    profiles = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    profiles.create_profile(name, "correct horse battery staple")
    session = profiles.unlock_with_password("correct horse battery staple")
    master_key = session.master_key_copy()
    session.lock()
    return repository, master_key


def _contact(identifier: str, name: str) -> Contact:
    return Contact(
        contact_id=identifier,
        display_name=name,
        fingerprint=(identifier * 64)[:64].upper(),
        encryption_public_key=utils.random(32),
        signing_public_key=utils.random(32),
        created_at="2026-08-23T00:00:00+00:00",
    )


def test_recipient_dialog_returns_only_checked_contacts() -> None:
    application = QApplication.instance() or QApplication([])
    alice = _contact("a", "Alice")
    bob = _contact("b", "Bob")
    dialog = RecipientSelectionDialog((alice, bob))

    dialog.contact_list.item(1).setCheckState(Qt.CheckState.Checked)
    dialog._accept_selection()

    assert dialog.selected_contacts == (bob,)
    assert not any(
        button.text() in {"Отмена", "Закрыть"}
        for button in dialog.findChildren(QPushButton)
    )
    dialog.close()
    application.processEvents()


def test_contacts_dialog_exports_imports_and_deletes_key(
    monkeypatch,
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    alice_repository, alice_key = _profile(tmp_path, "Alice")
    bob_repository, bob_key = _profile(tmp_path, "Bob")
    key_file = tmp_path / "alice.cpgk"

    alice_dialog = ContactsDialog(alice_repository, alice_key)
    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *_args, **_kwargs: (str(key_file), ""),
    )
    alice_dialog._export_key()
    assert key_file.is_file()
    assert alice_dialog.status.objectName() == "success"
    alice_dialog.close()

    bob_dialog = ContactsDialog(bob_repository, bob_key)
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: (str(key_file), ""),
    )
    bob_dialog._import_key()
    contacts = bob_repository.list_contacts()
    assert len(contacts) == 1
    assert contacts[0].display_name == "Alice"
    assert bob_dialog.contact_list.count() == 1

    bob_dialog.contact_list.setCurrentRow(0)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    bob_dialog._delete_contact()
    assert bob_repository.list_contacts() == ()
    assert bob_dialog.status.objectName() == "success"

    assert not any(
        button.text() == "Закрыть"
        for button in bob_dialog.findChildren(QPushButton)
    )
    bob_dialog.close()
    application.processEvents()
    assert alice_dialog._master_key is None
    assert bob_dialog._master_key is None


def test_public_key_double_click_dialog_imports_verified_preview(
    tmp_path: Path,
) -> None:
    application = QApplication.instance() or QApplication([])
    alice_repository, alice_key = _profile(tmp_path, "Alice")
    bob_repository, _bob_key = _profile(tmp_path, "Bob")
    key_file = tmp_path / "alice.cpgk"
    export_dialog = ContactsDialog(alice_repository, alice_key)
    export_dialog.identity_service.export_public_identity(key_file, alice_key)
    export_dialog.close()

    dialog = PublicKeyImportDialog(bob_repository, key_file)
    assert dialog.public_identity is not None
    assert dialog.public_identity.display_name == "Alice"
    assert dialog.import_button.isEnabled()

    dialog._import_key()

    assert [contact.display_name for contact in bob_repository.list_contacts()] == [
        "Alice"
    ]
    assert dialog.status.objectName() == "success"
    assert not dialog.import_button.isEnabled()
    assert not any(
        button.text() == "Закрыть"
        for button in dialog.findChildren(QPushButton)
    )
    dialog.close()
    application.processEvents()
