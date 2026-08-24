import os
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nacl import pwhash  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from cleverpgp.core.identity import IdentityService, formatted_fingerprint  # noqa: E402
from cleverpgp.core.profile_service import KdfParameters, ProfileService  # noqa: E402
from cleverpgp.core.storage import ProfileRepository  # noqa: E402
from cleverpgp.ui.shell_dialog import ShellFileWorker, ShellOperationDialog  # noqa: E402


def _profile(
    directory: Path,
    name: str,
) -> tuple[ProfileRepository, ProfileService, bytes]:
    repository = ProfileRepository(directory / f"{name}.sqlite3")
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
    return repository, profiles, master_key


def test_shell_encrypt_dialog_can_be_created(tmp_path: Path) -> None:
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profiles = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    profiles.create_profile("Алмас", "correct horse battery staple")
    source = tmp_path / "report.txt"
    source.write_text("BioPGP", encoding="utf-8")

    dialog = ShellOperationDialog(repository, "encrypt", source)

    assert dialog.target == tmp_path / "report.txt.cpgp"
    assert dialog.windowTitle().startswith("Шифрование")
    assert dialog.width() >= 760
    assert dialog.height() >= 560
    dialog.close()
    application.processEvents()


def test_shell_worker_encrypts_path_with_spaces(tmp_path: Path) -> None:
    application = QApplication.instance() or QApplication([])
    repository = ProfileRepository(tmp_path / "profile.sqlite3")
    repository.initialize()
    profiles = ProfileService(
        repository,
        KdfParameters(
            opslimit=pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=pwhash.argon2id.MEMLIMIT_MIN,
        ),
    )
    password = "correct horse battery staple"
    profiles.create_profile("Алмас", password)
    source = tmp_path / "report with spaces.txt"
    source.write_text("BioPGP shell integration", encoding="utf-8")
    dialog = ShellOperationDialog(repository, "encrypt", source)
    dialog.password_input.setText(password)

    dialog._start()
    assert dialog.running
    assert not dialog.cancel_button.isEnabled()
    assert not dialog.choose_button.isEnabled()
    assert not dialog.windowFlags() & Qt.WindowType.WindowCloseButtonHint
    deadline = time.monotonic() + 10
    while dialog.running and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    assert not dialog.running
    encrypted = tmp_path / "report with spaces.txt.cpgp"
    assert encrypted.is_file()
    assert dialog.status.objectName() == "success"
    assert dialog.windowFlags() & Qt.WindowType.WindowCloseButtonHint
    dialog.close()
    application.processEvents()

    decrypt_dialog = ShellOperationDialog(repository, "decrypt", encrypted)
    decrypt_dialog.password_input.setText(password)
    decrypt_dialog._start()
    deadline = time.monotonic() + 10
    while decrypt_dialog.running and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(0.01)

    restored = tmp_path / "report with spaces.decrypted.txt"
    assert not decrypt_dialog.running
    assert restored.read_text(encoding="utf-8") == "BioPGP shell integration"
    assert decrypt_dialog.status.objectName() == "success"
    decrypt_dialog.close()
    application.processEvents()


def test_shell_worker_encrypts_for_contact_and_shows_unknown_sender_fingerprint(
    tmp_path: Path,
) -> None:
    _application = QApplication.instance() or QApplication([])
    alice_repository, _alice_profiles, alice_key = _profile(tmp_path, "Alice")
    bob_repository, _bob_profiles, bob_key = _profile(tmp_path, "Bob")
    alice_identity = IdentityService(alice_repository).public_identity(alice_key)
    bob_bundle = tmp_path / "bob.cpgk"
    IdentityService(bob_repository).export_public_identity(bob_bundle, bob_key)
    bob_contact = IdentityService(alice_repository).import_contact(bob_bundle)
    source = tmp_path / "message.txt"
    encrypted = tmp_path / "message.txt.cpgp"
    restored = tmp_path / "restored.txt"
    source.write_text("signed message for Bob", encoding="utf-8")
    failures: list[str] = []

    encrypt_worker = ShellFileWorker(
        alice_repository,
        "encrypt",
        source,
        encrypted,
        "correct horse battery staple",
        False,
        (bob_contact,),
    )
    encrypt_worker.failed.connect(failures.append)
    encrypt_worker.run()
    assert failures == []
    assert encrypted.is_file()

    results: list[str] = []
    decrypt_worker = ShellFileWorker(
        bob_repository,
        "decrypt",
        encrypted,
        restored,
        "correct horse battery staple",
        False,
    )
    decrypt_worker.succeeded.connect(results.append)
    decrypt_worker.failed.connect(failures.append)
    decrypt_worker.run()

    assert failures == []
    assert restored.read_text(encoding="utf-8") == "signed message for Bob"
    assert len(results) == 1
    assert formatted_fingerprint(alice_identity.fingerprint) in results[0]
