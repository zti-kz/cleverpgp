import os
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nacl import pwhash  # noqa: E402
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from biopgp.core.profile_service import KdfParameters, ProfileService  # noqa: E402
from biopgp.core.storage import ProfileRepository  # noqa: E402
from biopgp.ui.shell_dialog import ShellOperationDialog  # noqa: E402


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
