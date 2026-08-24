from __future__ import annotations

import string

from PySide6.QtWidgets import QApplication, QLineEdit

from cleverpgp.core.password_generator import (
    generate_memorable_password,
    generate_random_password,
)
from cleverpgp.ui.password_generator import add_password_generator_action


def test_memorable_password_has_words_symbol_and_random_number() -> None:
    generated = generate_memorable_password()

    assert generated[0].isupper()
    assert sum(character.isupper() for character in generated) >= 2
    assert any(symbol in generated for symbol in "!@#$%&*?")
    assert generated[-4:].isdigit()
    assert len(generated) >= 12
    assert "-" not in generated


def test_random_password_contains_all_character_classes() -> None:
    generated = generate_random_password()

    assert len(generated) == 24
    assert any(character in string.ascii_lowercase for character in generated)
    assert any(character in string.ascii_uppercase for character in generated)
    assert any(character in string.digits for character in generated)
    assert any(character in "!@#$%&*?" for character in generated)


def test_generator_action_fills_password_and_confirmation() -> None:
    QApplication.instance() or QApplication([])
    password = QLineEdit()
    confirmation = QLineEdit()
    action = add_password_generator_action(password, confirmation)

    assert action in password.actions()
    assert action.objectName() == "passwordGeneratorAction"
    action.trigger()

    assert password.text()
    assert password.text() == confirmation.text()
    assert password.echoMode() == QLineEdit.EchoMode.Normal
    assert confirmation.echoMode() == QLineEdit.EchoMode.Password
