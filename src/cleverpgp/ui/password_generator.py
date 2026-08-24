from __future__ import annotations

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QLineEdit

from cleverpgp.core.password_generator import generate_memorable_password
from cleverpgp.localization import tr
from cleverpgp.ui.icons import line_icon


def add_password_generator_action(
    password_input: QLineEdit,
    repeat_input: QLineEdit,
) -> QAction:
    """Add one compact, direct generator button inside a password field."""

    action = password_input.addAction(
        line_icon("key"),
        QLineEdit.ActionPosition.TrailingPosition,
    )
    action.setObjectName("passwordGeneratorAction")
    action.setToolTip(tr("Создать запоминаемый пароль"))

    def fill() -> None:
        password = generate_memorable_password()
        password_input.setText(password)
        repeat_input.setText(password)
        password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        repeat_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_input.setFocus()
        password_input.selectAll()

    action.triggered.connect(lambda _checked=False: fill())
    return action
