from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import QLineEdit, QMenu, QPushButton, QWidget

from cleverpgp.core.password_generator import (
    generate_memorable_password,
    generate_random_password,
)
from cleverpgp.localization import tr
from cleverpgp.ui.icons import line_icon


def create_password_generator_button(
    password_input: QLineEdit,
    repeat_input: QLineEdit,
    parent: QWidget | None = None,
    *,
    text: str = "Сгенерировать пароль",
) -> QPushButton:
    button = QPushButton(tr(text), parent)
    button.setIcon(line_icon("key"))
    button.setToolTip(
        tr("Созданный пароль будет показан до закрытия текущего окна.")
    )
    menu = QMenu(button)
    memorable = menu.addAction(tr("Запоминаемый пароль из слов"))
    random_combination = menu.addAction(tr("Случайная комбинация"))

    def fill(generator: Callable[[], str]) -> None:
        password = generator()
        password_input.setText(password)
        repeat_input.setText(password)
        password_input.setEchoMode(QLineEdit.EchoMode.Normal)
        repeat_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_input.setFocus()
        password_input.selectAll()

    memorable.triggered.connect(
        lambda _checked=False: fill(generate_memorable_password)
    )
    random_combination.triggered.connect(
        lambda _checked=False: fill(generate_random_password)
    )
    button.setMenu(menu)
    return button
