from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

from biopgp.core.models import UnlockMode  # noqa: E402
from biopgp.ui.settings_dialog import AccessSettingsDialog  # noqa: E402


def _button(dialog: AccessSettingsDialog, text: str) -> QPushButton:
    return next(
        button
        for button in dialog.findChildren(QPushButton)
        if button.text() == text
    )


def test_settings_dialog_uses_title_bar_for_closing() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = AccessSettingsDialog(
        UnlockMode.PASSWORD_OR_FACE,
        biometric_enrolled=True,
    )

    button_texts = {
        button.text() for button in dialog.findChildren(QPushButton)
    }
    assert "Закрыть" not in button_texts
    assert "Отмена" not in button_texts
    assert button_texts == {
        "Применить режим",
        "Обновить данные лица",
        "Изменить мастер-пароль",
    }

    dialog.close()
    application.processEvents()


def test_face_dependent_mode_is_rejected_until_face_is_enrolled() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = AccessSettingsDialog(
        UnlockMode.PASSWORD_ONLY,
        biometric_enrolled=False,
    )
    dialog.mode_input.setCurrentIndex(
        dialog.mode_input.findData(UnlockMode.PASSWORD_AND_FACE.value)
    )

    _button(dialog, "Применить режим").click()

    assert dialog.request is None
    assert dialog.error_label.isVisible() is False or dialog.error_label.text()
    assert "Сначала зарегистрируйте лицо" in dialog.error_label.text()
    dialog.close()
    application.processEvents()


def test_password_request_requires_matching_confirmation_and_clears_fields() -> None:
    application = QApplication.instance() or QApplication([])
    dialog = AccessSettingsDialog(
        UnlockMode.PASSWORD_ONLY,
        biometric_enrolled=False,
    )
    dialog.current_password_input.setText("correct horse battery staple")
    dialog.new_password_input.setText("new correct horse battery staple")
    dialog.repeat_password_input.setText("different password confirmation")

    _button(dialog, "Изменить мастер-пароль").click()
    assert dialog.request is None
    assert "не совпадают" in dialog.error_label.text()

    dialog.repeat_password_input.setText("new correct horse battery staple")
    _button(dialog, "Изменить мастер-пароль").click()

    assert dialog.request is not None
    assert dialog.request.operation == "password"
    assert dialog.request.current_password == "correct horse battery staple"
    assert dialog.request.new_password == "new correct horse battery staple"
    assert dialog.current_password_input.text() == ""
    assert dialog.new_password_input.text() == ""
    assert dialog.repeat_password_input.text() == ""
    dialog.close()
    application.processEvents()
