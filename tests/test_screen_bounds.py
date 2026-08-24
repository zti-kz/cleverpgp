import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QRect, QSize  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog  # noqa: E402

from cleverpgp.ui.screen_bounds import (  # noqa: E402
    bounded_window_size,
    centred_rect,
    fit_window_to_screen,
    install_screen_bounds,
)


def test_window_size_is_clamped_to_available_work_area() -> None:
    assert bounded_window_size(QSize(900, 920), QSize(800, 600)) == QSize(
        760,
        560,
    )
    assert bounded_window_size(QSize(500, 400), QSize(800, 600)) == QSize(
        500,
        400,
    )


def test_centred_rect_stays_inside_offset_work_area() -> None:
    available = QRect(1920, 40, 1280, 680)
    result = centred_rect(QSize(1600, 900), available)

    assert available.contains(result)
    assert result.center() == available.center()


def test_screen_filter_reduces_oversized_dialog() -> None:
    application = QApplication.instance() or QApplication([])
    install_screen_bounds(application)
    dialog = QDialog()
    dialog.setMinimumSize(1600, 1200)
    dialog.resize(1600, 1200)

    dialog.show()
    application.processEvents()
    application.processEvents()
    fit_window_to_screen(dialog)

    available = dialog.screen().availableGeometry()
    assert dialog.width() <= available.width() - 40
    assert dialog.height() <= available.height() - 40
    assert available.contains(dialog.frameGeometry())
    dialog.close()
    application.processEvents()
