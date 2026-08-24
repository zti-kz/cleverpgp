from __future__ import annotations

import weakref

from PySide6.QtCore import QEvent, QObject, QRect, QSize, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QWidget

WINDOW_MARGIN = 20


def bounded_window_size(
    desired: QSize,
    available: QSize,
    *,
    margin: int = WINDOW_MARGIN,
) -> QSize:
    """Clamp a top-level window to the usable desktop in logical pixels."""

    inset = max(0, int(margin)) * 2
    maximum_width = max(1, available.width() - inset)
    maximum_height = max(1, available.height() - inset)
    return QSize(
        max(1, min(desired.width(), maximum_width)),
        max(1, min(desired.height(), maximum_height)),
    )


def fit_window_to_screen(
    window: QWidget,
    *,
    margin: int = WINDOW_MARGIN,
) -> None:
    """Resize and centre a window inside its current screen's work area."""

    if not isinstance(window, QWidget):
        return
    screen = window.screen()
    if screen is None:
        application = QApplication.instance()
        screen = application.primaryScreen() if application is not None else None
    if screen is None:
        return

    available = screen.availableGeometry()
    inset = max(0, int(margin)) * 2
    maximum = QSize(
        max(1, available.width() - inset),
        max(1, available.height() - inset),
    )
    layout = window.layout()
    if layout is not None:
        layout.activate()
    hint = window.sizeHint()
    current = window.size()
    desired = QSize(
        max(current.width(), hint.width()),
        max(current.height(), hint.height()),
    )
    bounded = bounded_window_size(desired, available.size(), margin=margin)

    minimum = window.minimumSize()
    window.setMinimumSize(
        min(minimum.width(), maximum.width()),
        min(minimum.height(), maximum.height()),
    )
    if isinstance(window, QDialog):
        window.setMaximumSize(maximum)
    window.resize(bounded)

    frame = window.frameGeometry()
    frame.moveCenter(available.center())
    x = max(
        available.left(),
        min(frame.left(), available.right() - frame.width() + 1),
    )
    y = max(
        available.top(),
        min(frame.top(), available.bottom() - frame.height() + 1),
    )
    window.move(x, y)


class ScreenBoundsFilter(QObject):
    """Apply work-area bounds to every modal window after Qt lays it out."""

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        if event.type() == QEvent.Type.Show and isinstance(watched, QDialog):
            reference = weakref.ref(watched)

            def apply_bounds() -> None:
                dialog = reference()
                if dialog is not None and dialog.isVisible():
                    fit_window_to_screen(dialog)

            QTimer.singleShot(0, apply_bounds)
        return super().eventFilter(watched, event)


def install_screen_bounds(application: QApplication) -> ScreenBoundsFilter:
    existing = getattr(application, "_cleverpgp_screen_bounds", None)
    if isinstance(existing, ScreenBoundsFilter):
        return existing
    # Keep the filter on the QApplication object below. Avoiding a QObject
    # parent also keeps the entry point straightforward to exercise with a
    # lightweight application double.
    bounds_filter = ScreenBoundsFilter()
    application.installEventFilter(bounds_filter)
    setattr(application, "_cleverpgp_screen_bounds", bounds_filter)
    return bounds_filter


def centred_rect(size: QSize, available: QRect) -> QRect:
    """Return a centred rectangle, primarily for geometry regression tests."""

    bounded = bounded_window_size(size, available.size())
    result = QRect(available.topLeft(), bounded)
    result.moveCenter(available.center())
    return result
