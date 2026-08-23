from __future__ import annotations

from collections.abc import Iterable

from PySide6.QtCore import Qt
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import (
    QBoxLayout,
    QDialog,
    QFrame,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


def scrollable_dialog_layout(dialog: QDialog) -> QVBoxLayout:
    """Return a content layout that scrolls only when the screen is too small."""

    root = QVBoxLayout(dialog)
    root.setContentsMargins(0, 0, 0, 0)
    root.setSpacing(0)
    scroll = QScrollArea()
    scroll.setObjectName("adaptiveDialogScroll")
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setWidgetResizable(True)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    scroll.setStyleSheet(
        "QScrollArea#adaptiveDialogScroll { background: transparent; border: 0; }"
        "QScrollArea#adaptiveDialogScroll > QWidget > QWidget, "
        "QWidget#adaptiveDialogBody { background: transparent; }"
    )
    body = QWidget()
    body.setObjectName("adaptiveDialogBody")
    body.setMinimumSize(0, 0)
    content = QVBoxLayout(body)
    scroll.setWidget(body)
    root.addWidget(scroll)
    return content


class ResponsiveBox(QWidget):
    """Lay child panels beside each other or stack them at a narrow width."""

    def __init__(
        self,
        widgets: Iterable[QWidget],
        *,
        breakpoint: int,
        spacing: int = 12,
        align_last_right: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._breakpoint = max(1, int(breakpoint))
        self._align_last_right = align_last_right
        self._widgets = tuple(widgets)
        self._box = QBoxLayout(QBoxLayout.Direction.LeftToRight, self)
        self._box.setContentsMargins(0, 0, 0, 0)
        self._box.setSpacing(spacing)
        for widget in self._widgets:
            self._box.addWidget(widget, 1)
        self._vertical: bool | None = None
        self._apply_direction(False)

    def resizeEvent(self, event: QResizeEvent) -> None:  # noqa: N802
        self._apply_direction(event.size().width() < self._breakpoint)
        super().resizeEvent(event)

    def _apply_direction(self, vertical: bool) -> None:
        if self._vertical is vertical:
            return
        self._vertical = vertical
        self._box.setDirection(
            QBoxLayout.Direction.TopToBottom
            if vertical
            else QBoxLayout.Direction.LeftToRight
        )
        for index, widget in enumerate(self._widgets):
            self._box.setStretch(index, 0 if vertical else 1)
            alignment = (
                Qt.AlignmentFlag.AlignRight
                if self._align_last_right
                and index == len(self._widgets) - 1
                else Qt.AlignmentFlag(0)
            )
            self._box.setAlignment(widget, alignment)
