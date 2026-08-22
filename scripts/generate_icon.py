from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (
    QColor,
    QIcon,
    QImage,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import QApplication


PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]
ASSETS_DIRECTORY = PROJECT_DIRECTORY / "assets"


def shield_path(size: int) -> QPainterPath:
    scale = size / 256
    path = QPainterPath(QPointF(128 * scale, 38 * scale))
    path.cubicTo(
        QPointF(103 * scale, 55 * scale),
        QPointF(79 * scale, 63 * scale),
        QPointF(54 * scale, 66 * scale),
    )
    path.lineTo(QPointF(54 * scale, 118 * scale))
    path.cubicTo(
        QPointF(54 * scale, 170 * scale),
        QPointF(82 * scale, 207 * scale),
        QPointF(128 * scale, 225 * scale),
    )
    path.cubicTo(
        QPointF(174 * scale, 207 * scale),
        QPointF(202 * scale, 170 * scale),
        QPointF(202 * scale, 118 * scale),
    )
    path.lineTo(QPointF(202 * scale, 66 * scale))
    path.cubicTo(
        QPointF(177 * scale, 63 * scale),
        QPointF(153 * scale, 55 * scale),
        QPointF(128 * scale, 38 * scale),
    )
    path.closeSubpath()
    return path


def draw_icon(size: int) -> QPixmap:
    image = QImage(size, size, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    painter.setBrush(QColor("#071426"))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(QRectF(5, 5, size - 10, size - 10), size * 0.22, size * 0.22)

    shield = shield_path(size)
    painter.setBrush(QColor("#1976F3"))
    painter.drawPath(shield)

    scale = size / 256
    painter.setPen(QPen(QColor("#FFFFFF"), 15 * scale, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawEllipse(QPointF(128 * scale, 115 * scale), 34 * scale, 34 * scale)
    painter.drawLine(QPointF(128 * scale, 149 * scale), QPointF(128 * scale, 184 * scale))
    painter.setPen(QPen(QColor("#52E0B5"), 10 * scale, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    painter.drawArc(QRectF(83 * scale, 75 * scale, 90 * scale, 90 * scale), 28 * 16, 124 * 16)
    painter.end()
    return QPixmap.fromImage(image)


def main() -> int:
    application = QApplication.instance() or QApplication([])
    ASSETS_DIRECTORY.mkdir(parents=True, exist_ok=True)
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(draw_icon(size))
    if not icon.pixmap(256, 256).save(str(ASSETS_DIRECTORY / "biopgp.png"), "PNG"):
        raise RuntimeError("Не удалось сохранить PNG-значок Clever PGP.")
    if not icon.pixmap(256, 256).save(str(ASSETS_DIRECTORY / "biopgp.ico"), "ICO"):
        raise RuntimeError("Не удалось сохранить ICO-значок Clever PGP.")
    application.processEvents()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
