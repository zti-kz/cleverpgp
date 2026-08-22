from __future__ import annotations

from functools import lru_cache

from PySide6.QtGui import QIcon, QPixmap


_SHAPES = {
    "lock": (
        '<rect x="6" y="10" width="12" height="10" rx="2"/>'
        '<path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10"/>'
        '<circle cx="12" cy="15" r="1"/>'
    ),
    "unlock": (
        '<rect x="6" y="10" width="12" height="10" rx="2"/>'
        '<path d="M15.5 10V7.5a3.5 3.5 0 0 0-6.7-1.4"/>'
        '<circle cx="12" cy="15" r="1"/>'
    ),
    "face": (
        '<circle cx="12" cy="8" r="4"/>'
        '<path d="M4.5 20c.7-4.3 3.2-6.5 7.5-6.5s6.8 2.2 7.5 6.5"/>'
        '<path d="M9.8 8h.01M14.2 8h.01M10 10.2c1.3.9 2.7.9 4 0"/>'
    ),
    "file_lock": (
        '<path d="M6 3h8l4 4v13H6z"/>'
        '<path d="M14 3v5h4M9 14h6v5H9zM10.2 14v-1.2a1.8 1.8 0 0 1 3.6 0V14"/>'
    ),
    "file_open": (
        '<path d="M6 3h8l4 4v13H6z"/>'
        '<path d="M14 3v5h4M9 14h6v5H9zM13.8 14v-1.2a1.8 1.8 0 0 0-3.4-.8"/>'
    ),
    "vault_add": (
        '<rect x="3" y="5" width="18" height="14" rx="2"/>'
        '<circle cx="10" cy="12" r="3"/>'
        '<path d="M10 9v6M7 12h6M18 9v6"/>'
    ),
    "vault": (
        '<rect x="3" y="5" width="18" height="14" rx="2"/>'
        '<circle cx="10" cy="12" r="3"/>'
        '<path d="M10 9v6M7 12h6M18 9v6"/>'
    ),
    "eject": '<path d="M5 14l7-8 7 8zM5 18h14"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>',
    "close": '<path d="M6 6l12 12M18 6L6 18"/>',
    "folder": '<path d="M3 7h7l2 2h9v10H3z"/>',
    "shield": '<path d="M12 3l8 3v5c0 5-3.2 8.2-8 10-4.8-1.8-8-5-8-10V6z"/><path d="M8.5 12l2.2 2.2 4.8-5"/>',
}


@lru_cache(maxsize=64)
def line_icon(name: str, color: str = "#e2e8f0") -> QIcon:
    shape = _SHAPES[name]
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
        'viewBox="0 0 24 24" fill="none" '
        f'stroke="{color}" stroke-width="1.8" stroke-linecap="round" '
        f'stroke-linejoin="round">{shape}</svg>'
    )
    pixmap = QPixmap()
    if not pixmap.loadFromData(svg.encode("utf-8"), "SVG"):
        return QIcon()
    return QIcon(pixmap)
