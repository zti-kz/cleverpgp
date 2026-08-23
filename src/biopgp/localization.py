from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib.resources import files
from threading import RLock

from PySide6.QtCore import QLocale
from PySide6.QtWidgets import (
    QAbstractButton,
    QComboBox,
    QLabel,
    QLineEdit,
    QWidget,
)


@dataclass(frozen=True)
class Language:
    code: str
    native_name: str


_lock = RLock()
_catalogs: dict[str, dict[str, str]] | None = None
_languages: tuple[Language, ...] = ()
_current_language = "ru"
_dynamic_messages = (
    (
        re.compile(r"^Мастер-пароль должен содержать не менее (?P<count>\d+) символов\.$"),
        "Мастер-пароль должен содержать не менее {count} символов.",
    ),
    (
        re.compile(r"^Версия формата (?P<version>\d+) пока не поддерживается\.$"),
        "Версия формата {version} пока не поддерживается.",
    ),
    (
        re.compile(r"^Версия контейнера (?P<version>\d+) пока не поддерживается\.$"),
        "Версия контейнера {version} пока не поддерживается.",
    ),
    (
        re.compile(r"^Не удалось загрузить модели лица: (?P<error>.+)$"),
        "Не удалось загрузить модели лица: {error}",
    ),
    (
        re.compile(r"^Ошибка локального детектора лица: (?P<error>.+)$"),
        "Ошибка локального детектора лица: {error}",
    ),
    (
        re.compile(r"^Ошибка локального распознавания лица: (?P<error>.+)$"),
        "Ошибка локального распознавания лица: {error}",
    ),
    (
        re.compile(
            r"^Windows не запустила форматирование диска \(код (?P<code>\d+)\)\.$"
        ),
        "Windows не запустила форматирование диска (код {code}).",
    ),
    (
        re.compile(
            r"^Ожидание процесса Windows завершилось с кодом (?P<code>\d+)\.$"
        ),
        "Ожидание процесса Windows завершилось с кодом {code}.",
    ),
    (
        re.compile(
            r"^Windows не запустила защищённую операцию \(код (?P<code>\d+)\)\.$"
        ),
        "Windows не запустила защищённую операцию (код {code}).",
    ),
)


def _load_catalogs() -> None:
    global _catalogs, _languages
    with _lock:
        if _catalogs is not None:
            return
        catalogs: dict[str, dict[str, str]] = {}
        languages: list[Language] = []
        locale_directory = files("biopgp").joinpath("locales")
        for resource in sorted(locale_directory.iterdir(), key=lambda item: item.name):
            if not resource.name.endswith(".json"):
                continue
            payload = json.loads(resource.read_text(encoding="utf-8"))
            code = str(payload["code"])
            languages.append(Language(code, str(payload["native_name"])))
            catalogs[code] = {
                str(source): str(translated)
                for source, translated in payload.get("translations", {}).items()
            }
        if "ru" not in catalogs:
            raise RuntimeError("The base Russian language catalog is missing")
        preferred_order = {"en": 0, "ru": 1, "kk": 2}
        languages.sort(key=lambda item: (preferred_order.get(item.code, 100), item.code))
        _catalogs = catalogs
        _languages = tuple(languages)


def available_languages() -> tuple[Language, ...]:
    _load_catalogs()
    return _languages


def current_language() -> str:
    return _current_language


def system_language() -> str:
    prefix = QLocale.system().name().split("_", 1)[0].lower()
    return prefix if prefix in {item.code for item in available_languages()} else "en"


def set_language(code: str | None) -> str:
    global _current_language
    selected = code or system_language()
    supported = {item.code for item in available_languages()}
    if selected not in supported:
        selected = "en"
    _current_language = selected
    return selected


def tr(source: str, **values: object) -> str:
    _load_catalogs()
    assert _catalogs is not None
    catalog = _catalogs.get(_current_language, {})
    translated = catalog.get(source, source)
    if translated == source and _current_language != "ru":
        for pattern, template in _dynamic_messages:
            match = pattern.fullmatch(source)
            if match is not None:
                translated = catalog.get(template, template).format(**match.groupdict())
                break
    return translated.format(**values) if values else translated


def localize_widget_tree(root: QWidget) -> None:
    """Translate a newly built widget tree from the Russian source catalog."""

    widgets: list[QWidget] = [root, *root.findChildren(QWidget)]
    for widget in widgets:
        title = widget.windowTitle()
        if title:
            widget.setWindowTitle(tr(title))
        tooltip = widget.toolTip()
        if tooltip:
            widget.setToolTip(tr(tooltip))
        accessible_name = widget.accessibleName()
        if accessible_name:
            widget.setAccessibleName(tr(accessible_name))
        if isinstance(widget, QAbstractButton):
            widget.setText(tr(widget.text()))
        elif isinstance(widget, QLabel):
            widget.setText(tr(widget.text()))
        elif isinstance(widget, QLineEdit):
            widget.setPlaceholderText(tr(widget.placeholderText()))
        elif isinstance(widget, QComboBox) and widget.objectName() != "languageSelector":
            for index in range(widget.count()):
                widget.setItemText(index, tr(widget.itemText(index)))
