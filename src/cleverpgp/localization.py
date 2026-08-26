from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from threading import RLock

from PySide6.QtCore import QLocale
from PySide6.QtWidgets import (
    QAbstractButton,
    QComboBox,
    QLabel,
    QLineEdit,
    QWidget,
)

from cleverpgp.config import app_data_directory


@dataclass(frozen=True)
class Language:
    code: str
    native_name: str


_lock = RLock()
_catalogs: dict[str, dict[str, str]] | None = None
_languages: tuple[Language, ...] = ()
_current_language = "ru"
_LANGUAGE_CODE = re.compile(r"^[a-z]{2,3}(?:[_-][A-Z]{2})?$")
_MAX_LANGUAGE_PACK_BYTES = 2 * 1024 * 1024
_MAX_TRANSLATIONS = 5000
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
        re.compile(r"^Версия формата (?P<version>\d+) не поддерживается\.$"),
        "Версия формата {version} не поддерживается.",
    ),
    (
        re.compile(
            r"^Для одного файла можно выбрать не более (?P<count>\d+) получателей\.$"
        ),
        "Для одного файла можно выбрать не более {count} получателей.",
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
        locale_directory = files("cleverpgp").joinpath("locales")
        built_in_codes: set[str] = set()
        for resource in sorted(locale_directory.iterdir(), key=lambda item: item.name):
            if not resource.name.endswith(".json"):
                continue
            language, translations = _validated_language_payload(
                json.loads(resource.read_text(encoding="utf-8"))
            )
            built_in_codes.add(language.code)
            languages.append(language)
            catalogs[language.code] = translations
        user_directory = language_pack_directory()
        if user_directory.is_dir():
            for source in sorted(user_directory.glob("*.json")):
                try:
                    if source.stat().st_size > _MAX_LANGUAGE_PACK_BYTES:
                        continue
                    language, translations = _validated_language_payload(
                        json.loads(source.read_text(encoding="utf-8"))
                    )
                except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError):
                    continue
                if language.code in built_in_codes:
                    continue
                languages.append(language)
                catalogs[language.code] = translations
        if "ru" not in catalogs:
            raise RuntimeError("The base Russian language catalog is missing")
        preferred_order = {"en": 0, "ru": 1, "kk": 2}
        languages.sort(key=lambda item: (preferred_order.get(item.code, 100), item.code))
        _catalogs = catalogs
        _languages = tuple(languages)


def language_pack_directory() -> Path:
    return app_data_directory() / "languages"


def install_language_pack(source: Path) -> Language:
    """Validate and install a text-only local Clever PGP language pack."""

    selected = Path(source).expanduser().resolve()
    if not selected.is_file():
        raise ValueError("Файл языкового пакета не найден.")
    if selected.stat().st_size > _MAX_LANGUAGE_PACK_BYTES:
        raise ValueError("Языковой пакет слишком большой.")
    try:
        payload = json.loads(selected.read_text(encoding="utf-8"))
        language, translations = _validated_language_payload(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValueError("Языковой пакет имеет неверный формат.") from error
    built_in = {item.code for item in _built_in_languages()}
    if language.code in built_in:
        raise ValueError("Встроенный язык нельзя заменить внешним пакетом.")
    destination_directory = language_pack_directory()
    destination_directory.mkdir(parents=True, exist_ok=True)
    destination = destination_directory / f"{language.code}.json"
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    canonical = {
        "code": language.code,
        "native_name": language.native_name,
        "translations": translations,
    }
    try:
        temporary.write_text(
            json.dumps(canonical, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    reload_language_catalogs()
    return language


def export_language_template(
    destination: Path,
    *,
    code: str,
    native_name: str,
) -> Path:
    """Write a complete text-only translation template for a new locale."""

    normalized_code = code.strip()
    normalized_name = native_name.strip()
    if _LANGUAGE_CODE.fullmatch(normalized_code) is None:
        raise ValueError("Код языка должен иметь вид de_DE или de.")
    if not normalized_name or len(normalized_name) > 80 or "\x00" in normalized_name:
        raise ValueError("Введите название языка на этом языке.")
    built_in = {item.code for item in _built_in_languages()}
    if normalized_code in built_in:
        raise ValueError("Для встроенного языка шаблон не требуется.")

    _load_catalogs()
    assert _catalogs is not None
    source_messages = sorted(
        {
            message
            for catalog in _catalogs.values()
            for message in catalog
        }
    )
    payload = {
        "code": normalized_code,
        "native_name": normalized_name,
        # Russian source text is retained until a translator replaces a value.
        # This keeps incomplete packs readable instead of producing blank labels.
        "translations": {message: message for message in source_messages},
    }
    selected = Path(destination).expanduser().resolve()
    selected.parent.mkdir(parents=True, exist_ok=True)
    selected.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return selected


def reload_language_catalogs() -> None:
    global _catalogs, _languages
    with _lock:
        _catalogs = None
        _languages = ()


def _built_in_languages() -> tuple[Language, ...]:
    result: list[Language] = []
    locale_directory = files("cleverpgp").joinpath("locales")
    for resource in locale_directory.iterdir():
        if not resource.name.endswith(".json"):
            continue
        language, _translations = _validated_language_payload(
            json.loads(resource.read_text(encoding="utf-8"))
        )
        result.append(language)
    return tuple(result)


def _validated_language_payload(
    payload: object,
) -> tuple[Language, dict[str, str]]:
    if not isinstance(payload, dict) or set(payload) != {
        "code",
        "native_name",
        "translations",
    }:
        raise ValueError("invalid language fields")
    code = payload["code"]
    native_name = payload["native_name"]
    raw_translations = payload["translations"]
    if not isinstance(code, str) or _LANGUAGE_CODE.fullmatch(code) is None:
        raise ValueError("invalid language code")
    if (
        not isinstance(native_name, str)
        or not native_name.strip()
        or len(native_name) > 80
        or "\x00" in native_name
    ):
        raise ValueError("invalid native name")
    if (
        not isinstance(raw_translations, dict)
        or len(raw_translations) > _MAX_TRANSLATIONS
    ):
        raise ValueError("invalid translations")
    translations: dict[str, str] = {}
    for source, translated in raw_translations.items():
        if (
            not isinstance(source, str)
            or not isinstance(translated, str)
            or not source
            or len(source) > 10000
            or len(translated) > 10000
            or "\x00" in source
            or "\x00" in translated
        ):
            raise ValueError("invalid translation")
        translations[source] = translated
    return Language(code, native_name.strip()), translations


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
