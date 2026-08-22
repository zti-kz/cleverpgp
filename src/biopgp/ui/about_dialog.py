from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from biopgp import __version__
from biopgp.localization import localize_widget_tree, tr
from biopgp.ui.icons import line_icon


COPYRIGHT_TEXT = (
    "© 2026 Алмас Оскенбаев, Институт интеллектуальных технологий. "
    "Все права защищены."
)
LICENSE_TEXT = "Свободное программное обеспечение: GNU GPL v3 или более поздняя версия."
WINFSP_NOTICE = (
    "WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos. "
    '<a href="https://github.com/winfsp/winfsp">github.com/winfsp/winfsp</a>'
)


class AboutDialog(QDialog):
    """Product information presented inside the application."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("О программе Clever PGP")
        self.setModal(True)
        self.resize(960, 840)
        self.setMinimumSize(700, 600)
        self.setStyleSheet(ABOUT_STYLESHEET)
        self._build_ui()
        localize_widget_tree(self)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setObjectName("aboutScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        body = QWidget()
        body.setObjectName("aboutBody")
        outer = QVBoxLayout(body)
        outer.setContentsMargins(28, 26, 28, 24)
        outer.setSpacing(18)

        header = QHBoxLayout()
        identity = QVBoxLayout()
        brand = QLabel("Clever PGP")
        brand.setObjectName("aboutBrand")
        tagline = QLabel("Криптографическая защита файлов и дисков")
        tagline.setObjectName("muted")
        identity.addWidget(brand)
        identity.addWidget(tagline)
        header.addLayout(identity)
        header.addStretch()
        version = QLabel(tr("Версия {version}", version=__version__))
        version.setObjectName("versionBadge")
        header.addWidget(version, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(header)

        summary = QLabel(
            "Clever PGP — локальная программа для криптографической защиты файлов "
            "и зашифрованных дисков с биометрическим управлением. Программа "
            "разрабатывается как реализация метода "
            "криптографической защиты файлов с биометрическим управлением на "
            "основе распознавания лица. Она защищает отдельные файлы и создаёт "
            "контейнеры, которые подключаются в Windows как обычные диски."
        )
        summary.setObjectName("lead")
        summary.setWordWrap(True)
        outer.addWidget(summary)

        outer.addWidget(self._section(
            "Принцип криптографической защиты",
            "При инициализации профиля криптографически стойкий генератор "
            "случайных чисел формирует мастер-ключ. Мастер-пароль не хранится: "
            "из него с применением индивидуальной соли и ресурсоёмкой функции "
            "выработки ключа формируется ключ разблокировки, защищающий "
            "мастер-ключ. Для каждого файла создаётся независимый сеансовый "
            "ключ. Содержимое защищается аутентифицированным шифрованием, а "
            "сеансовый ключ сохраняется только в зашифрованном виде под защитой "
            "мастер-ключа. При расшифровании проверяется целостность и подлинность "
            "данных: изменение любого блока, неправильный ключ или повреждение "
            "приводят к отказу открытия без выдачи недостоверного результата.",
            "shield",
        ))
        outer.addWidget(self._section(
            "Биометрическое управление",
            "Распознавание лица и проверка присутствия выполняются локально. "
            "Биометрический шаблон хранится в защищённом виде. Лицо не "
            "превращается в криптографический ключ: успешная верификация только "
            "разрешает использование защищённых криптографических ключей. Изображения, "
            "пароль и ключи не передаются на сервер.",
            "face",
        ))
        outer.addWidget(self._section(
            "Файлы и зашифрованные диски",
            "При отдельном шифровании исходный файл сохраняется, а защищённая "
            "копия получает расширение .cpgp. Контейнер .cpgv содержит "
            "зашифрованную файловую систему: защищаются структура каталогов, "
            "имена, метаданные и содержимое файлов. При подключении рабочее "
            "состояние существует только в оперативной памяти; после изменений "
            "оно повторно шифруется и сохраняется в контейнер. Открытая временная "
            "папка на диске не создаётся.",
            "vault",
        ))
        outer.addStretch()

        copyright_label = QLabel(COPYRIGHT_TEXT)
        copyright_label.setObjectName("copyright")
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        copyright_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        outer.addWidget(copyright_label)
        license_label = QLabel(LICENSE_TEXT)
        license_label.setObjectName("license")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        license_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        outer.addWidget(license_label)
        winfsp_label = QLabel(WINFSP_NOTICE)
        winfsp_label.setObjectName("thirdParty")
        winfsp_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        winfsp_label.setTextFormat(Qt.TextFormat.RichText)
        winfsp_label.setOpenExternalLinks(True)
        winfsp_label.setWordWrap(True)
        outer.addWidget(winfsp_label)
        scroll.setWidget(body)
        root.addWidget(scroll)

    @staticmethod
    def _section(title: str, text: str, icon_name: str) -> QFrame:
        card = QFrame()
        card.setObjectName("aboutSection")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 15, 18, 16)
        layout.setSpacing(7)
        heading_row = QHBoxLayout()
        heading_icon = QLabel()
        heading_icon.setPixmap(line_icon(icon_name, "#7dd3fc").pixmap(22, 22))
        heading = QLabel(title)
        heading.setObjectName("sectionTitle")
        description = QLabel(text)
        description.setObjectName("sectionText")
        description.setWordWrap(True)
        description.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        heading_row.addWidget(heading_icon)
        heading_row.addWidget(heading)
        heading_row.addStretch()
        layout.addLayout(heading_row)
        layout.addWidget(description)
        return card


ABOUT_STYLESHEET = """
QDialog, QWidget {
    background: #111827;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
}
QScrollArea#aboutScroll, QWidget#aboutBody { border: 0; background: #111827; }
QLabel { background: transparent; }
QLabel#aboutBrand { color: #7dd3fc; font-size: 28px; font-weight: 700; }
QLabel#muted { color: #9ca3af; }
QLabel#copyright { color: #94a3b8; padding: 8px 0 2px 0; }
QLabel#license { color: #7dd3fc; padding: 0 0 2px 0; }
QLabel#thirdParty { color: #94a3b8; padding: 0 0 2px 0; }
QLabel#thirdParty a { color: #7dd3fc; }
QLabel#versionBadge {
    color: #bae6fd;
    background: #0c4a6e;
    border: 1px solid #0369a1;
    border-radius: 13px;
    padding: 6px 12px;
    font-weight: 600;
}
QLabel#lead { color: #f3f4f6; font-size: 15px; line-height: 1.4; }
QFrame#aboutSection {
    background: #172033;
    border: 1px solid #2b3a55;
    border-radius: 12px;
}
QLabel#sectionTitle { color: #f9fafb; font-size: 16px; font-weight: 650; }
QLabel#sectionText { color: #cbd5e1; }
"""
