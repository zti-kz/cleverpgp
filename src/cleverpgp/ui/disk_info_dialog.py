from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
)

from cleverpgp.config import APP_NAME, ORGANIZATION_NAME, database_path
from cleverpgp.core.disk_crypto import AES256_GCM, XCHACHA20_POLY1305
from cleverpgp.core.disk_info import MountedDiskInfo, inspect_mounted_cleverpgp_disk
from cleverpgp.core.errors import BioPGPError
from cleverpgp.core.storage import ProfileRepository
from cleverpgp.localization import localize_widget_tree, set_language, tr
from cleverpgp.ui.adaptive import scrollable_dialog_layout
from cleverpgp.ui.container_dialog import CONTAINER_DIALOG_STYLESHEET
from cleverpgp.ui.icons import line_icon
from cleverpgp.ui.screen_bounds import install_screen_bounds


class DiskInfoDialog(QDialog):
    """Compact read-only information window for an already mounted disk."""

    def __init__(self, info: MountedDiskInfo, parent: object = None) -> None:
        super().__init__(parent)
        self.info = info
        self.setWindowTitle("Сведения о диске — Clever PGP")
        self.setWindowIcon(line_icon("vault", "#38bdf8"))
        self.setMinimumSize(420, 320)
        self.resize(700, 660)
        self.setStyleSheet(CONTAINER_DIALOG_STYLESHEET + _INFO_STYLESHEET)
        self._build_ui()

    def _build_ui(self) -> None:
        outer = scrollable_dialog_layout(self)
        outer.setContentsMargins(32, 28, 32, 28)
        outer.setSpacing(18)

        header = QHBoxLayout()
        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        badge = QLabel("ЗАЩИЩЁННЫЙ ДИСК")
        badge.setObjectName("badge")
        header.addWidget(brand)
        header.addStretch()
        header.addWidget(badge)
        outer.addLayout(header)

        title_row = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(line_icon("vault", "#38bdf8").pixmap(36, 36))
        title = QLabel("Сведения о подключённом диске")
        title.setObjectName("title")
        title_row.addWidget(icon)
        title_row.addWidget(title)
        title_row.addStretch()
        outer.addLayout(title_row)

        details = QFrame()
        details.setObjectName("storageCard")
        details.setMinimumHeight(160)
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(20, 17, 20, 17)
        details_layout.setSpacing(11)
        details_layout.addLayout(
            self._detail_row("Диск", f"{self.info.drive}\\")
        )
        details_layout.addLayout(
            self._detail_row("Тип подключения", tr(self.info.backend))
        )
        details_layout.addLayout(
            self._detail_row("Файловая система", self.info.file_system)
        )
        details_layout.addLayout(
            self._detail_row("Общая ёмкость", _format_bytes(self.info.capacity))
        )
        details_layout.addLayout(
            self._detail_row("Свободно", _format_bytes(self.info.free_space))
        )
        outer.addWidget(details)

        usage_percent = min(
            100,
            round(self.info.used_space / self.info.capacity * 100),
        )
        usage_title = QLabel(
            tr(
                "Использовано: {used} из {total}",
                used=_format_bytes(self.info.used_space),
                total=_format_bytes(self.info.capacity),
            )
        )
        usage_title.setObjectName("fieldTitle")
        outer.addWidget(usage_title)
        usage = QProgressBar()
        usage.setRange(0, 100)
        usage.setValue(usage_percent)
        usage.setFormat(tr("{percent}% занято", percent=usage_percent))
        outer.addWidget(usage)

        protection = QFrame()
        protection.setObjectName("sizeCard")
        protection.setMinimumHeight(175)
        protection_layout = QVBoxLayout(protection)
        protection_layout.setContentsMargins(20, 17, 20, 17)
        protection_layout.setSpacing(7)
        protection_title = QLabel("Метод защиты")
        protection_title.setObjectName("fieldTitle")
        protection_caption, protection_detail = _protection_text(
            self.info.algorithm
        )
        protection_name = QLabel(protection_caption)
        protection_name.setObjectName("protectionName")
        protection_description = QLabel(protection_detail)
        protection_description.setObjectName("muted")
        protection_description.setWordWrap(True)
        protection_layout.addWidget(protection_title)
        protection_layout.addWidget(protection_name)
        protection_layout.addWidget(protection_description)
        outer.addWidget(protection)

        note = QLabel(
            "Окно содержит только сведения об уже открытом диске. Пароль, "
            "биометрические данные и криптографические ключи не отображаются."
        )
        note.setObjectName("hint")
        note.setWordWrap(True)
        outer.addWidget(note)
        outer.addStretch()

        localize_widget_tree(self)

    @staticmethod
    def _detail_row(caption: str, value: str) -> QHBoxLayout:
        row = QHBoxLayout()
        name = QLabel(caption)
        name.setObjectName("muted")
        result = QLabel(value)
        result.setObjectName("detailValue")
        result.setMinimumWidth(240)
        result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        result.setAlignment(Qt.AlignmentFlag.AlignRight)
        row.addWidget(name)
        row.addStretch()
        row.addWidget(result)
        return row


class DiskInfoErrorDialog(QDialog):
    def __init__(self, message: str, parent: object = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Clever PGP")
        self.setWindowIcon(line_icon("shield", "#38bdf8"))
        self.setMinimumWidth(360)
        self.setStyleSheet(CONTAINER_DIALOG_STYLESHEET)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 26, 30, 30)
        layout.setSpacing(14)
        title = QLabel("Не удалось показать сведения о диске")
        title.setObjectName("title")
        detail = QLabel(str(message))
        detail.setObjectName("hint")
        detail.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(detail)
        localize_widget_tree(self)


def run_disk_info_dialog(drive: str) -> int:
    application = QApplication.instance()
    if application is None:
        application = QApplication([APP_NAME])
    application.setApplicationName(APP_NAME)
    application.setOrganizationName(ORGANIZATION_NAME)
    application.setWindowIcon(line_icon("shield", "#38bdf8"))
    install_screen_bounds(application)

    try:
        repository = ProfileRepository(database_path())
        repository.initialize()
        set_language(repository.get_setting("language"))
        info = inspect_mounted_cleverpgp_disk(drive)
    except (BioPGPError, OSError, TypeError, ValueError) as error:
        DiskInfoErrorDialog(str(error)).exec()
        return 1
    DiskInfoDialog(info).exec()
    return 0


def _format_bytes(size: int) -> str:
    units = (
        ("ТБ", 1024**4),
        ("ГБ", 1024**3),
        ("МБ", 1024**2),
        ("КБ", 1024),
    )
    for unit, factor in units:
        if size >= factor:
            value = size / factor
            formatted = f"{value:.2f}".rstrip("0").rstrip(".")
            return f"{formatted} {tr(unit)}"
    return tr("{size} байт", size=size)


def _protection_text(algorithm: str | None) -> tuple[str, str]:
    if algorithm == AES256_GCM:
        return (
            "AES-256-GCM",
            "Каждый логический адрес получает независимый подключ. Блоки "
            "зашифровываются с 256-битным ключом и кодом аутентификации; "
            "адрес блока и служебный контекст также контролируются. Повреждение, "
            "подмена или перестановка шифротекста обнаруживаются при чтении.",
        )
    if algorithm == XCHACHA20_POLY1305:
        return (
            "XChaCha20-Poly1305",
            "Каждый блок использует независимый 192-битный одноразовый параметр "
            "и код аутентификации. Адрес блока и служебный контекст включены в "
            "контроль целостности, поэтому повреждение, подмена или перестановка "
            "шифротекста обнаруживаются при чтении.",
        )
    return (
        "Аутентифицированное блочное шифрование",
        "Каждый блок преобразуется независимо и связан со своим адресом. "
        "При чтении проверяется целостность, поэтому повреждение, подмена "
        "или перестановка зашифрованных блоков обнаруживаются.",
    )


_INFO_STYLESHEET = """
QLabel#detailValue {
    color: #e0f2fe;
    font-weight: 650;
}
QLabel#protectionName {
    color: #7dd3fc;
    font-size: 16px;
    font-weight: 700;
}
QProgressBar {
    min-height: 18px;
    border: 1px solid #334155;
    border-radius: 9px;
    background: #0f172a;
    color: #e0f2fe;
    text-align: center;
}
QProgressBar::chunk {
    border-radius: 8px;
    background: #0284c7;
}
"""
