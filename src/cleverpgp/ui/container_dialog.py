from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QStandardPaths
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from cleverpgp.core.block_container import (
    CONTAINER_SUFFIX,
    BlockVaultContainer as EncryptedContainer,
)
from cleverpgp.core.errors import ValidationError
from cleverpgp.core.disk_crypto import (
    DEFAULT_DISK_ALGORITHM,
    XCHACHA20_POLY1305,
    available_disk_ciphers,
)
from cleverpgp.core.winspd import MIN_HIDDEN_WINDOWS_COVER_CAPACITY
from cleverpgp.localization import localize_widget_tree, tr
from cleverpgp.ui.adaptive import ResponsiveBox
from cleverpgp.ui.icons import line_icon
from cleverpgp.ui.password_generator import create_password_generator_button

MEBIBYTE = 1024 * 1024
GIBIBYTE = 1024 * MEBIBYTE
TEBIBYTE = 1024 * GIBIBYTE
PEBIBYTE = 1024 * TEBIBYTE
EXBIBYTE = 1024 * PEBIBYTE
MINIMUM_CAPACITY = MEBIBYTE
DEFAULT_CAPACITY = 20 * MEBIBYTE
DISK_BACKEND_WINDOWS = "windows"
DISK_BACKEND_WINFSP = "winfsp"
VOLUME_KIND_NORMAL = "normal"
VOLUME_KIND_HIDDEN = "hidden"
MINIMUM_DISK_PASSWORD_LENGTH = 12


def disk_algorithm_caption(identifier: str) -> str:
    if identifier == XCHACHA20_POLY1305:
        return tr("XChaCha20-Poly1305 — переносимый (рекомендуется)")
    return tr("AES-256-GCM — аппаратно ускоряемый")


def disk_algorithm_description(identifier: str) -> str:
    if identifier == XCHACHA20_POLY1305:
        return tr(
            "Потоковое преобразование с расширенным 192-битным одноразовым "
            "параметром и кодом аутентификации. Эффективно работает программно "
            "и одинаково доступно в Windows и Ubuntu."
        )
    return tr(
        "Симметричное блочное преобразование с 256-битным ключом в режиме "
        "аутентифицированного шифрования. Использует аппаратное ускорение "
        "процессора; диск требует такой поддержки и на другом компьютере."
    )


class ContainerCreationDialog(QDialog):
    def __init__(
        self,
        parent: object = None,
        *,
        minimum_capacity: int = MINIMUM_CAPACITY,
        system_disk: bool = False,
        allow_backend_choice: bool = False,
        system_backend_available: bool = True,
        winfsp_backend_available: bool = True,
        hidden_volume_available: bool = False,
    ) -> None:
        super().__init__(parent)
        if minimum_capacity < MINIMUM_CAPACITY:
            raise ValueError("Minimum capacity must be at least 1 MiB.")
        self._base_minimum_capacity = minimum_capacity
        self._minimum_capacity = minimum_capacity
        self._allow_backend_choice = allow_backend_choice
        self._system_backend_available = system_backend_available
        self._winfsp_backend_available = winfsp_backend_available
        self._hidden_volume_available = hidden_volume_available
        self._system_disk = (
            system_disk
            if not allow_backend_choice
            else system_backend_available
        )
        self._selected_path: Path | None = None
        self._selected_capacity = max(DEFAULT_CAPACITY, self._minimum_capacity)
        self._maximum_capacity = self._selected_capacity
        self._capacity_choices = [self._minimum_capacity, self._selected_capacity]
        self._current_path: Path | None = None
        self.setWindowTitle("Новый зашифрованный диск — Clever PGP")
        self.setMinimumSize(560, 360)
        self.resize(
            1100,
            920
            if self._hidden_volume_available
            else 880
            if self._allow_backend_choice
            else (850 if self._system_disk else 760),
        )
        self.setStyleSheet(CONTAINER_DIALOG_STYLESHEET)
        self._build_ui()

    @property
    def container_path(self) -> Path:
        if self._selected_path is not None:
            return self._selected_path
        return self._normalized_path()

    @property
    def data_capacity(self) -> int:
        return self._selected_capacity

    @property
    def volume_label(self) -> str:
        return self.label_input.text().strip() or "Clever PGP"

    @property
    def file_system(self) -> str:
        if not self._system_disk:
            return "NTFS"
        selected = str(self.file_system_input.currentData() or "NTFS").upper()
        return selected if selected in ("NTFS", "EXFAT") else "NTFS"

    @property
    def system_disk(self) -> bool:
        return self._system_disk

    @property
    def disk_backend(self) -> str:
        return (
            DISK_BACKEND_WINDOWS
            if self._system_disk
            else DISK_BACKEND_WINFSP
        )

    @property
    def hidden_volume(self) -> bool:
        return bool(
            self._hidden_volume_available
            and self._system_disk
            and self.volume_kind_input.currentData() == VOLUME_KIND_HIDDEN
        )

    @property
    def disk_algorithm(self) -> str:
        selected = str(
            self.algorithm_input.currentData() or DEFAULT_DISK_ALGORITHM
        )
        return XCHACHA20_POLY1305 if self.hidden_volume else selected

    @property
    def disk_password(self) -> str:
        return self.password_input.text()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        scroll = QScrollArea()
        scroll.setObjectName("dialogScroll")
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        # Keep transient Windows scrollbars away from controls and wrapped
        # text on compact displays.
        scroll.setViewportMargins(0, 0, 24, 12)
        body = QWidget()
        body.setObjectName("dialogBody")
        body.setMinimumSize(0, 0)
        body.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )
        outer = QVBoxLayout(body)
        outer.setContentsMargins(28, 20, 28, 10)
        outer.setSpacing(12)
        scroll.setWidget(body)
        root.addWidget(scroll, 1)

        brand_row = QHBoxLayout()
        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        badge = QLabel("ЗАШИФРОВАННЫЙ ДИСК")
        badge.setObjectName("badge")
        brand_row.addWidget(brand)
        brand_row.addStretch()
        brand_row.addWidget(badge)
        outer.addLayout(brand_row)

        title = QLabel("Создание защищённого контейнера")
        title.setObjectName("title")
        title.setWordWrap(True)
        subtitle = QLabel(
            "После подключения контейнер появится в Проводнике как обычный диск. "
            "Файлы внутри шифруются автоматически."
        )
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        outer.addWidget(title)
        outer.addWidget(subtitle)

        top_option_cards: list[QFrame] = []
        if self._allow_backend_choice:
            backend_card = QFrame()
            backend_card.setObjectName("backendCard")
            backend_layout = QVBoxLayout(backend_card)
            backend_layout.setContentsMargins(16, 14, 16, 14)
            backend_layout.setSpacing(8)
            backend_title = QLabel("Тип зашифрованного диска")
            backend_title.setObjectName("fieldTitle")
            self.backend_input = QComboBox()
            self.backend_input.setObjectName("diskBackendInput")
            if self._system_backend_available:
                self.backend_input.addItem(
                    "Виртуальный диск Windows — быстрый (рекомендуется)",
                    DISK_BACKEND_WINDOWS,
                )
            if self._winfsp_backend_available:
                self.backend_input.addItem(
                    "Универсальный диск Clever PGP",
                    DISK_BACKEND_WINFSP,
                )
            self.backend_description = QLabel()
            self.backend_description.setObjectName("muted")
            self.backend_description.setWordWrap(True)
            backend_layout.addWidget(backend_title)
            backend_layout.addWidget(self.backend_input)
            backend_layout.addWidget(self.backend_description)
            top_option_cards.append(backend_card)

        if self._hidden_volume_available:
            self.volume_kind_card = QFrame()
            self.volume_kind_card.setObjectName("backendCard")
            kind_layout = QVBoxLayout(self.volume_kind_card)
            kind_layout.setContentsMargins(16, 14, 16, 14)
            kind_layout.setSpacing(8)
            kind_title = QLabel("Структура зашифрованного диска")
            kind_title.setObjectName("fieldTitle")
            self.volume_kind_input = QComboBox()
            self.volume_kind_input.setObjectName("volumeKindInput")
            self.volume_kind_input.addItem(
                "Обычный зашифрованный диск",
                VOLUME_KIND_NORMAL,
            )
            self.volume_kind_input.addItem(
                "Скрытый диск внутри внешнего",
                VOLUME_KIND_HIDDEN,
            )
            self.volume_kind_description = QLabel()
            self.volume_kind_description.setObjectName("muted")
            self.volume_kind_description.setWordWrap(True)
            kind_layout.addWidget(kind_title)
            kind_layout.addWidget(self.volume_kind_input)
            kind_layout.addWidget(self.volume_kind_description)
            top_option_cards.append(self.volume_kind_card)

        algorithm_card = QFrame()
        algorithm_card.setObjectName("backendCard")
        algorithm_layout = QVBoxLayout(algorithm_card)
        algorithm_layout.setContentsMargins(16, 12, 16, 12)
        algorithm_layout.setSpacing(6)
        algorithm_title = QLabel("Метод шифрования диска")
        algorithm_title.setObjectName("fieldTitle")
        self.algorithm_input = QComboBox()
        self.algorithm_input.setObjectName("diskAlgorithmInput")
        for cipher in available_disk_ciphers():
            self.algorithm_input.addItem(
                disk_algorithm_caption(cipher.identifier),
                cipher.identifier,
            )
        self.algorithm_description = QLabel()
        self.algorithm_description.setObjectName("muted")
        self.algorithm_description.setWordWrap(True)
        algorithm_layout.addWidget(algorithm_title)
        algorithm_layout.addWidget(self.algorithm_input)
        algorithm_layout.addWidget(self.algorithm_description)
        self.format_card: QFrame | None = None
        if self._system_disk or self._allow_backend_choice:
            self.format_card = QFrame()
            self.format_card.setObjectName("formatCard")
            format_layout = QVBoxLayout(self.format_card)
            format_layout.setContentsMargins(16, 12, 16, 12)
            format_layout.setSpacing(6)
            format_title = QLabel("Файловая система")
            format_title.setObjectName("fieldTitle")
            self.file_system_input = QComboBox()
            self.file_system_input.setObjectName("fileSystemInput")
            self.file_system_input.addItem(
                "NTFS — для Windows (рекомендуется)", "NTFS"
            )
            self.file_system_input.addItem(
                "exFAT — для совместимости", "EXFAT"
            )
            self.file_system_description = QLabel()
            self.file_system_description.setObjectName("muted")
            self.file_system_description.setWordWrap(True)
            self.file_system_input.currentIndexChanged.connect(
                self._update_file_system_description
            )
            format_layout.addWidget(format_title)
            format_layout.addWidget(self.file_system_input)
            format_layout.addWidget(self.file_system_description)

        if top_option_cards:
            self.top_options = ResponsiveBox(
                top_option_cards,
                breakpoint=900,
                spacing=12,
            )
            self.top_options.setObjectName("topDiskOptions")
            outer.addWidget(self.top_options)
        bottom_cards = (
            (algorithm_card, self.format_card)
            if self.format_card is not None
            else (algorithm_card,)
        )
        self.bottom_options = ResponsiveBox(
            bottom_cards,
            breakpoint=900,
            spacing=12,
        )
        self.bottom_options.setObjectName("bottomDiskOptions")
        outer.addWidget(self.bottom_options)

        path_title = QLabel("Где сохранить контейнер")
        path_title.setObjectName("fieldTitle")
        outer.addWidget(path_title)
        path_row = QHBoxLayout()
        self.path_input = QLineEdit(str(self._default_path()))
        self.path_input.setPlaceholderText("Путь к файлу .cpgv")
        browse_button = QPushButton("Обзор…")
        browse_button.setIcon(line_icon("folder"))
        browse_button.clicked.connect(self._browse)
        path_row.addWidget(self.path_input, 1)
        path_row.addWidget(browse_button)
        outer.addLayout(path_row)

        storage_card = QFrame()
        storage_card.setObjectName("storageCard")
        storage_layout = QVBoxLayout(storage_card)
        storage_layout.setContentsMargins(16, 12, 16, 12)
        storage_layout.setSpacing(4)
        self.storage_location = QLabel()
        self.storage_location.setObjectName("storageTitle")
        self.storage_space = QLabel()
        self.storage_space.setObjectName("muted")
        self.storage_space.setWordWrap(True)
        self.storage_warning = QLabel()
        self.storage_warning.setObjectName("capacityWarning")
        self.storage_warning.setWordWrap(True)
        self.storage_warning.hide()
        storage_layout.addWidget(self.storage_location)
        storage_layout.addWidget(self.storage_space)
        storage_layout.addWidget(self.storage_warning)
        outer.addWidget(storage_card)

        size_card = QFrame()
        size_card.setObjectName("sizeCard")
        shadow = QGraphicsDropShadowEffect(size_card)
        shadow.setBlurRadius(28)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(2, 132, 199, 70))
        size_card.setGraphicsEffect(shadow)
        size_layout = QVBoxLayout(size_card)
        size_layout.setContentsMargins(20, 16, 20, 16)
        size_layout.setSpacing(8)

        size_header = QHBoxLayout()
        size_caption = QLabel("Ёмкость зашифрованного диска")
        size_caption.setObjectName("fieldTitle")
        size_caption.setWordWrap(True)
        self.size_value = QLabel()
        self.size_value.setObjectName("sizeValue")
        size_header.addWidget(size_caption)
        size_header.addStretch()
        size_header.addWidget(self.size_value)
        size_layout.addLayout(size_header)

        slider_instruction = QLabel(
            "Перемещайте ползунок, чтобы выбрать ёмкость диска."
        )
        slider_instruction.setObjectName("muted")
        slider_instruction.setWordWrap(True)
        size_layout.addWidget(slider_instruction)

        self.size_slider = QSlider(Qt.Orientation.Horizontal)
        self.size_slider.setObjectName("capacitySlider")
        self.size_slider.setRange(0, 1)
        self.size_slider.setSingleStep(1)
        self.size_slider.setPageStep(20)
        self.size_slider.setTracking(True)
        size_layout.addWidget(self.size_slider)

        scale_row = QHBoxLayout()
        self.minimum_size_label = QLabel()
        self.minimum_size_label.setObjectName("scaleLabel")
        self.maximum_size_label = QLabel()
        self.maximum_size_label.setObjectName("scaleLabel")
        self.maximum_size_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        scale_row.addWidget(self.minimum_size_label)
        scale_row.addStretch()
        scale_row.addWidget(self.maximum_size_label)
        size_layout.addLayout(scale_row)

        self.size_hint = QLabel()
        self.size_hint.setObjectName("hint")
        self.size_hint.setWordWrap(True)
        size_layout.addWidget(self.size_hint)
        no_limit = QLabel(
            "Максимальный размер рассчитывается по свободному месту именно на "
            "выбранном накопителе."
        )
        no_limit.setObjectName("muted")
        no_limit.setWordWrap(True)
        size_layout.addWidget(no_limit)
        outer.addWidget(size_card)

        self.password_card = QFrame()
        self.password_card.setObjectName("storageCard")
        password_layout = QVBoxLayout(self.password_card)
        password_layout.setContentsMargins(16, 12, 16, 12)
        password_layout.setSpacing(8)
        password_title = QLabel("Переносимый пароль диска")
        password_title.setObjectName("fieldTitle")
        password_description = QLabel(
            "Этот пароль открывает контейнер после переустановки и на другом "
            "компьютере. Он не хранится в программе и не является ключом "
            "шифрования данных."
        )
        password_description.setObjectName("muted")
        password_description.setWordWrap(True)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Не менее 12 символов")
        self.password_confirm_input = QLineEdit()
        self.password_confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_confirm_input.setPlaceholderText("Повторите пароль диска")
        password_layout.addWidget(password_title)
        password_layout.addWidget(password_description)
        password_layout.addWidget(self.password_input)
        password_layout.addWidget(self.password_confirm_input)
        password_layout.addWidget(
            create_password_generator_button(
                self.password_input,
                self.password_confirm_input,
                self.password_card,
            )
        )
        outer.addWidget(self.password_card)

        label_title = QLabel("Название диска")
        label_title.setObjectName("fieldTitle")
        self.label_input = QLineEdit("Clever PGP")
        self.label_input.setMaxLength(31)
        self.label_input.setPlaceholderText("Например, Личные документы")
        outer.addWidget(label_title)
        outer.addWidget(self.label_input)

        self.error_label = QLabel()
        self.error_label.setObjectName("error")
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        outer.addWidget(self.error_label)

        buttons = QHBoxLayout()
        cancel_button = QPushButton("Отмена")
        cancel_button.setIcon(line_icon("close"))
        cancel_button.clicked.connect(self.reject)
        self.create_button = QPushButton("Создать контейнер")
        self.create_button.setObjectName("primary")
        self.create_button.setIcon(line_icon("vault_add"))
        self.create_button.clicked.connect(self.accept)
        buttons.addStretch()
        buttons.addWidget(cancel_button)
        buttons.addWidget(self.create_button)
        button_bar = QWidget()
        button_bar.setObjectName("dialogButtonBar")
        button_bar.setLayout(buttons)
        buttons.setContentsMargins(28, 10, 28, 20)
        root.addWidget(button_bar)

        self.size_slider.valueChanged.connect(self._slider_changed)
        self.path_input.textChanged.connect(self._update_storage_summary)
        self.algorithm_input.currentIndexChanged.connect(
            self._update_algorithm_description
        )
        if self._allow_backend_choice:
            self.backend_input.currentIndexChanged.connect(
                self._update_backend_description
            )
        if self._hidden_volume_available:
            self.volume_kind_input.currentIndexChanged.connect(
                self._update_volume_kind
            )
        # Long translated entries must not define the minimum dialog width.
        # They remain fully available in the drop-down, while the selected
        # value is elided by Qt on genuinely small screens.
        for combo in self.findChildren(QComboBox):
            combo.setMinimumWidth(0)
            combo.setMinimumContentsLength(12)
            combo.setSizeAdjustPolicy(
                QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
            )
            combo.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Fixed,
            )
        localize_widget_tree(self)
        if self._system_disk or self._allow_backend_choice:
            self._update_file_system_description()
        if self._allow_backend_choice:
            self._update_backend_description()
        elif self._hidden_volume_available:
            self._update_volume_kind_availability()
        if self._hidden_volume_available:
            self._update_volume_kind()
        self._update_algorithm_description()
        self._update_storage_summary()

    def _update_backend_description(self, *_: object) -> None:
        selected = self.backend_input.currentData()
        self._system_disk = selected == DISK_BACKEND_WINDOWS
        if self.format_card is not None:
            self.format_card.setVisible(self._system_disk)
        if self._system_disk:
            description = (
                "Windows использует обычную файловую систему NTFS или exFAT и "
                "системное кэширование. Этот вариант лучше подходит для больших "
                "файлов, фильмов и повседневной работы."
            )
        else:
            description = (
                "Собственная файловая система Clever PGP сохраняет переносимый "
                "формат контейнера и используется как совместимый резервный вариант."
            )
        self.backend_description.setText(tr(description))
        if self._hidden_volume_available:
            self._update_volume_kind_availability()

    def _update_volume_kind_availability(self) -> None:
        self.volume_kind_card.setVisible(self._system_disk)
        if not self._system_disk:
            self.volume_kind_input.setCurrentIndex(0)

    def _update_volume_kind(self, *_: object) -> None:
        if self.hidden_volume:
            portable_index = self.algorithm_input.findData(XCHACHA20_POLY1305)
            if portable_index >= 0:
                self.algorithm_input.setCurrentIndex(portable_index)
            self.algorithm_input.setEnabled(False)
            self._minimum_capacity = max(
                self._base_minimum_capacity,
                MIN_HIDDEN_WINDOWS_COVER_CAPACITY,
            )
            description = (
                "Один файл .cpgv содержит внешний и скрытый диски. Какой диск "
                "откроется, определяется введённым паролем."
            )
        else:
            self.algorithm_input.setEnabled(self.algorithm_input.count() > 1)
            self._minimum_capacity = self._base_minimum_capacity
            description = (
                "Диск можно открыть локальным профилем или его собственным "
                "переносимым паролем."
            )
        self.password_card.setVisible(not self.hidden_volume)
        self.volume_kind_description.setText(tr(description))
        self._update_algorithm_description()
        if self._current_path is not None:
            self._update_storage_summary()

    def _update_algorithm_description(self, *_: object) -> None:
        if self.hidden_volume:
            description = (
                "Для внешней и скрытой областей используется переносимый метод "
                "с 192-битным одноразовым параметром. Это сохраняет единую "
                "проверенную структуру скрытого диска."
            )
        else:
            description = disk_algorithm_description(self.disk_algorithm)
        self.algorithm_description.setText(description)

    def _update_file_system_description(self, *_: object) -> None:
        if self.file_system == "EXFAT":
            description = (
                "Файловая система для обмена между Windows, Linux и другими "
                "системами. Не использует журналирование, поэтому чувствительнее "
                "к внезапному отключению. Встроенное Windows увеличение размера "
                "для exFAT не поддерживается."
            )
        else:
            description = (
                "Журналируемая файловая система Windows с поддержкой больших "
                "файлов, контроля доступа и восстановления метаданных после сбоя."
            )
        self.file_system_description.setText(tr(description))

    def accept(self) -> None:
        try:
            if self._allow_backend_choice and self.backend_input.count() == 0:
                raise ValueError(
                    "Компоненты зашифрованного диска не установлены."
                )
            path = self._normalized_path()
            if not path.parent.is_dir():
                raise ValueError("Выбранная папка не существует.")
            if path.exists():
                raise ValueError("Файл с таким именем уже существует. Выберите другое имя.")
            if not self.volume_label:
                raise ValueError("Введите название диска.")
            if not self.hidden_volume:
                if len(self.disk_password) < MINIMUM_DISK_PASSWORD_LENGTH:
                    raise ValueError(
                        "Пароль диска должен содержать не менее 12 символов."
                    )
                if self.disk_password != self.password_confirm_input.text():
                    raise ValueError("Пароли диска не совпадают.")
            capacity = self.data_capacity
            if self.hidden_volume and capacity < MIN_HIDDEN_WINDOWS_COVER_CAPACITY:
                raise ValueError(
                    "Увеличьте внешний диск, чтобы разместить внешнюю и "
                    "скрытую файловые системы."
                )
            _, maximum_capacity = EncryptedContainer.storage_space(path)
            if capacity > maximum_capacity:
                raise ValueError(
                    "Недостаточно свободного места на выбранном накопителе."
                )
        except (OSError, ValueError, ValidationError) as error:
            self.error_label.setText(tr(str(error)))
            self.error_label.show()
            return
        self._selected_path = path
        super().accept()

    def _browse(self) -> None:
        selected, _ = QFileDialog.getSaveFileName(
            self,
            tr("Сохранить контейнер Clever PGP"),
            self.path_input.text(),
            tr("Контейнер Clever PGP (*.cpgv)"),
        )
        if selected:
            self.path_input.setText(selected)
            self.error_label.hide()

    def _normalized_path(self) -> Path:
        raw_path = self.path_input.text().strip()
        if not raw_path:
            raise ValueError("Выберите место для контейнера.")
        path = Path(raw_path).expanduser()
        if path.suffix.lower() != CONTAINER_SUFFIX:
            path = path.with_name(path.name + CONTAINER_SUFFIX)
        return path.resolve()

    def _slider_changed(self, position: int) -> None:
        self._selected_capacity = self._slider_to_capacity(
            position
        )
        self._update_size_summary()
        if self._current_path is not None:
            self._update_create_state(
                self._current_path, self._maximum_capacity
            )

    def _update_size_summary(self) -> None:
        self.size_value.setText(self._format_capacity(self._selected_capacity))
        self.size_hint.setText(tr(
            "Контейнер резервирует выбранную ёмкость. Файл контейнера включает "
            "служебные криптографические данные и может быть немного больше "
            "указанного объёма."
        ))

    def _update_storage_summary(self, *_: object) -> None:
        self.storage_warning.hide()
        try:
            path = self._normalized_path()
            free_bytes, maximum_capacity = EncryptedContainer.storage_space(path)
        except (OSError, ValueError, ValidationError):
            self._current_path = None
            self.storage_location.setText(tr("Накопитель не выбран"))
            self.storage_space.setText(
                tr("Выберите существующую папку для контейнера.")
            )
            self.create_button.setEnabled(False)
            return

        self._current_path = path
        slider_maximum = max(self._minimum_capacity, maximum_capacity)
        self._configure_slider(slider_maximum)

        drive_name = path.anchor.rstrip("\\/") or str(path.parent)
        self.storage_location.setText(
            tr("Выбранный накопитель: {drive}", drive=drive_name)
        )
        self.storage_space.setText(
            tr(
                "Свободно: {free}. Максимальный размер контейнера: {maximum}.",
                free=self._format_bytes(free_bytes),
                maximum=self._format_bytes(maximum_capacity),
            )
        )
        self._update_create_state(path, maximum_capacity)

    def _update_create_state(self, path: Path, maximum_capacity: int) -> None:
        self.storage_warning.hide()
        if self._selected_capacity > maximum_capacity:
            self.storage_warning.setText(
                tr(
                    "Указанный размер превышает свободное место на выбранном накопителе."
                )
            )
            self.storage_warning.show()
            self.create_button.setEnabled(False)
            return
        if path.exists():
            self.storage_warning.setText(
                tr("Файл с таким именем уже существует. Выберите другое имя.")
            )
            self.storage_warning.show()
            self.create_button.setEnabled(False)
            return
        self.create_button.setEnabled(True)

    def _configure_slider(self, maximum_capacity: int) -> None:
        previous_capacity = min(self._selected_capacity, maximum_capacity)
        self._maximum_capacity = maximum_capacity
        self._capacity_choices = self._build_capacity_choices(
            maximum_capacity,
            minimum_capacity=self._minimum_capacity,
        )
        position = self._capacity_to_slider(previous_capacity, maximum_capacity)
        self.size_slider.blockSignals(True)
        self.size_slider.setRange(0, len(self._capacity_choices) - 1)
        self.size_slider.setValue(position)
        self.size_slider.blockSignals(False)
        self._selected_capacity = self._slider_to_capacity(position)
        self.minimum_size_label.setText(
            tr(
                "Минимум: {size}",
                size=self._format_capacity(self._minimum_capacity),
            )
        )
        self.maximum_size_label.setText(
            tr("Максимум: {size}", size=self._format_capacity(maximum_capacity))
        )
        self._update_size_summary()

    def _slider_to_capacity(self, position: int) -> int:
        index = max(0, min(len(self._capacity_choices) - 1, position))
        return self._capacity_choices[index]

    def _capacity_to_slider(self, capacity: int, maximum_capacity: int) -> int:
        target = max(self._minimum_capacity, min(maximum_capacity, capacity))
        return min(
            range(len(self._capacity_choices)),
            key=lambda index: abs(self._capacity_choices[index] - target),
        )

    @staticmethod
    def _build_capacity_choices(
        maximum_capacity: int,
        *,
        minimum_capacity: int = MINIMUM_CAPACITY,
    ) -> list[int]:
        maximum = max(minimum_capacity, maximum_capacity)
        choices = {minimum_capacity, maximum}
        for unit in (MEBIBYTE, GIBIBYTE, TEBIBYTE, PEBIBYTE, EXBIBYTE):
            for amount in range(1, 101):
                capacity = amount * unit
                if minimum_capacity <= capacity <= maximum:
                    choices.add(capacity)
            for amount in range(110, 1001, 10):
                capacity = amount * unit
                if minimum_capacity <= capacity <= maximum:
                    choices.add(capacity)
        return sorted(choices)

    @staticmethod
    def _format_capacity(capacity: int) -> str:
        for unit, factor in ((tr("ТБ"), TEBIBYTE), (tr("ГБ"), GIBIBYTE)):
            if capacity >= factor and capacity % factor == 0:
                return f"{capacity // factor} {unit}"
        return f"{capacity / MEBIBYTE:g} {tr('МБ')}"

    @staticmethod
    def _format_bytes(size: int) -> str:
        for unit, factor in (
            (tr("ТБ"), TEBIBYTE),
            (tr("ГБ"), GIBIBYTE),
            (tr("МБ"), MEBIBYTE),
        ):
            if size >= factor:
                value = size / factor
                formatted = f"{value:.2f}".rstrip("0").rstrip(".")
                return f"{formatted} {unit}"
        return f"{size} {tr('байт')}"

    @staticmethod
    def _default_path() -> Path:
        documents = QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.DocumentsLocation
        )
        base = Path(documents) if documents else Path.cwd()
        stem = tr("Защищённый диск")
        candidate = base / f"{stem}{CONTAINER_SUFFIX}"
        index = 2
        while candidate.exists():
            candidate = base / f"{stem} ({index}){CONTAINER_SUFFIX}"
            index += 1
        return candidate


CONTAINER_DIALOG_STYLESHEET = """
QDialog {
    background: #0b1220;
    color: #e5e7eb;
    font-family: "Segoe UI";
    font-size: 14px;
}
QWidget#dialogBody, QWidget#dialogButtonBar, QScrollArea#dialogScroll,
QScrollArea#dialogScroll > QWidget > QWidget {
    background: #0b1220;
}
QLabel { background: transparent; }
QLabel#brand { color: #7dd3fc; font-size: 23px; font-weight: 750; }
QLabel#badge {
    background: #0c4a6e;
    border: 1px solid #0369a1;
    border-radius: 10px;
    color: #bae6fd;
    font-size: 10px;
    font-weight: 700;
    padding: 5px 10px;
}
QLabel#title { color: #f8fafc; font-size: 24px; font-weight: 700; }
QLabel#muted { color: #94a3b8; }
QLabel#fieldTitle { color: #e2e8f0; font-weight: 650; }
QLabel#storageTitle { color: #bae6fd; font-weight: 650; }
QLabel#sizeValue { color: #7dd3fc; font-size: 28px; font-weight: 750; }
QLabel#scaleLabel { color: #64748b; font-size: 12px; }
QLabel#hint {
    background: #10233a;
    border-radius: 8px;
    color: #bae6fd;
    padding: 9px 11px;
}
QLabel#error {
    background: #3f151b;
    border: 1px solid #991b1b;
    border-radius: 8px;
    color: #fecaca;
    padding: 10px;
}
QLabel#capacityWarning {
    color: #fca5a5;
    padding-top: 4px;
}
QFrame#storageCard, QFrame#backendCard {
    background: #0d2135;
    border: 1px solid #1e4f70;
    border-radius: 10px;
}
QFrame#formatCard {
    background: #0d2135;
    border: 1px solid #1e4f70;
    border-radius: 10px;
}
QFrame#sizeCard {
    background: #111c2e;
    border: 1px solid #1e4f70;
    border-radius: 16px;
}
QLineEdit, QComboBox {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 9px;
    color: #f8fafc;
    min-height: 40px;
    padding: 0 12px;
    selection-background-color: #0284c7;
}
QLineEdit:focus, QComboBox:focus { border-color: #38bdf8; }
QComboBox::drop-down { border: 0; width: 34px; }
QComboBox QAbstractItemView {
    background: #0f172a;
    border: 1px solid #334155;
    color: #f8fafc;
    selection-background-color: #0369a1;
}
QPushButton {
    background: #1e293b;
    border: 1px solid #475569;
    border-radius: 9px;
    color: #f8fafc;
    min-height: 40px;
    padding: 0 18px;
    font-weight: 650;
}
QPushButton:hover { background: #334155; }
QPushButton#primary { background: #0284c7; border-color: #0ea5e9; }
QPushButton#primary:hover { background: #0369a1; }
QSlider#capacitySlider { min-height: 34px; }
QSlider#capacitySlider::groove:horizontal {
    background: #243247;
    border-radius: 4px;
    height: 8px;
}
QSlider#capacitySlider::sub-page:horizontal {
    background: #0ea5e9;
    border-radius: 4px;
}
QSlider#capacitySlider::handle:horizontal {
    background: #e0f2fe;
    border: 3px solid #0284c7;
    border-radius: 11px;
    height: 22px;
    width: 22px;
    margin: -8px 0;
}
QSlider#capacitySlider::handle:horizontal:hover {
    background: #ffffff;
    border-color: #38bdf8;
}
"""
