from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSlider,
    QVBoxLayout,
)

from biopgp.core.block_volume import (
    LOGICAL_BLOCK_SIZE,
    PHYSICAL_SLOT_SIZE,
)
from biopgp.localization import localize_widget_tree, tr
from biopgp.ui.container_dialog import (
    CONTAINER_DIALOG_STYLESHEET,
    ContainerCreationDialog,
)
from biopgp.ui.icons import line_icon


class ContainerResizeDialog(QDialog):
    """Modern grow-only capacity selector for a mounted Windows disk."""

    def __init__(
        self,
        container_path: Path,
        *,
        current_capacity: int,
        file_system: str,
        partition_growth_pending: bool = False,
        parent: object = None,
    ) -> None:
        super().__init__(parent)
        source = Path(container_path).expanduser().resolve()
        if not source.is_file():
            raise ValueError("Файл подключённого контейнера не найден.")
        if current_capacity <= 0 or current_capacity % LOGICAL_BLOCK_SIZE:
            raise ValueError("Текущий размер контейнера некорректен.")
        self.container_path = source
        self.current_capacity = current_capacity
        self.file_system = str(file_system).upper()
        self.partition_growth_pending = bool(partition_growth_pending)
        free_bytes = int(shutil.disk_usage(source.parent).free)
        additional_blocks = free_bytes // PHYSICAL_SLOT_SIZE
        self.maximum_capacity = (
            current_capacity + additional_blocks * LOGICAL_BLOCK_SIZE
        )
        self._capacity_choices = ContainerCreationDialog._build_capacity_choices(
            self.maximum_capacity,
            minimum_capacity=current_capacity,
        )
        self._selected_capacity = current_capacity

        self.setWindowTitle("Увеличение зашифрованного диска — Clever PGP")
        self.setMinimumWidth(650)
        self.resize(700, 610)
        self.setStyleSheet(CONTAINER_DIALOG_STYLESHEET)
        self._build_ui(free_bytes)

    @property
    def logical_capacity(self) -> int:
        return self._selected_capacity

    def _build_ui(self, free_bytes: int) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 28)
        outer.setSpacing(18)

        brand_row = QHBoxLayout()
        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        badge = QLabel("РАЗМЕР ДИСКА")
        badge.setObjectName("badge")
        brand_row.addWidget(brand)
        brand_row.addStretch()
        brand_row.addWidget(badge)
        outer.addLayout(brand_row)

        title = QLabel("Увеличение зашифрованного диска")
        title.setObjectName("title")
        description = QLabel(
            "Диск будет безопасно отключён, дополнен новыми защищёнными блоками "
            "и снова подключён. Существующие файлы и ключ тома сохраняются."
        )
        description.setObjectName("muted")
        description.setWordWrap(True)
        outer.addWidget(title)
        outer.addWidget(description)

        identity_card = QFrame()
        identity_card.setObjectName("storageCard")
        identity_layout = QVBoxLayout(identity_card)
        identity_layout.setContentsMargins(16, 12, 16, 12)
        identity_layout.setSpacing(5)
        path_label = QLabel(
            tr("Контейнер: {path}", path=self.container_path)
        )
        path_label.setObjectName("storageTitle")
        path_label.setWordWrap(True)
        file_system_label = QLabel(
            tr("Файловая система: {file_system}", file_system=self.file_system)
        )
        file_system_label.setObjectName("muted")
        free_label = QLabel(
            tr(
                "Свободно на накопителе: {free}",
                free=ContainerCreationDialog._format_bytes(free_bytes),
            )
        )
        free_label.setObjectName("muted")
        identity_layout.addWidget(path_label)
        identity_layout.addWidget(file_system_label)
        identity_layout.addWidget(free_label)
        outer.addWidget(identity_card)

        size_card = QFrame()
        size_card.setObjectName("sizeCard")
        shadow = QGraphicsDropShadowEffect(size_card)
        shadow.setBlurRadius(28)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(2, 132, 199, 70))
        size_card.setGraphicsEffect(shadow)
        size_layout = QVBoxLayout(size_card)
        size_layout.setContentsMargins(24, 22, 24, 22)
        size_layout.setSpacing(12)

        header = QHBoxLayout()
        caption = QLabel("Новый размер")
        caption.setObjectName("fieldTitle")
        self.size_value = QLabel()
        self.size_value.setObjectName("sizeValue")
        header.addWidget(caption)
        header.addStretch()
        header.addWidget(self.size_value)
        size_layout.addLayout(header)

        instruction = QLabel(
            "Перемещайте ползунок вправо, чтобы увеличить ёмкость диска."
        )
        instruction.setObjectName("muted")
        size_layout.addWidget(instruction)

        self.size_slider = QSlider(Qt.Orientation.Horizontal)
        self.size_slider.setObjectName("capacitySlider")
        self.size_slider.setRange(0, len(self._capacity_choices) - 1)
        self.size_slider.setValue(0)
        self.size_slider.setTracking(True)
        self.size_slider.valueChanged.connect(self._slider_changed)
        size_layout.addWidget(self.size_slider)

        scale = QHBoxLayout()
        self.current_size_label = QLabel(
            tr(
                "Текущий: {size}",
                size=ContainerCreationDialog._format_capacity(
                    self.current_capacity
                ),
            )
        )
        self.current_size_label.setObjectName("scaleLabel")
        self.maximum_size_label = QLabel(
            tr(
                "Доступно: {size}",
                size=ContainerCreationDialog._format_capacity(
                    self.maximum_capacity
                ),
            )
        )
        self.maximum_size_label.setObjectName("scaleLabel")
        self.maximum_size_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        scale.addWidget(self.current_size_label)
        scale.addStretch()
        scale.addWidget(self.maximum_size_label)
        size_layout.addLayout(scale)
        outer.addWidget(size_card)

        self.notice = QLabel()
        self.notice.setObjectName("hint")
        self.notice.setWordWrap(True)
        outer.addWidget(self.notice)

        self.resize_button = QPushButton("Увеличить диск")
        self.resize_button.setObjectName("primary")
        self.resize_button.setIcon(line_icon("vault_add"))
        self.resize_button.clicked.connect(self.accept)
        button_row = QHBoxLayout()
        button_row.addStretch()
        button_row.addWidget(self.resize_button)
        outer.addLayout(button_row)

        localize_widget_tree(self)
        self._update_state()

    def _slider_changed(self, position: int) -> None:
        index = max(0, min(len(self._capacity_choices) - 1, position))
        self._selected_capacity = self._capacity_choices[index]
        self._update_state()

    def _update_state(self) -> None:
        self.size_value.setText(
            ContainerCreationDialog._format_capacity(self._selected_capacity)
        )
        if self.file_system != "NTFS":
            self.notice.setText(
                tr(
                    "Windows не поддерживает безопасное увеличение exFAT без "
                    "переформатирования. Скопируйте данные в новый диск NTFS."
                )
            )
            self.resize_button.setEnabled(False)
            return
        if (
            self._selected_capacity == self.current_capacity
            and self.partition_growth_pending
        ):
            self.notice.setText(
                tr(
                    "Контейнер уже увеличен. Повторите только подтверждение "
                    "расширения NTFS в Windows."
                )
            )
            self.resize_button.setText(tr("Повторить расширение Windows"))
            self.resize_button.setEnabled(True)
            return
        if self.maximum_capacity <= self.current_capacity:
            self.notice.setText(
                tr("На накопителе недостаточно свободного места для увеличения.")
            )
            self.resize_button.setEnabled(False)
            return
        if self._selected_capacity == self.current_capacity:
            self.notice.setText(tr("Выберите новый размер больше текущего."))
            self.resize_button.setText(tr("Увеличить диск"))
            self.resize_button.setEnabled(False)
            return
        self.notice.setText(
            tr(
                "Уменьшение отключено для защиты данных. Во время увеличения "
                "кнопки и закрытие окна будут заблокированы, а прогресс будет "
                "показан в процентах."
            )
        )
        self.resize_button.setText(tr("Увеличить диск"))
        self.resize_button.setEnabled(True)

    def accept(self) -> None:
        if not self.resize_button.isEnabled():
            return
        super().accept()
