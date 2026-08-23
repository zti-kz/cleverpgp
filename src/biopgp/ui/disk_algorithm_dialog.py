from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from biopgp.core.disk_crypto import available_disk_ciphers, get_disk_cipher
from biopgp.localization import localize_widget_tree, tr
from biopgp.ui.container_dialog import (
    CONTAINER_DIALOG_STYLESHEET,
    ContainerCreationDialog,
    disk_algorithm_caption,
    disk_algorithm_description,
)
from biopgp.ui.icons import line_icon


class DiskAlgorithmChangeDialog(QDialog):
    """Select a new authenticated-encryption method for an ordinary disk."""

    def __init__(
        self,
        container_path: Path,
        current_algorithm: str,
        parent: object = None,
    ) -> None:
        super().__init__(parent)
        source = Path(container_path).expanduser().resolve()
        if not source.is_file():
            raise ValueError("Файл подключённого контейнера не найден.")
        self.container_path = source
        self.current_algorithm = get_disk_cipher(current_algorithm).identifier
        self.required_temporary_space = source.stat().st_size
        self.free_space = int(shutil.disk_usage(source.parent).free)

        self.setWindowTitle("Метод шифрования диска — Clever PGP")
        self.setMinimumWidth(680)
        self.resize(720, 590)
        self.setStyleSheet(CONTAINER_DIALOG_STYLESHEET)
        self._build_ui()

    @property
    def new_algorithm(self) -> str:
        value = self.algorithm_input.currentData()
        return str(value) if value is not None else self.current_algorithm

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 28)
        outer.setSpacing(16)

        brand_row = QHBoxLayout()
        brand = QLabel("Clever PGP")
        brand.setObjectName("brand")
        badge = QLabel("МЕТОД ШИФРОВАНИЯ")
        badge.setObjectName("badge")
        brand_row.addWidget(brand)
        brand_row.addStretch()
        brand_row.addWidget(badge)
        outer.addLayout(brand_row)

        title = QLabel("Изменение метода шифрования диска")
        title.setObjectName("title")
        description = QLabel(
            "Диск будет безопасно отключён. Каждый блок будет расшифрован, "
            "проверен и записан в новый временный образ с выбранным методом. "
            "Исходный контейнер заменяется только после полной проверки."
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
        path_label = QLabel(tr("Контейнер: {path}", path=self.container_path))
        path_label.setObjectName("storageTitle")
        path_label.setWordWrap(True)
        current_label = QLabel(
            tr(
                "Текущий метод: {algorithm}",
                algorithm=disk_algorithm_caption(self.current_algorithm),
            )
        )
        current_label.setObjectName("muted")
        space_label = QLabel(
            tr(
                "Нужно временно: {required}. Свободно: {free}.",
                required=ContainerCreationDialog._format_bytes(
                    self.required_temporary_space
                ),
                free=ContainerCreationDialog._format_bytes(self.free_space),
            )
        )
        space_label.setObjectName("muted")
        identity_layout.addWidget(path_label)
        identity_layout.addWidget(current_label)
        identity_layout.addWidget(space_label)
        outer.addWidget(identity_card)

        method_card = QFrame()
        method_card.setObjectName("backendCard")
        method_layout = QVBoxLayout(method_card)
        method_layout.setContentsMargins(18, 16, 18, 16)
        method_layout.setSpacing(10)
        method_title = QLabel("Новый метод")
        method_title.setObjectName("fieldTitle")
        self.algorithm_input = QComboBox()
        self.algorithm_input.setObjectName("algorithmChangeInput")
        for cipher in available_disk_ciphers():
            if cipher.identifier != self.current_algorithm:
                self.algorithm_input.addItem(
                    disk_algorithm_caption(cipher.identifier),
                    cipher.identifier,
                )
        self.algorithm_description = QLabel()
        self.algorithm_description.setObjectName("muted")
        self.algorithm_description.setWordWrap(True)
        self.algorithm_input.currentIndexChanged.connect(
            self._update_description
        )
        method_layout.addWidget(method_title)
        method_layout.addWidget(self.algorithm_input)
        method_layout.addWidget(self.algorithm_description)
        outer.addWidget(method_card)

        self.notice = QLabel()
        self.notice.setObjectName("hint")
        self.notice.setWordWrap(True)
        outer.addWidget(self.notice)

        self.convert_button = QPushButton("Изменить метод шифрования")
        self.convert_button.setObjectName("primary")
        self.convert_button.setIcon(line_icon("shield"))
        self.convert_button.clicked.connect(self.accept)
        button_row = QHBoxLayout()
        button_row.addStretch()
        button_row.addWidget(self.convert_button)
        outer.addLayout(button_row)

        localize_widget_tree(self)
        self._update_description()
        self._update_state()

    def _update_description(self, *_: object) -> None:
        if self.algorithm_input.count() == 0:
            self.algorithm_description.clear()
            return
        self.algorithm_description.setText(
            disk_algorithm_description(self.new_algorithm)
        )

    def _update_state(self) -> None:
        if self.algorithm_input.count() == 0:
            self.notice.setText(
                tr("На этом компьютере нет другого доступного метода шифрования.")
            )
            self.convert_button.setEnabled(False)
            return
        if self.free_space < self.required_temporary_space:
            self.notice.setText(
                tr(
                    "Недостаточно свободного места для безопасного временного "
                    "образа. Освободите место на накопителе контейнера."
                )
            )
            self.convert_button.setEnabled(False)
            return
        self.notice.setText(
            tr(
                "Во время преобразования нельзя закрывать окно или отключать "
                "компьютер. Кнопки будут заблокированы, а выполнение показано "
                "в процентах. Файловая система и пользовательские файлы сохраняются."
            )
        )
        self.convert_button.setEnabled(True)

    def accept(self) -> None:
        if not self.convert_button.isEnabled():
            return
        super().accept()


__all__ = ["DiskAlgorithmChangeDialog"]
