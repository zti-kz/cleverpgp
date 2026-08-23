from __future__ import annotations

import sys
import time

import cv2
import numpy as np
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QCloseEvent, QImage, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
)

from biopgp.biometrics.face_engine import FaceAnalysis, FaceEngine
from biopgp.biometrics.liveness import HeadTurnLiveness, LivenessStage
from biopgp.biometrics.service import BiometricService, BiometricVerificationContext
from biopgp.core.errors import BioPGPError
from biopgp.core.profile_service import UnlockedSession
from biopgp.localization import localize_widget_tree, tr
from biopgp.ui.container_dialog import CONTAINER_DIALOG_STYLESHEET


class CameraDialog(QDialog):
    def __init__(self, title: str, instruction: str, parent=None) -> None:
        super().__init__(parent)
        self.capture: cv2.VideoCapture | None = None
        self.engine: FaceEngine | None = None
        self.timer = QTimer(self)
        self.timer.setInterval(90)
        self.timer.timeout.connect(self._process_frame)
        self._started = False

        self.setWindowTitle(title)
        self.setMinimumSize(420, 360)
        self.resize(760, 680)
        self.setModal(True)
        self.setStyleSheet(CONTAINER_DIALOG_STYLESHEET)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)
        heading = QLabel(title)
        heading.setObjectName("title")
        layout.addWidget(heading)
        explanation = QLabel(instruction)
        explanation.setWordWrap(True)
        explanation.setObjectName("muted")
        layout.addWidget(explanation)

        self.preview = QLabel("Подготовка локальной камеры…")
        self.preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview.setMinimumSize(320, 180)
        self.preview.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        self.preview.setStyleSheet(
            "background: #071426; border: 1px solid #29405f; "
            "border-radius: 16px; color: #9fb2ca;"
        )
        layout.addWidget(self.preview, 1)

        self.status = QLabel("Подготовка моделей лица…")
        self.status.setWordWrap(True)
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        actions = QHBoxLayout()
        actions.addStretch()
        self.cancel_button = QPushButton("Отмена")
        self.cancel_button.clicked.connect(self.reject)
        actions.addWidget(self.cancel_button)
        layout.addLayout(actions)
        localize_widget_tree(self)
        QTimer.singleShot(0, self._initialize_camera)

    def _initialize_camera(self) -> None:
        if self._started:
            return
        self._started = True
        try:
            self._prepare_operation()
            self.engine = FaceEngine()
            backend = cv2.CAP_DSHOW if sys.platform == "win32" else cv2.CAP_ANY
            self.capture = cv2.VideoCapture(0, backend)
            if not self.capture.isOpened():
                raise RuntimeError("Камера не найдена или занята другой программой.")
            self.capture.set(cv2.CAP_PROP_FRAME_WIDTH, 960)
            self.capture.set(cv2.CAP_PROP_FRAME_HEIGHT, 540)
            self.status.setText(tr("Смотрите прямо в камеру"))
            self.timer.start()
        except (BioPGPError, OSError, RuntimeError, cv2.error) as error:
            self._show_failure(str(error))

    def _prepare_operation(self) -> None:
        pass

    def _process_frame(self) -> None:
        raise NotImplementedError

    def _read_frame(self) -> np.ndarray | None:
        if self.capture is None:
            return None
        ok, frame = self.capture.read()
        if not ok or frame is None:
            self._show_failure("Не удалось получить изображение с камеры.")
            return None
        return frame

    def _show_preview(self, frame: np.ndarray, analysis: FaceAnalysis) -> None:
        display = frame.copy()
        if analysis.face is not None:
            x, y, width, height = (int(value) for value in analysis.face[:4])
            color = (181, 224, 82) if analysis.usable else (72, 120, 245)
            cv2.rectangle(display, (x, y), (x + width, y + height), color, 3)
        rgb = cv2.cvtColor(display, cv2.COLOR_BGR2RGB)
        height, width, channels = rgb.shape
        image = QImage(
            rgb.data,
            width,
            height,
            channels * width,
            QImage.Format.Format_RGB888,
        ).copy()
        pixmap = QPixmap.fromImage(image).scaled(
            self.preview.size(),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.preview.setPixmap(pixmap)

    def _show_failure(self, message: str) -> None:
        self.timer.stop()
        self.status.setText(tr(message))
        self.status.setObjectName("error")
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)
        self.cancel_button.setText(tr("Закрыть"))
        self._release_camera()

    def _release_camera(self) -> None:
        self.timer.stop()
        if self.capture is not None:
            self.capture.release()
            self.capture = None

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        self._release_camera()
        event.accept()

    def done(self, result: int) -> None:
        self._release_camera()
        super().done(result)


class FaceVerificationDialog(CameraDialog):
    def __init__(self, service: BiometricService, parent=None) -> None:
        self.service = service
        self.context: BiometricVerificationContext | None = None
        self.liveness = HeadTurnLiveness()
        self.session: UnlockedSession | None = None
        self.comparison_attempts = 0
        super().__init__(
            "Разблокировка по лицу",
            "Проверка выполняется локально. Поверните голову по подсказке — "
            "это защищает от использования фотографии.",
            parent,
        )

    def _prepare_operation(self) -> None:
        self.context = self.service.begin_verification()

    def _process_frame(self) -> None:
        frame = self._read_frame()
        if frame is None or self.engine is None or self.context is None:
            return
        try:
            analysis = self.engine.analyze(frame, extract_embedding=False)
            stage = self.liveness.update(analysis.yaw_ratio, analysis.usable)
            self._show_preview(frame, analysis)
            self.progress.setValue(self.liveness.progress)
            if not analysis.usable:
                self.status.setText(tr(analysis.message))
                return
            if stage is LivenessStage.FAILED:
                self._show_failure("Время проверки истекло. Повторите попытку.")
                return
            if stage is not LivenessStage.COMPLETE:
                self.status.setText(tr(self.liveness.prompt))
                return

            self.status.setText(tr("Сопоставление лица…"))
            comparison = self.engine.analyze(frame, extract_embedding=True)
            if comparison.embedding is None:
                return
            score = FaceEngine.cosine(self.context.template, comparison.embedding)
            if score < self.context.threshold:
                self.comparison_attempts += 1
                self.status.setText(tr("Лицо не совпало. Смотрите прямо в камеру."))
                if self.comparison_attempts >= 10:
                    self._show_failure("Лицо не прошло проверку Clever PGP.")
                return

            self.session = self.context.unlock(score, liveness_passed=True)
            self.context = None
            self.timer.stop()
            self.progress.setValue(100)
            self.status.setText(tr("Лицо подтверждено"))
            self.status.setObjectName("success")
            QTimer.singleShot(250, self.accept)
        except (BioPGPError, ValueError, cv2.error) as error:
            self._show_failure(str(error))

    def done(self, result: int) -> None:
        if self.context is not None:
            self.context.close()
            self.context = None
        super().done(result)


class FaceEnrollmentDialog(CameraDialog):
    REQUIRED_SAMPLES = 5

    def __init__(self, parent=None) -> None:
        self.liveness = HeadTurnLiveness()
        self.samples: list[np.ndarray] = []
        self.template: np.ndarray | None = None
        self.last_sample_at = 0.0
        super().__init__(
            "Регистрация лица",
            "Сначала пройдите проверку движения, затем смотрите прямо в камеру. "
            "Биометрический шаблон останется зашифрованным на этом компьютере.",
            parent,
        )

    def _process_frame(self) -> None:
        frame = self._read_frame()
        if frame is None or self.engine is None:
            return
        try:
            extract = self.liveness.stage is LivenessStage.COMPLETE
            analysis = self.engine.analyze(frame, extract_embedding=extract)
            self._show_preview(frame, analysis)
            if self.liveness.stage is not LivenessStage.COMPLETE:
                stage = self.liveness.update(analysis.yaw_ratio, analysis.usable)
                self.progress.setValue(self.liveness.progress // 2)
                if stage is LivenessStage.FAILED:
                    self._show_failure("Время проверки истекло. Повторите регистрацию.")
                elif analysis.usable:
                    self.status.setText(tr(self.liveness.prompt))
                else:
                    self.status.setText(tr(analysis.message))
                return

            if not analysis.usable or analysis.embedding is None:
                self.status.setText(tr(analysis.message))
                return
            if analysis.yaw_ratio is None or abs(analysis.yaw_ratio) > 0.12:
                self.status.setText(tr("Смотрите прямо в камеру"))
                return
            now = time.monotonic()
            if now - self.last_sample_at < 0.35:
                return
            self.last_sample_at = now
            self.samples.append(analysis.embedding.copy())
            count = len(self.samples)
            self.status.setText(
                tr(
                    "Сбор образцов: {count} из {total}",
                    count=count,
                    total=self.REQUIRED_SAMPLES,
                )
            )
            self.progress.setValue(50 + 50 * count // self.REQUIRED_SAMPLES)
            if count >= self.REQUIRED_SAMPLES:
                self.template = FaceEngine.aggregate(self.samples)
                self.timer.stop()
                self.status.setText(tr("Лицо зарегистрировано"))
                self.status.setObjectName("success")
                QTimer.singleShot(250, self.accept)
        except (BioPGPError, ValueError, cv2.error) as error:
            self._show_failure(str(error))

    def done(self, result: int) -> None:
        for sample in self.samples:
            sample.fill(0)
        self.samples.clear()
        super().done(result)
