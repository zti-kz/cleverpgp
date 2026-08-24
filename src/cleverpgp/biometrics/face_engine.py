from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np

from cleverpgp.biometrics.model_assets import SFACE, YUNET, verify_all_models
from cleverpgp.core.errors import BiometricError, ValidationError

FACE_MATCH_THRESHOLD = 0.45
MINIMUM_FACE_SIZE = 120


@dataclass(slots=True)
class FaceAnalysis:
    face_count: int
    face: np.ndarray | None
    embedding: np.ndarray | None
    yaw_ratio: float | None
    usable: bool
    message: str


class FaceEngine:
    def __init__(self) -> None:
        paths = verify_all_models()
        try:
            self.detector = cv2.FaceDetectorYN.create(
                str(paths[YUNET.filename]), "", (320, 320), 0.9, 0.3, 5000
            )
            self.recognizer = cv2.FaceRecognizerSF.create(
                str(paths[SFACE.filename]), ""
            )
        except cv2.error as error:
            raise BiometricError(f"Не удалось загрузить модели лица: {error}") from error

    def analyze(self, frame: np.ndarray, *, extract_embedding: bool) -> FaceAnalysis:
        if frame.ndim != 3 or frame.shape[2] != 3:
            raise ValidationError("Кадр камеры имеет неподдерживаемый формат.")
        height, width = frame.shape[:2]
        self.detector.setInputSize((width, height))
        try:
            _, faces = self.detector.detect(frame)
        except cv2.error as error:
            raise BiometricError(f"Ошибка локального детектора лица: {error}") from error

        if faces is None or len(faces) == 0:
            return FaceAnalysis(0, None, None, None, False, "Лицо не найдено")
        if len(faces) != 1:
            return FaceAnalysis(
                len(faces), None, None, None, False, "В кадре должен быть один человек"
            )

        face = np.asarray(faces[0], dtype=np.float32)
        x, y, face_width, face_height = face[:4]
        if face_width < MINIMUM_FACE_SIZE or face_height < MINIMUM_FACE_SIZE:
            return FaceAnalysis(1, face, None, None, False, "Подойдите ближе к камере")

        center_x = x + face_width / 2
        center_y = y + face_height / 2
        if abs(center_x - width / 2) > width * 0.30 or abs(center_y - height / 2) > height * 0.32:
            return FaceAnalysis(1, face, None, None, False, "Расположите лицо по центру")

        x1 = max(0, int(x))
        y1 = max(0, int(y))
        x2 = min(width, int(x + face_width))
        y2 = min(height, int(y + face_height))
        roi = frame[y1:y2, x1:x2]
        gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
        brightness = float(gray.mean())
        if brightness < 45:
            return FaceAnalysis(1, face, None, None, False, "Недостаточно света")
        if brightness > 220:
            return FaceAnalysis(1, face, None, None, False, "Слишком яркое освещение")
        if float(cv2.Laplacian(gray, cv2.CV_64F).var()) < 35:
            return FaceAnalysis(1, face, None, None, False, "Кадр размыт")

        right_eye_x, left_eye_x, nose_x = float(face[4]), float(face[6]), float(face[8])
        eye_distance = max(abs(left_eye_x - right_eye_x), 1.0)
        eye_midpoint = (left_eye_x + right_eye_x) / 2.0
        yaw_ratio = (nose_x - eye_midpoint) / eye_distance

        embedding = None
        if extract_embedding:
            try:
                aligned = self.recognizer.alignCrop(frame, face)
                embedding = self.normalize(self.recognizer.feature(aligned))
            except cv2.error as error:
                raise BiometricError(f"Ошибка локального распознавания лица: {error}") from error

        return FaceAnalysis(1, face, embedding, yaw_ratio, True, "Лицо найдено")

    @staticmethod
    def normalize(embedding: np.ndarray) -> np.ndarray:
        vector = np.asarray(embedding, dtype=np.float32).reshape(-1)
        if vector.size < 64 or not np.isfinite(vector).all():
            raise ValidationError("Модель вернула некорректный шаблон лица.")
        norm = float(np.linalg.norm(vector))
        if norm <= 1e-8:
            raise ValidationError("Модель вернула пустой шаблон лица.")
        return np.ascontiguousarray(vector / norm, dtype=np.float32)

    @classmethod
    def aggregate(cls, embeddings: list[np.ndarray]) -> np.ndarray:
        if len(embeddings) < 3:
            raise ValidationError("Недостаточно образцов лица для регистрации.")
        normalized = [cls.normalize(embedding) for embedding in embeddings]
        centroid = cls.normalize(np.mean(np.stack(normalized), axis=0))
        if min(cls.cosine(centroid, sample) for sample in normalized) < 0.55:
            raise ValidationError(
                "Образцы лица получились нестабильными. Повторите регистрацию."
            )
        return centroid

    @staticmethod
    def cosine(first: np.ndarray, second: np.ndarray) -> float:
        a = FaceEngine.normalize(first)
        b = FaceEngine.normalize(second)
        if a.shape != b.shape:
            raise ValidationError("Размеры биометрических шаблонов не совпадают.")
        return float(np.dot(a, b))
