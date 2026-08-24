from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from cleverpgp.config import bundled_models_directory
from cleverpgp.core.errors import ModelIntegrityError


@dataclass(frozen=True, slots=True)
class ModelAsset:
    filename: str
    url: str
    sha256: str

    def path(self, directory: Path | None = None) -> Path:
        return (directory or bundled_models_directory()) / self.filename


YUNET = ModelAsset(
    filename="face_detection_yunet_2023mar.onnx",
    url=(
        "https://github.com/opencv/opencv_zoo/raw/main/models/"
        "face_detection_yunet/face_detection_yunet_2023mar.onnx"
    ),
    sha256="8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
)

SFACE = ModelAsset(
    filename="face_recognition_sface_2021dec.onnx",
    url=(
        "https://github.com/opencv/opencv_zoo/raw/main/models/"
        "face_recognition_sface/face_recognition_sface_2021dec.onnx"
    ),
    sha256="0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79",
)

MODEL_ASSETS = (YUNET, SFACE)
MODEL_ID = "opencv-sface-2021dec"
MODEL_SHA256 = SFACE.sha256


def verify_model_asset(asset: ModelAsset, directory: Path | None = None) -> Path:
    path = asset.path(directory)
    if not path.is_file():
        raise ModelIntegrityError(
            f"Модель {asset.filename} не найдена. Выполните setup.ps1."
        )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != asset.sha256:
        raise ModelIntegrityError(
            f"Контрольная сумма модели {asset.filename} не совпадает."
        )
    return path


def verify_all_models(directory: Path | None = None) -> dict[str, Path]:
    return {
        asset.filename: verify_model_asset(asset, directory) for asset in MODEL_ASSETS
    }
