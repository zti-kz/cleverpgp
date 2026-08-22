from pathlib import Path
from unittest.mock import patch

from biopgp.config import bundled_models_directory


def test_frozen_application_uses_pyinstaller_models_directory() -> None:
    runtime_directory = Path("C:/Program Files/BioPGP/_internal")
    with (
        patch("biopgp.config.sys.frozen", True, create=True),
        patch("biopgp.config.sys._MEIPASS", str(runtime_directory), create=True),
        patch.dict("os.environ", {}, clear=True),
    ):
        result = bundled_models_directory()

    assert result == runtime_directory / "models"
