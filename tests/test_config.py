from pathlib import Path
from unittest.mock import patch

from cleverpgp.config import (
    bundled_models_directory,
    database_path,
    migrate_legacy_app_data,
)


def test_frozen_application_uses_pyinstaller_models_directory() -> None:
    runtime_directory = Path("C:/Program Files/Clever PGP/_internal")
    with (
        patch("cleverpgp.config.sys.frozen", True, create=True),
        patch("cleverpgp.config.sys._MEIPASS", str(runtime_directory), create=True),
        patch.dict("os.environ", {}, clear=True),
    ):
        result = bundled_models_directory()

    assert result == runtime_directory / "models"


def test_windows_profile_is_migrated_to_cleverpgp_directory(tmp_path: Path) -> None:
    legacy = tmp_path / "BioPGP"
    legacy.mkdir()
    (legacy / "biopgp.sqlite3").write_bytes(b"encrypted local profile")

    with (
        patch("cleverpgp.config.sys.platform", "win32"),
        patch.dict(
            "os.environ",
            {"LOCALAPPDATA": str(tmp_path)},
            clear=True,
        ),
    ):
        migrate_legacy_app_data()
        result = database_path()

    assert result == tmp_path / "CleverPGP" / "cleverpgp.sqlite3"
    assert result.read_bytes() == b"encrypted local profile"
    assert not legacy.exists()
