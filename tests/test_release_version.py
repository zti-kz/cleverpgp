from __future__ import annotations

import importlib.util
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "scripts" / "check_release_version.py"


def _load_release_checker():
    spec = importlib.util.spec_from_file_location("check_release_version", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_version_is_consistent() -> None:
    checker = _load_release_checker()

    assert checker.checked_release_version("v0.10.0") == "0.10.0"
    assert set(checker.release_versions().values()) == {"0.10.0"}


def test_release_tag_must_match_project_version() -> None:
    checker = _load_release_checker()

    try:
        checker.checked_release_version("v9.9.9")
    except RuntimeError as error:
        assert "не соответствует версии проекта" in str(error)
    else:
        raise AssertionError("Несогласованный тег должен быть отклонён.")


def test_release_workflow_normalizes_and_checks_installer_versions() -> None:
    workflow = (
        PROJECT_ROOT / ".github" / "workflows" / "windows-release.yml"
    ).read_text(encoding="utf-8")

    assert "ProductVersion).Trim()" in workflow
    assert "FileVersion).Trim()" in workflow
    assert '$expectedFileVersion = $env:RELEASE_VERSION + ".0"' in workflow
