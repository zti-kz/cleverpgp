from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_windows_installer_build_forces_utf8_python_output() -> None:
    script = (PROJECT_ROOT / "build_installer.ps1").read_text(encoding="utf-8-sig")

    assert '$env:PYTHONUTF8 = "1"' in script
    assert '$env:PYTHONIOENCODING = "utf-8"' in script
    assert script.index("$env:PYTHONUTF8") < script.index("scripts\\download_models.py")
