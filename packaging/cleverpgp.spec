import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


project_directory = Path(SPEC).resolve().parents[1]
winspd_dll = os.environ.get("CLEVERPGP_WINSPD_DLL_SOURCE")
winspd_binaries = [(winspd_dll, ".")] if winspd_dll else []
hidden_imports = [
    "_cffi_backend",
    "cv2",
    "numpy",
    *collect_submodules("refuse"),
]

analysis = Analysis(
    [str(project_directory / "src" / "cleverpgp" / "__main__.py")],
    pathex=[str(project_directory / "src")],
    binaries=winspd_binaries,
    datas=[
        (str(project_directory / "models"), "models"),
        (str(project_directory / "assets"), "assets"),
        (str(project_directory / "src" / "cleverpgp" / "locales"), "cleverpgp/locales"),
    ],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest"],
    noarchive=False,
    optimize=1,
)

python_archive = PYZ(analysis.pure)

executable = EXE(
    python_archive,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="CleverPGP",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=str(project_directory / "assets" / "cleverpgp.ico"),
    version=str(project_directory / "packaging" / "version_info.txt"),
)

collection = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CleverPGP",
)
