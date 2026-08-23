from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SEMANTIC_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def _read(relative_path: str) -> str:
    return (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")


def _match(relative_path: str, pattern: str) -> str:
    match = re.search(pattern, _read(relative_path), flags=re.MULTILINE)
    if match is None:
        raise RuntimeError(f"Не найдена версия в {relative_path}.")
    return match.group(1)


def release_versions() -> dict[str, str]:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as stream:
        project_version = str(tomllib.load(stream)["project"]["version"])

    return {
        "pyproject.toml": project_version,
        "src/biopgp/__init__.py": _match(
            "src/biopgp/__init__.py",
            r'^__version__\s*=\s*"([^"]+)"\s*$',
        ),
        "build_installer.ps1": _match(
            "build_installer.ps1",
            r'^\$AppVersion\s*=\s*"([^"]+)"\s*$',
        ),
        "packaging/biopgp.iss": _match(
            "packaging/biopgp.iss",
            r'^\s*#define\s+AppVersion\s+"([^"]+)"\s*$',
        ),
        "packaging/version_info.txt": _match(
            "packaging/version_info.txt",
            r"StringStruct\('ProductVersion',\s*'([^']+)'\)",
        ),
    }


def checked_release_version(tag: str | None = None) -> str:
    versions = release_versions()
    unique_versions = set(versions.values())
    if len(unique_versions) != 1:
        details = ", ".join(f"{path}={version}" for path, version in versions.items())
        raise RuntimeError(f"Версии выпуска не совпадают: {details}")

    version = unique_versions.pop()
    if SEMANTIC_VERSION.fullmatch(version) is None:
        raise RuntimeError(f"Версия выпуска должна иметь вид X.Y.Z: {version}")
    if tag is not None and tag != f"v{version}":
        raise RuntimeError(
            f"Тег {tag} не соответствует версии проекта {version}; "
            f"ожидается v{version}."
        )
    return version


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Проверяет согласованность номера выпуска Clever PGP."
    )
    parser.add_argument("--tag", help="Git-тег вида vX.Y.Z")
    arguments = parser.parse_args()
    print(checked_release_version(arguments.tag))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
