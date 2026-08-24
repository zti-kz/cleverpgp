from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox

from cleverpgp.config import APP_NAME, ORGANIZATION_NAME, database_path
from cleverpgp.core.storage import ProfileRepository
from cleverpgp.localization import set_language, tr
from cleverpgp.ui.screen_bounds import install_screen_bounds
from cleverpgp.ui.shell_dialog import ShellOperationDialog


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cleverpgp-shell")
    parser.add_argument("operation", choices=("encrypt", "decrypt"))
    parser.add_argument("path", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    application = QApplication(sys.argv if argv is None else ["cleverpgp-shell", *argv])
    application.setApplicationName(APP_NAME)
    application.setOrganizationName(ORGANIZATION_NAME)
    install_screen_bounds(application)

    repository = ProfileRepository(database_path())
    repository.initialize()
    set_language(repository.get_setting("language") or "ru")
    if not repository.has_profile():
        QMessageBox.critical(
            None,
            "Clever PGP",
            tr("Профиль Clever PGP ещё не создан. Сначала запустите основное приложение."),
        )
        return 2
    if not arguments.path.expanduser().is_file():
        QMessageBox.critical(None, "Clever PGP", tr("Выбранный файл не найден."))
        return 2

    dialog = ShellOperationDialog(
        repository, arguments.operation, arguments.path
    )
    return 0 if dialog.exec() else 1


if __name__ == "__main__":
    raise SystemExit(main())
