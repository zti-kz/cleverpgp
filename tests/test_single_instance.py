from __future__ import annotations

from PySide6.QtWidgets import QApplication

from cleverpgp.single_instance import SingleApplicationInstance


def test_second_regular_shell_activates_primary(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("CLEVERPGP_DATA_DIR", str(tmp_path / "application-data"))
    application = QApplication.instance() or QApplication([])
    primary = SingleApplicationInstance()
    secondary = SingleApplicationInstance()
    try:
        assert primary.acquire()
        assert not secondary.acquire()
    finally:
        secondary.close()
        primary.close()
        application.processEvents()
