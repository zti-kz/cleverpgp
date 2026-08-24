from __future__ import annotations

from cleverpgp.core.profile_purge import purge_local_profile


def test_full_uninstall_purges_only_local_application_state(
    monkeypatch, tmp_path
) -> None:
    application_data = tmp_path / "CleverPGP"
    application_data.mkdir()
    (application_data / "cleverpgp.sqlite3").write_bytes(b"profile")
    (application_data / "languages").mkdir()
    (application_data / "languages" / "de.json").write_text("{}")
    container = tmp_path / "private.cpgv"
    container.write_bytes(b"encrypted-user-data")
    monkeypatch.setenv("CLEVERPGP_DATA_DIR", str(application_data))

    assert purge_local_profile(retries=1) == 0
    assert not application_data.exists()
    assert container.read_bytes() == b"encrypted-user-data"


def test_explicit_uninstall_path_removes_current_and_legacy_profile(
    tmp_path,
) -> None:
    local = tmp_path / "AppData" / "Local"
    current = local / "CleverPGP"
    legacy = local / "BioPGP"
    current.mkdir(parents=True)
    legacy.mkdir()
    (current / "cleverpgp.sqlite3").write_bytes(b"current")
    (legacy / "biopgp.sqlite3").write_bytes(b"legacy")

    assert purge_local_profile(current, retries=1) == 0
    assert not current.exists()
    assert not legacy.exists()
