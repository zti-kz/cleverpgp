from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_windows_installer_build_forces_utf8_python_output() -> None:
    script = (PROJECT_ROOT / "build_installer.ps1").read_text(encoding="utf-8-sig")

    assert '$env:PYTHONUTF8 = "1"' in script
    assert '$env:PYTHONIOENCODING = "utf-8"' in script
    assert script.index("$env:PYTHONUTF8") < script.index("scripts\\download_models.py")


def test_windows_installer_excludes_host_runtime_dlls_from_path() -> None:
    script = (PROJECT_ROOT / "build_installer.ps1").read_text(encoding="utf-8-sig")

    assert "$BuildPathEntries" in script
    assert "codex-runtimes" in script
    assert "$env:PATH = $BuildPathEntries" in script
    assert script.index("$BuildPathEntries") < script.index("-m PyInstaller")


def test_windows_installer_verifies_vendor_hashes_and_signatures() -> None:
    script = (PROJECT_ROOT / "build_installer.ps1").read_text(encoding="utf-8-sig")

    assert "function Assert-TrustedNavimaticsSignature" in script
    assert 'Subject -notlike "CN=NAVIMATICS LLC*"' in script
    assert "$WinSpdSha256" in script
    assert "$WinFspSha256" in script
    assert "Assert-TrustedNavimaticsSignature $WinSpdInstaller" in script
    assert "Assert-TrustedNavimaticsSignature $WinFspInstaller" in script
    assert "Assert-TrustedNavimaticsSignature $WinSpdDll" in script
    assert script.index("Download-VerifiedFile $WinSpdUrl") < script.index(
        "Assert-TrustedNavimaticsSignature $WinSpdInstaller"
    )
    assert script.index("Download-VerifiedFile $WinFspUrl") < script.index(
        "Assert-TrustedNavimaticsSignature $WinFspInstaller"
    )


def test_windows_installer_rejects_wrong_publisher_certificate() -> None:
    script = (PROJECT_ROOT / "build_installer.ps1").read_text(encoding="utf-8-sig")

    assert '$ExpectedSigningIdentity = if (' in script
    assert '"Almas Oskenbay"' in script
    assert "function Test-CodeSigningEku" in script
    assert '"1.3.6.1.5.5.7.3.3"' in script
    assert "$SelectedCertificate.HasPrivateKey" in script
    assert "CertificateIdentity" in script


def test_windows_installer_verifies_timestamped_output_and_writes_checksum() -> None:
    script = (PROJECT_ROOT / "build_installer.ps1").read_text(encoding="utf-8-sig")

    assert "verify /pa /all /v" in script
    assert '"http://time.certum.pl"' in script
    assert "$Signature.TimeStamperCertificate" in script
    assert '"$SetupExecutable.sha256"' in script
    assert "Set-Content -LiteralPath $SetupChecksum -Encoding ascii" in script


def test_elevated_winspd_check_preserves_diagnostic_details() -> None:
    script = (PROJECT_ROOT / "scripts" / "run_winspd_windows_check.ps1").read_text(
        encoding="utf-8-sig"
    )

    assert "if ($Elevated)" in script
    assert "trap {" in script
    assert 'status = "error"' in script
    assert "Set-Content -LiteralPath $Marker -Encoding utf8" in script
    assert "Подробный отчёт не создан." in script
