$ErrorActionPreference = "Stop"

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

# PyInstaller resolves generic DLL names from PATH.  Codex/document runtimes
# may add an unrelated Poppler ICU build there; packaging that DLL beside Qt
# makes QtCore fail at startup with WinError 127.  Build only against Windows
# and the project's declared dependencies, never the host assistant runtime.
$BuildPathEntries = @(
    $env:PATH -split [IO.Path]::PathSeparator |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_) -and
            $_ -notmatch '[\\/]\.cache[\\/]codex-runtimes[\\/]'
        }
)
$env:PATH = $BuildPathEntries -join [IO.Path]::PathSeparator

$OutputDirectory = ""
for ($ArgumentIndex = 0; $ArgumentIndex -lt $args.Count; $ArgumentIndex++) {
    if (
        $args[$ArgumentIndex] -eq "-OutputDirectory" -and
        $ArgumentIndex + 1 -lt $args.Count
    ) {
        $OutputDirectory = [string]$args[$ArgumentIndex + 1]
        break
    }
}

$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExecutable = Join-Path $ProjectDirectory ".venv\Scripts\python.exe"
$BuildDirectory = Join-Path $ProjectDirectory "build"
$ApplicationDirectory = Join-Path $BuildDirectory "app"
$PyInstallerWorkDirectory = Join-Path $BuildDirectory "pyinstaller"
$VendorDirectory = Join-Path $BuildDirectory "vendor"
$ToolsDirectory = Join-Path $BuildDirectory "tools"
$ReleaseDirectory = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Join-Path $ProjectDirectory "release"
} else {
    [IO.Path]::GetFullPath($OutputDirectory)
}
$WinFspInstaller = Join-Path $VendorDirectory "winfsp-2.2.26194.msi"
$WinFspUrl = "https://github.com/winfsp/winfsp/releases/download/v2.2B3/winfsp-2.2.26194.msi"
$WinFspSha256 = "7B41020618CDCC33D699D0E15C1DF660F0762A09B57080049C565857AC00BD9D"
$WinSpdInstaller = Join-Path $VendorDirectory "winspd-1.0.20357.msi"
$WinSpdUrl = "https://github.com/winfsp/winspd/releases/download/v1.0B1/winspd-1.0.20357.msi"
$WinSpdSha256 = "F1157EEF805DCBEC78A477F2B4EE5ABC0049C8A9329444E5D18CAB01D3604265"
$WinSpdExtractDirectory = Join-Path $VendorDirectory "winspd-package"
$WinSpdDll = Join-Path $WinSpdExtractDirectory "WinSpd\sys\winspd-x64.dll"
$WinSpdDllSha256 = "35433B6E99C4B282A7EC07757F2206851F28DABF7BBCFFD90BF60F317E865F7B"
$WinSpdStgTest = Join-Path $WinSpdExtractDirectory "WinSpd\bin\stgtest-x64.exe"
$WinSpdStgTestSha256 = "FF53AE37AD610AA851765596B3E821BD28CF2F0F68AD30991C79B423A3FB0AB7"
$InnoInstaller = Join-Path $ToolsDirectory "innosetup-7.1.0-x64.exe"
$InnoUrl = "https://github.com/jrsoftware/issrc/releases/download/is-7_1_0/innosetup-7.1.0-x64.exe"
$InnoSha256 = "0362A383ED217D4C4239B5933866DD96D3EB2102737DA92F80F6057A4B40DF2F"
$InnoDirectory = Join-Path $ToolsDirectory "InnoSetup"
$InnoCompiler = Join-Path $InnoDirectory "ISCC.exe"
$AppVersion = "0.15.3"
$SignToolPath = $env:CLEVERPGP_SIGNTOOL
$SigningCertificateThumbprint = $env:CLEVERPGP_SIGN_CERT_SHA1
$ExpectedSigningIdentity = if ([string]::IsNullOrWhiteSpace($env:CLEVERPGP_SIGN_EXPECTED_NAME)) {
    "Almas Oskenbay"
} else {
    $env:CLEVERPGP_SIGN_EXPECTED_NAME.Trim()
}
$TimestampUrl = if ([string]::IsNullOrWhiteSpace($env:CLEVERPGP_TIMESTAMP_URL)) {
    "http://time.certum.pl"
} else {
    $env:CLEVERPGP_TIMESTAMP_URL.Trim()
}
$SigningEnabled = -not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)
$SigningCertificateStoreArguments = @()

function Assert-ProjectChild([string]$Path) {
    $ProjectRoot = [IO.Path]::GetFullPath($ProjectDirectory).TrimEnd('\') + '\'
    $Candidate = [IO.Path]::GetFullPath($Path)
    if (-not $Candidate.StartsWith($ProjectRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Операция сборки вышла за каталог проекта: $Candidate"
    }
}

function Reset-BuildDirectory([string]$Path) {
    Assert-ProjectChild $Path
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Download-VerifiedFile(
    [string]$Url,
    [string]$Destination,
    [string]$ExpectedSha256
) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        $ExistingHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash
        if ($ExistingHash -eq $ExpectedSha256) {
            return
        }
        Remove-Item -LiteralPath $Destination -Force
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination
    $ActualHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash
    if ($ActualHash -ne $ExpectedSha256) {
        Remove-Item -LiteralPath $Destination -Force
        throw "Проверка SHA-256 не пройдена для $Destination. Получено: $ActualHash"
    }
}

function Assert-TrustedNavimaticsSignature([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Подписанный системный компонент не найден: $Path"
    }
    $Signature = Get-AuthenticodeSignature -LiteralPath $Path
    if (
        $Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $Signature.SignerCertificate -or
        $Signature.SignerCertificate.Subject -notlike "CN=NAVIMATICS LLC*"
    ) {
        throw "Цифровая подпись официального системного компонента не подтверждена: $Path"
    }
}

function Resolve-SignToolPath {
    if (-not [string]::IsNullOrWhiteSpace($SignToolPath)) {
        if (-not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
            throw "CLEVERPGP_SIGNTOOL должен указывать на signtool.exe из Windows SDK."
        }
        return [IO.Path]::GetFullPath($SignToolPath)
    }

    $WindowsKitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    $DetectedSignTool = Get-ChildItem `
        -Path (Join-Path $WindowsKitsRoot "*\x64\signtool.exe") `
        -File `
        -ErrorAction SilentlyContinue |
        Sort-Object -Property FullName -Descending |
        Select-Object -First 1
    if ($null -eq $DetectedSignTool) {
        throw "signtool.exe не найден. Установите Windows SDK или задайте CLEVERPGP_SIGNTOOL."
    }
    return $DetectedSignTool.FullName
}

function Test-CodeSigningEku([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
    foreach ($Extension in $Certificate.Extensions) {
        if ($Extension.Oid.Value -ne "2.5.29.37") {
            continue
        }
        $EnhancedKeyUsage = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
            $Extension,
            $Extension.Critical
        )
        foreach ($Usage in $EnhancedKeyUsage.EnhancedKeyUsages) {
            if ($Usage.Value -eq "1.3.6.1.5.5.7.3.3") {
                return $true
            }
        }
    }
    return $false
}

function Initialize-CodeSigning {
    if (-not $SigningEnabled) {
        return
    }

    $script:SignToolPath = Resolve-SignToolPath
    $NormalizedThumbprint = $SigningCertificateThumbprint.Replace(" ", "").ToUpperInvariant()
    if ($NormalizedThumbprint -notmatch '^[0-9A-F]{40}$') {
        throw "CLEVERPGP_SIGN_CERT_SHA1 должен содержать 40-значный отпечаток сертификата."
    }
    $script:SigningCertificateThumbprint = $NormalizedThumbprint

    $TimestampUri = $null
    if (
        -not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$TimestampUri) -or
        $TimestampUri.Scheme -notin @("http", "https")
    ) {
        throw "CLEVERPGP_TIMESTAMP_URL должен содержать полный HTTP(S)-адрес службы RFC 3161."
    }

    $Stores = @(
        [PSCustomObject]@{
            Path = "Cert:\CurrentUser\My"
            SignToolArguments = @("/s", "My")
        },
        [PSCustomObject]@{
            Path = "Cert:\LocalMachine\My"
            SignToolArguments = @("/sm", "/s", "My")
        }
    )
    $SelectedCertificate = $null
    foreach ($Store in $Stores) {
        $Certificate = Get-ChildItem -LiteralPath $Store.Path -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $NormalizedThumbprint } |
            Select-Object -First 1
        if ($null -ne $Certificate) {
            $SelectedCertificate = $Certificate
            $script:SigningCertificateStoreArguments = $Store.SignToolArguments
            break
        }
    }
    if ($null -eq $SelectedCertificate) {
        throw "Сертификат подписи с указанным отпечатком не найден в хранилище Windows."
    }

    $Now = Get-Date
    if ($SelectedCertificate.NotBefore -gt $Now -or $SelectedCertificate.NotAfter -lt $Now) {
        throw "Сертификат издателя ещё не действует или уже истёк."
    }
    if (-not $SelectedCertificate.HasPrivateKey) {
        throw (
            "Для сертификата издателя недоступен закрытый ключ, аппаратный токен " +
            "или подключённое облачное хранилище."
        )
    }
    if (-not (Test-CodeSigningEku $SelectedCertificate)) {
        throw "Выбранный сертификат не предназначен для подписи программ."
    }

    $CertificateIdentity = $SelectedCertificate.GetNameInfo(
        [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false
    )
    if (-not [string]::Equals(
        $CertificateIdentity,
        $ExpectedSigningIdentity,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw (
            "Имя издателя в сертификате '$CertificateIdentity' не совпадает с " +
            "закреплённым именем '$ExpectedSigningIdentity'."
        )
    }

    Write-Host "Сертификат издателя проверен: $CertificateIdentity"
    Write-Host "Действует до: $($SelectedCertificate.NotAfter.ToString('yyyy-MM-dd'))"
}

function Invoke-CodeSigning([string]$Path) {
    if (-not $SigningEnabled) {
        return
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Файл для подписи не найден: $Path"
    }

    Write-Host "Цифровая подпись: $Path"
    & $SignToolPath sign `
        @SigningCertificateStoreArguments `
        /sha1 $SigningCertificateThumbprint `
        /fd SHA256 `
        /tr $TimestampUrl `
        /td SHA256 `
        /v `
        $Path
    if ($LASTEXITCODE -ne 0) {
        throw "Не удалось подписать файл: $Path"
    }
    & $SignToolPath verify /pa /all /v $Path
    if ($LASTEXITCODE -ne 0) {
        throw "Проверка цифровой подписи не пройдена: $Path"
    }

    $Signature = Get-AuthenticodeSignature -LiteralPath $Path
    $ActualSigner = if ($null -eq $Signature.SignerCertificate) {
        ""
    } else {
        $Signature.SignerCertificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
    }
    if (
        $Signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        -not [string]::Equals(
            $ActualSigner,
            $ExpectedSigningIdentity,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $null -eq $Signature.TimeStamperCertificate
    ) {
        throw "Подпись, издатель или доверенная метка времени не подтверждены: $Path"
    }
}

function Expand-VerifiedWinSpdPackage {
    if (
        (Test-Path -LiteralPath $WinSpdDll -PathType Leaf) -and
        (Test-Path -LiteralPath $WinSpdStgTest -PathType Leaf)
    ) {
        $ExistingDllHash = (Get-FileHash -LiteralPath $WinSpdDll -Algorithm SHA256).Hash
        $ExistingTestHash = (Get-FileHash -LiteralPath $WinSpdStgTest -Algorithm SHA256).Hash
        if (
            $ExistingDllHash -eq $WinSpdDllSha256 -and
            $ExistingTestHash -eq $WinSpdStgTestSha256
        ) {
            return
        }
    }
    Reset-BuildDirectory $WinSpdExtractDirectory
    $MsiArguments = @(
        "/a",
        "`"$WinSpdInstaller`"",
        "/qn",
        "TARGETDIR=`"$WinSpdExtractDirectory`""
    )
    $MsiProcess = Start-Process `
        -FilePath (Join-Path $env:SystemRoot "System32\msiexec.exe") `
        -ArgumentList $MsiArguments `
        -Wait `
        -PassThru `
        -WindowStyle Hidden
    if ($MsiProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $WinSpdDll -PathType Leaf)) {
        throw "Не удалось извлечь официальный компонент WinSpd для сборки."
    }
    $DllHash = (Get-FileHash -LiteralPath $WinSpdDll -Algorithm SHA256).Hash
    if ($DllHash -ne $WinSpdDllSha256) {
        throw "Проверка SHA-256 библиотеки WinSpd не пройдена: $DllHash"
    }
    $TestHash = (Get-FileHash -LiteralPath $WinSpdStgTest -Algorithm SHA256).Hash
    if ($TestHash -ne $WinSpdStgTestSha256) {
        throw "Проверка SHA-256 утилиты WinSpd не пройдена: $TestHash"
    }
    Assert-TrustedNavimaticsSignature $WinSpdDll
}

if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
    throw "Сначала подготовьте среду разработки Clever PGP с помощью setup.ps1."
}

Initialize-CodeSigning

Write-Host "Подготовка сборки Clever PGP..."
& $PythonExecutable -m pip install -e "${ProjectDirectory}[packaging]"
if ($LASTEXITCODE -ne 0) { throw "Не удалось установить инструменты сборки." }
& $PythonExecutable (Join-Path $ProjectDirectory "scripts\download_models.py")
if ($LASTEXITCODE -ne 0) { throw "Не удалось проверить модели лица." }
& $PythonExecutable (Join-Path $ProjectDirectory "scripts\generate_icon.py")
if ($LASTEXITCODE -ne 0) { throw "Не удалось создать значок Clever PGP." }

Reset-BuildDirectory $ApplicationDirectory
Reset-BuildDirectory $PyInstallerWorkDirectory
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Reset-BuildDirectory $ReleaseDirectory
} else {
    New-Item -ItemType Directory -Path $ReleaseDirectory -Force | Out-Null
}
New-Item -ItemType Directory -Path $VendorDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $ToolsDirectory -Force | Out-Null

Write-Host "Подготовка системных компонентов диска..."
Download-VerifiedFile $WinSpdUrl $WinSpdInstaller $WinSpdSha256
Assert-TrustedNavimaticsSignature $WinSpdInstaller
Expand-VerifiedWinSpdPackage
$env:CLEVERPGP_WINSPD_DLL_SOURCE = $WinSpdDll

Write-Host "Сборка приложения..."
& $PythonExecutable -m PyInstaller `
    --noconfirm `
    --clean `
    --distpath $ApplicationDirectory `
    --workpath $PyInstallerWorkDirectory `
    (Join-Path $ProjectDirectory "packaging\cleverpgp.spec")
if ($LASTEXITCODE -ne 0) { throw "Сборка CleverPGP.exe завершилась ошибкой." }

$BundledApplication = Join-Path $ApplicationDirectory "CleverPGP"
$BundledExecutable = Join-Path $BundledApplication "CleverPGP.exe"
if ($SigningEnabled) {
    Invoke-CodeSigning $BundledExecutable
} else {
    Write-Host "Цифровая подпись пропущена: сертификат Code Signing ещё не настроен."
}
$RuntimeMarker = Join-Path $BuildDirectory "runtime-check.json"
Assert-ProjectChild $RuntimeMarker
if (Test-Path -LiteralPath $RuntimeMarker) {
    Remove-Item -LiteralPath $RuntimeMarker -Force
}
$RuntimeArguments = @("--runtime-check", "`"$RuntimeMarker`"")
$RuntimeProcess = Start-Process `
    -FilePath $BundledExecutable `
    -ArgumentList $RuntimeArguments `
    -Wait `
    -PassThru `
    -WindowStyle Hidden
if ($RuntimeProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $RuntimeMarker -PathType Leaf)) {
    $RuntimeDetails = if (Test-Path -LiteralPath $RuntimeMarker) {
        Get-Content -LiteralPath $RuntimeMarker -Raw
    } else {
        "Проверочный файл не создан."
    }
    throw "Проверка собранного CleverPGP.exe не пройдена: $RuntimeDetails"
}
Write-Host "Собранное приложение и криптографический backend проверены."

$UiWorkerMarker = Join-Path $BuildDirectory "ui-worker-runtime-check.json"
Assert-ProjectChild $UiWorkerMarker
if (Test-Path -LiteralPath $UiWorkerMarker) {
    Remove-Item -LiteralPath $UiWorkerMarker -Force
}
$UiWorkerArguments = @("--ui-worker-check", "`"$UiWorkerMarker`"")
$UiWorkerProcess = Start-Process `
    -FilePath $BundledExecutable `
    -ArgumentList $UiWorkerArguments `
    -Wait `
    -PassThru `
    -WindowStyle Hidden
if (
    $UiWorkerProcess.ExitCode -ne 0 -or
    -not (Test-Path -LiteralPath $UiWorkerMarker -PathType Leaf)
) {
    $UiWorkerDetails = if (Test-Path -LiteralPath $UiWorkerMarker) {
        Get-Content -LiteralPath $UiWorkerMarker -Raw
    } else {
        "Проверочный файл не создан."
    }
    throw "Проверка фоновых операций собранного CleverPGP.exe не пройдена: $UiWorkerDetails"
}
Write-Host "Фоновые операции собранного приложения проверены."

$FileShellMarker = Join-Path $BuildDirectory "file-shell-runtime-check.json"
Assert-ProjectChild $FileShellMarker
if (Test-Path -LiteralPath $FileShellMarker) {
    Remove-Item -LiteralPath $FileShellMarker -Force
}
$FileShellArguments = @("--file-shell-check", "`"$FileShellMarker`"")
$FileShellProcess = Start-Process `
    -FilePath $BundledExecutable `
    -ArgumentList $FileShellArguments `
    -Wait `
    -PassThru `
    -WindowStyle Hidden
if (
    $FileShellProcess.ExitCode -ne 0 -or
    -not (Test-Path -LiteralPath $FileShellMarker -PathType Leaf)
) {
    $FileShellDetails = if (Test-Path -LiteralPath $FileShellMarker) {
        Get-Content -LiteralPath $FileShellMarker -Raw
    } else {
        "Проверочный файл не создан."
    }
    throw "Проверка шифрования файлов собранного CleverPGP.exe не пройдена: $FileShellDetails"
}
Write-Host "Шифрование и расшифрование файлов в собранном приложении проверены."

$WinSpdRuntimeMarker = Join-Path $BuildDirectory "winspd-runtime-check.json"
Assert-ProjectChild $WinSpdRuntimeMarker
if (Test-Path -LiteralPath $WinSpdRuntimeMarker) {
    Remove-Item -LiteralPath $WinSpdRuntimeMarker -Force
}
$WinSpdRuntimeArguments = @(
    "--winspd-pipe-check",
    "`"$WinSpdRuntimeMarker`"",
    "`"$WinSpdStgTest`""
)
$WinSpdRuntimeProcess = Start-Process `
    -FilePath $BundledExecutable `
    -ArgumentList $WinSpdRuntimeArguments `
    -Wait `
    -PassThru `
    -WindowStyle Hidden
if (
    $WinSpdRuntimeProcess.ExitCode -ne 0 -or
    -not (Test-Path -LiteralPath $WinSpdRuntimeMarker -PathType Leaf)
) {
    $WinSpdRuntimeDetails = if (Test-Path -LiteralPath $WinSpdRuntimeMarker) {
        Get-Content -LiteralPath $WinSpdRuntimeMarker -Raw
    } else {
        "Проверочный файл не создан."
    }
    throw "Проверка системного диска собранного CleverPGP.exe не пройдена: $WinSpdRuntimeDetails"
}
Write-Host "Системный блочный процесс собранного приложения проверен."

$VirtualDiskMarker = Join-Path $BuildDirectory "virtual-disk-runtime-check.json"
Assert-ProjectChild $VirtualDiskMarker
if (Test-Path -LiteralPath $VirtualDiskMarker) {
    Remove-Item -LiteralPath $VirtualDiskMarker -Force
}
$VirtualDiskArguments = @("--virtual-disk-check", "`"$VirtualDiskMarker`"")
$VirtualDiskProcess = Start-Process `
    -FilePath $BundledExecutable `
    -ArgumentList $VirtualDiskArguments `
    -Wait `
    -PassThru `
    -WindowStyle Hidden
if (
    $VirtualDiskProcess.ExitCode -ne 0 -or
    -not (Test-Path -LiteralPath $VirtualDiskMarker -PathType Leaf)
) {
    $VirtualDiskDetails = if (Test-Path -LiteralPath $VirtualDiskMarker) {
        Get-Content -LiteralPath $VirtualDiskMarker -Raw
    } else {
        "Проверочный файл не создан."
    }
    throw "Проверка виртуального диска собранного CleverPGP.exe не пройдена: $VirtualDiskDetails"
}
Write-Host "Виртуальный диск собранного приложения проверен."

Write-Host "Подготовка установщика виртуального диска..."
Download-VerifiedFile $WinFspUrl $WinFspInstaller $WinFspSha256
Assert-TrustedNavimaticsSignature $WinFspInstaller

if (-not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
    Write-Host "Подготовка конструктора установщика..."
    New-Item -ItemType Directory -Path $InnoDirectory -Force | Out-Null
    Download-VerifiedFile $InnoUrl $InnoInstaller $InnoSha256
    $InnoSignature = Get-AuthenticodeSignature -LiteralPath $InnoInstaller
    if (
        $InnoSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $InnoSignature.SignerCertificate.Subject -notlike "CN=Pyrsys B.V.*"
    ) {
        throw "Цифровая подпись конструктора установщика не подтверждена."
    }
    $InnoArguments = @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/CURRENTUSER",
        "/DIR=`"$InnoDirectory`""
    )
    $InnoProcess = Start-Process -FilePath $InnoInstaller -ArgumentList $InnoArguments -Wait -PassThru -WindowStyle Hidden
    if ($InnoProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $InnoCompiler -PathType Leaf)) {
        throw "Не удалось подготовить конструктор EXE-установщика."
    }
}

$InnoScript = Join-Path $ProjectDirectory "packaging\cleverpgp.iss"
$CompilerArguments = @(
    "/DAppVersion=$AppVersion",
    "/DAppSourceDirectory=$BundledApplication",
    "/DProjectDirectory=$ProjectDirectory",
    "/DWinFspInstaller=$WinFspInstaller",
    "/DWinSpdInstaller=$WinSpdInstaller",
    "/DReleaseDirectory=$ReleaseDirectory",
    $InnoScript
)
Write-Host "Создание единого EXE-установщика..."
& $InnoCompiler $CompilerArguments
if ($LASTEXITCODE -ne 0) { throw "Создание EXE-установщика завершилось ошибкой." }

$SetupExecutable = Join-Path $ReleaseDirectory "Clever-PGP-Setup-$AppVersion.exe"
if (-not (Test-Path -LiteralPath $SetupExecutable -PathType Leaf)) {
    throw "Готовый установщик не найден."
}
if ($SigningEnabled) {
    Invoke-CodeSigning $SetupExecutable
}
$SetupHash = (Get-FileHash -LiteralPath $SetupExecutable -Algorithm SHA256).Hash
$SetupChecksum = "$SetupExecutable.sha256"
"$SetupHash *$([IO.Path]::GetFileName($SetupExecutable))" |
    Set-Content -LiteralPath $SetupChecksum -Encoding ascii
Write-Host "Готово: $SetupExecutable"
Write-Host "Контрольная сумма: $SetupChecksum"
Write-Host "SHA-256: $SetupHash"
