$ErrorActionPreference = "Stop"

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
$InnoInstaller = Join-Path $ToolsDirectory "innosetup-7.1.0-x64.exe"
$InnoUrl = "https://github.com/jrsoftware/issrc/releases/download/is-7_1_0/innosetup-7.1.0-x64.exe"
$InnoSha256 = "0362A383ED217D4C4239B5933866DD96D3EB2102737DA92F80F6057A4B40DF2F"
$InnoDirectory = Join-Path $ToolsDirectory "InnoSetup"
$InnoCompiler = Join-Path $InnoDirectory "ISCC.exe"
$AppVersion = "0.5.7"
$SignToolPath = $env:BIOPGP_SIGNTOOL
$SigningCertificateThumbprint = $env:BIOPGP_SIGN_CERT_SHA1
$TimestampUrl = $env:BIOPGP_TIMESTAMP_URL
$SigningEnabled = -not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)

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

function Invoke-CodeSigning([string]$Path) {
    if (-not $SigningEnabled) {
        return
    }
    if (-not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
        throw "BIOPGP_SIGNTOOL должен указывать на signtool.exe из Windows SDK."
    }
    if ([string]::IsNullOrWhiteSpace($TimestampUrl)) {
        throw "Для долговечной подписи укажите BIOPGP_TIMESTAMP_URL от поставщика сертификата."
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Файл для подписи не найден: $Path"
    }

    $NormalizedThumbprint = $SigningCertificateThumbprint.Replace(" ", "").ToUpperInvariant()
    if ($NormalizedThumbprint -notmatch '^[0-9A-F]{40}$') {
        throw "BIOPGP_SIGN_CERT_SHA1 должен содержать 40-значный отпечаток сертификата."
    }

    Write-Host "Цифровая подпись: $Path"
    & $SignToolPath sign `
        /sha1 $NormalizedThumbprint `
        /fd SHA256 `
        /tr $TimestampUrl `
        /td SHA256 `
        /v `
        $Path
    if ($LASTEXITCODE -ne 0) {
        throw "Не удалось подписать файл: $Path"
    }
    & $SignToolPath verify /pa /v $Path
    if ($LASTEXITCODE -ne 0) {
        throw "Проверка цифровой подписи не пройдена: $Path"
    }
}

if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
    throw "Сначала подготовьте среду разработки Clever PGP с помощью setup.ps1."
}

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

Write-Host "Сборка приложения..."
& $PythonExecutable -m PyInstaller `
    --noconfirm `
    --clean `
    --distpath $ApplicationDirectory `
    --workpath $PyInstallerWorkDirectory `
    (Join-Path $ProjectDirectory "packaging\biopgp.spec")
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

$InnoScript = Join-Path $ProjectDirectory "packaging\biopgp.iss"
$CompilerArguments = @(
    "/DAppVersion=$AppVersion",
    "/DAppSourceDirectory=$BundledApplication",
    "/DProjectDirectory=$ProjectDirectory",
    "/DWinFspInstaller=$WinFspInstaller",
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
Write-Host "Готово: $SetupExecutable"
Write-Host "SHA-256: $SetupHash"
