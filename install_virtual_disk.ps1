$ErrorActionPreference = "Stop"

$InstallerUrl = "https://github.com/winfsp/winfsp/releases/download/v2.2B3/winfsp-2.2.26194.msi"
$ExpectedSha256 = "7B41020618CDCC33D699D0E15C1DF660F0762A09B57080049C565857AC00BD9D"
$DownloadDirectory = Join-Path $env:TEMP "CleverPGP-WinFsp"
$InstallerPath = Join-Path $DownloadDirectory "winfsp-2.2.26194.msi"

function Get-WinFspInstallDirectory {
    $RegistryPaths = @(
        "HKLM:\SOFTWARE\WinFsp",
        "HKLM:\SOFTWARE\WOW6432Node\WinFsp"
    )
    foreach ($RegistryPath in $RegistryPaths) {
        $Entry = Get-ItemProperty -LiteralPath $RegistryPath -ErrorAction SilentlyContinue
        if ($null -ne $Entry -and $Entry.InstallDir) {
            $Candidate = [string]$Entry.InstallDir
            $Library = Join-Path $Candidate "bin\winfsp-x64.dll"
            if (Test-Path -LiteralPath $Library -PathType Leaf) {
                return $Candidate
            }
        }
    }
    return $null
}

$ExistingInstallation = Get-WinFspInstallDirectory
if ($null -ne $ExistingInstallation) {
    Write-Host "WinFsp уже установлен."
    return
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path $DownloadDirectory | Out-Null

$DownloadRequired = $true
if (Test-Path -LiteralPath $InstallerPath -PathType Leaf) {
    $CachedSha256 = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
    $DownloadRequired = $CachedSha256 -ne $ExpectedSha256
}
if ($DownloadRequired) {
    Write-Host "Загрузка компонента виртуального диска WinFsp..."
    Invoke-WebRequest -UseBasicParsing -Uri $InstallerUrl -OutFile $InstallerPath
}

$ActualSha256 = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
if ($ActualSha256 -ne $ExpectedSha256) {
    throw "Проверка установщика WinFsp не пройдена. Установка отменена."
}

$Arguments = "/i `"$InstallerPath`" /passive /norestart"
$Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -PassThru
if ($Process.ExitCode -notin @(0, 3010)) {
    throw "Установка WinFsp завершилась с кодом $($Process.ExitCode)."
}

if ($null -eq (Get-WinFspInstallDirectory)) {
    throw "WinFsp установлен, но его библиотека не найдена."
}

if ($Process.ExitCode -eq 3010) {
    Write-Host "Для завершения установки WinFsp потребуется перезагрузка Windows."
} else {
    Write-Host "WinFsp установлен."
}
