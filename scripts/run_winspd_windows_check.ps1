param([switch]$Elevated)

$ErrorActionPreference = "Stop"

$ProjectDirectory = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$PythonExecutable = Join-Path $ProjectDirectory ".venv\Scripts\python.exe"
$CheckScript = Join-Path $ProjectDirectory "scripts\check_winspd_windows_disk.py"
$Marker = Join-Path $ProjectDirectory "build\winspd-windows-disk-check.json"
$VendorDirectory = Join-Path $ProjectDirectory "build\vendor"
$WinSpdInstaller = Join-Path $VendorDirectory "winspd-1.0.20357.msi"
$WinSpdUrl = "https://github.com/winfsp/winspd/releases/download/v1.0B1/winspd-1.0.20357.msi"
$WinSpdSha256 = "F1157EEF805DCBEC78A477F2B4EE5ABC0049C8A9329444E5D18CAB01D3604265"

if ($Elevated) {
    trap {
        [pscustomobject]@{
            status = "error"
            message = $_.Exception.Message
            details = ($_ | Out-String).Trim()
        } |
            ConvertTo-Json -Depth 3 |
            Set-Content -LiteralPath $Marker -Encoding utf8
        exit 1
    }
}

if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
    throw "Среда разработки Clever PGP не найдена."
}

if (-not $Elevated) {
    $PowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $ElevatedArguments = @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "`"$PSCommandPath`"",
        "-Elevated"
    )
    $ElevatedProcess = Start-Process `
        -FilePath $PowerShell `
        -ArgumentList $ElevatedArguments `
        -Verb RunAs `
        -Wait `
        -PassThru
    if ($ElevatedProcess.ExitCode -ne 0) {
        $Details = if (Test-Path -LiteralPath $Marker -PathType Leaf) {
            Get-Content -LiteralPath $Marker -Raw
        } else {
            "Подробный отчёт не создан."
        }
        throw (
            "Системная проверка WinSpd завершилась с кодом " +
            "$($ElevatedProcess.ExitCode): $Details"
        )
    }
    if (-not (Test-Path -LiteralPath $Marker -PathType Leaf)) {
        throw "Проверка не создала итоговый отчёт."
    }
    Get-Content -LiteralPath $Marker -Raw
    return
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Проверка не получила права администратора."
}

New-Item -ItemType Directory -Path $VendorDirectory -Force | Out-Null
if (-not (Test-Path -LiteralPath $WinSpdInstaller -PathType Leaf)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -Uri $WinSpdUrl -OutFile $WinSpdInstaller
}
$InstallerHash = (Get-FileHash -LiteralPath $WinSpdInstaller -Algorithm SHA256).Hash
if ($InstallerHash -ne $WinSpdSha256) {
    throw "Проверка SHA-256 установщика WinSpd не пройдена."
}

$RegistryPaths = @(
    "HKLM:\SOFTWARE\WinSpd",
    "HKLM:\SOFTWARE\WOW6432Node\WinSpd"
)
$WinSpdRegistry = Get-ItemProperty -LiteralPath $RegistryPaths -ErrorAction SilentlyContinue |
    Select-Object -First 1
$WinSpdInstalled = $null -ne $WinSpdRegistry
if (-not $WinSpdInstalled) {
    $MsiProcess = Start-Process `
        -FilePath (Join-Path $env:SystemRoot "System32\msiexec.exe") `
        -ArgumentList @("/i", "`"$WinSpdInstaller`"", "/passive", "/norestart") `
        -Wait `
        -PassThru
    if ($MsiProcess.ExitCode -ne 0) {
        throw "Установка WinSpd завершилась с кодом $($MsiProcess.ExitCode)."
    }
}
$WinSpdRegistry = Get-ItemProperty -LiteralPath $RegistryPaths -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $WinSpdRegistry) {
    throw "WinSpd не зарегистрирован после установки."
}
$InstallDirectory = [string]$WinSpdRegistry.InstallDir
$InstalledDll = Join-Path $InstallDirectory "sys\winspd-x64.dll"
if (-not (Test-Path -LiteralPath $InstalledDll -PathType Leaf)) {
    throw "Установленная библиотека WinSpd не найдена."
}
$env:CLEVERPGP_WINSPD_DLL = $InstalledDll

if (Test-Path -LiteralPath $Marker -PathType Leaf) {
    Remove-Item -LiteralPath $Marker -Force
}

$Arguments = @(
    $CheckScript,
    "--marker",
    $Marker,
    "--capacity-mib",
    "128",
    "--file-system",
    "NTFS",
    "--confirm-ephemeral-format"
)
& $PythonExecutable @Arguments
if ($LASTEXITCODE -ne 0) {
    throw "Системная проверка WinSpd завершилась с кодом $LASTEXITCODE."
}
if (-not (Test-Path -LiteralPath $Marker -PathType Leaf)) {
    throw "Проверка не создала итоговый отчёт."
}
Get-Content -LiteralPath $Marker -Raw
