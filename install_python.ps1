$ErrorActionPreference = "Stop"

$PythonVersion = "3.14.7"
$InstallerUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe"
$ExpectedSha256 = "9D9EB2709EF81BF5CD30DB3C2096BDBC4EA10087C22E62F27D356B36F6AE9649"
$DownloadDirectory = Join-Path $env:TEMP "CleverPGP-Python"
$InstallerPath = Join-Path $DownloadDirectory "python-$PythonVersion-amd64.exe"
$InstallDirectory = Join-Path $env:LOCALAPPDATA "Programs\Python\Python314"

function Get-Python314Path {
    $Launcher = Get-Command "py.exe" -ErrorAction SilentlyContinue
    if ($null -ne $Launcher) {
        $Resolved = & $Launcher.Source -3.14 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $Resolved) {
            $Candidate = ([string]$Resolved).Trim()
            if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
                return $Candidate
            }
        }
    }

    $PythonCommand = Get-Command "python.exe" -ErrorAction SilentlyContinue
    if ($null -ne $PythonCommand) {
        $Resolved = & $PythonCommand.Source -c "import sys; print(sys.executable if sys.version_info[:2] == (3, 14) else '')" 2>$null
        if ($LASTEXITCODE -eq 0 -and $Resolved) {
            $Candidate = ([string]$Resolved).Trim()
            if (Test-Path -LiteralPath $Candidate -PathType Leaf) {
                return $Candidate
            }
        }
    }

    $InstalledCandidate = Join-Path $InstallDirectory "python.exe"
    if (Test-Path -LiteralPath $InstalledCandidate -PathType Leaf) {
        return $InstalledCandidate
    }
    return $null
}

$PythonExecutable = Get-Python314Path
if ($null -ne $PythonExecutable) {
    Write-Host "Python 3.14 уже установлен."
    Write-Output $PythonExecutable
    return
}

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "Текущий установщик Clever PGP поддерживает только 64-битную Windows."
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path $DownloadDirectory | Out-Null

$DownloadRequired = $true
if (Test-Path -LiteralPath $InstallerPath -PathType Leaf) {
    $CachedSha256 = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
    $DownloadRequired = $CachedSha256 -ne $ExpectedSha256
}
if ($DownloadRequired) {
    Write-Host "Загрузка Python $PythonVersion..."
    Invoke-WebRequest -UseBasicParsing -Uri $InstallerUrl -OutFile $InstallerPath
}

$ActualSha256 = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
if ($ActualSha256 -ne $ExpectedSha256) {
    throw "Проверка установщика Python не пройдена. Установка отменена."
}

$Arguments = @(
    "/quiet",
    "InstallAllUsers=0",
    "TargetDir=`"$InstallDirectory`"",
    "Include_launcher=1",
    "InstallLauncherAllUsers=0",
    "Include_pip=1",
    "Include_test=0",
    "Include_doc=0",
    "PrependPath=0",
    "Shortcuts=0"
)
$Process = Start-Process -FilePath $InstallerPath -ArgumentList $Arguments -Wait -PassThru
if ($Process.ExitCode -notin @(0, 3010)) {
    throw "Установка Python завершилась с кодом $($Process.ExitCode)."
}

$PythonExecutable = Get-Python314Path
if ($null -eq $PythonExecutable) {
    throw "Python установлен, но python.exe не найден."
}

Write-Host "Python $PythonVersion установлен."
Write-Output $PythonExecutable
