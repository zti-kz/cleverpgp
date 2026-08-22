$ErrorActionPreference = "Stop"
$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonInstaller = Join-Path $ProjectDirectory "install_python.ps1"
$VirtualDiskInstaller = Join-Path $ProjectDirectory "install_virtual_disk.ps1"
$PythonExecutable = Join-Path $ProjectDirectory ".venv\Scripts\python.exe"

Write-Host "Установка Clever PGP..."

if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
    $BasePythonOutput = & $PythonInstaller
    $BasePython = [string]($BasePythonOutput | Select-Object -Last 1)
    if (-not (Test-Path -LiteralPath $BasePython -PathType Leaf)) {
        throw "Не удалось определить установленный Python 3.14."
    }
    & $BasePython -m venv (Join-Path $ProjectDirectory ".venv")
    if ($LASTEXITCODE -ne 0) {
        throw "Не удалось создать окружение Clever PGP."
    }
}

& $VirtualDiskInstaller

& $PythonExecutable -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw "Не удалось обновить установщик Python-пакетов."
}
& $PythonExecutable -m pip install -e "${ProjectDirectory}[dev]"
if ($LASTEXITCODE -ne 0) {
    throw "Не удалось установить Python-зависимости Clever PGP."
}
& $PythonExecutable (Join-Path $ProjectDirectory "scripts\download_models.py")
if ($LASTEXITCODE -ne 0) {
    throw "Не удалось установить локальные модели распознавания лица."
}
& (Join-Path $ProjectDirectory "install_context_menu.ps1")

& $PythonExecutable -c "import cv2, nacl, numpy, PySide6; from refuse import high; import biopgp; print('Clever PGP', biopgp.__version__, '- зависимости проверены')"
if ($LASTEXITCODE -ne 0) {
    throw "Проверка зависимостей Clever PGP не пройдена."
}

Write-Host "Clever PGP полностью установлен и готов к запуску."
Write-Host "Запуск: .\run.ps1"
