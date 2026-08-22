$ErrorActionPreference = "Stop"
$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExecutable = Join-Path $ProjectDirectory ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
    throw "Виртуальное окружение не найдено. Сначала выполните .\setup.ps1"
}

& $PythonExecutable -m biopgp
