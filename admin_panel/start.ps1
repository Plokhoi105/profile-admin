$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$pythonCandidates = @(
    "C:\Users\Alex\project_env\Scripts\python.exe",
    "C:\Users\Alex\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
)
$python = $pythonCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $python) {
    throw "Python 3.10+ not found"
}
Set-Location -LiteralPath $root
& $python -m admin_panel.app

