<#
.SYNOPSIS
  Install ai-defense into a local virtualenv (.venv) and verify it.
.EXAMPLE
  .\install.ps1                      # core + dev + mcp extras (runs tests + demo)
  .\install.ps1 -Extras "dev"        # pick extras explicitly (comma-separated)
  .\install.ps1 -Extras "dev,aws,mcp"
#>
param(
    [string]$Extras = "dev,mcp",
    [string]$Venv = ".venv"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host ">> Creating virtualenv in $Venv"
python -m venv $Venv
$py = Join-Path $Venv "Scripts\python.exe"

Write-Host ">> Upgrading pip"
& $py -m pip install --upgrade pip | Out-Null

Write-Host ">> Installing ai-defense (editable) with extras: [$Extras]"
& $py -m pip install -e ".[$Extras]"

Write-Host ">> Running the test suite"
& $py -m pytest -q

Write-Host ">> Running the end-to-end demo"
& $py -m ai_defense demo

Write-Host ""
Write-Host "Done. Activate the environment with:"
Write-Host "    $Venv\Scripts\Activate.ps1"
Write-Host ""
Write-Host "Try:"
Write-Host "    python -m ai_defense demo"
Write-Host "    python -m ai_defense mcp --db sqlite+pysqlite:///ai.db"
Write-Host "    register-vps --help"
