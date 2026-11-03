@echo off
rem Launch the AI Defense MCP server (durable; shares a DB with the operator CLI).
rem Usage: run-mcp.bat [DB_URL]   (default DB is ai.db next to this script)
setlocal
cd /d "%~dp0"

set "DB=%~1"
if "%DB%"=="" set "DB=sqlite+pysqlite:///ai.db"

if exist ".venv\Scripts\ai-defense.exe" (
    ".venv\Scripts\ai-defense.exe" mcp --db "%DB%"
) else (
    echo ai-defense not found in .venv - run install.ps1 first 1>&2
    exit /b 1
)
