#!/usr/bin/env bash
# Launch the AI Defense MCP server (durable, shares a DB with the operator CLI).
# Usage: ./run-mcp.sh [DB_URL]
#   default DB is ./ai.db next to this script.
set -euo pipefail
cd "$(dirname "$0")"

DB="${1:-sqlite+pysqlite:///ai.db}"

if [ -x ".venv/bin/ai-defense" ]; then
    EXE=".venv/bin/ai-defense"
elif [ -x ".venv/Scripts/ai-defense.exe" ]; then
    EXE=".venv/Scripts/ai-defense.exe"
else
    echo "ai-defense not found in .venv - run ./install.sh first" >&2
    exit 1
fi

exec "$EXE" mcp --db "$DB"
