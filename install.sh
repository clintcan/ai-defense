#!/usr/bin/env bash
# Install ai-defense into a local virtualenv and verify it.
#
# Usage:
#   ./install.sh            # core + dev + mcp extras (runs tests + demo)
#   ./install.sh dev        # pick extras explicitly (comma-separated)
#   ./install.sh dev,aws,mcp
set -euo pipefail

EXTRAS="${1:-dev,mcp}"
VENV="${VENV:-.venv}"
cd "$(dirname "$0")"

echo ">> Creating virtualenv in $VENV"
python3 -m venv "$VENV"
PY="$VENV/bin/python"

echo ">> Upgrading pip"
"$PY" -m pip install --upgrade pip >/dev/null

echo ">> Installing ai-defense (editable) with extras: [$EXTRAS]"
"$PY" -m pip install -e ".[$EXTRAS]"

echo ">> Running the test suite"
"$PY" -m pytest -q

echo ">> Running the end-to-end demo"
"$PY" -m ai_defense demo

cat <<EOF

Done. Activate the environment with:
    source $VENV/bin/activate

Try:
    python -m ai_defense demo                      # local end-to-end demo
    python -m ai_defense mcp --db sqlite+pysqlite:///ai.db   # chat/MCP server (durable)
    register-vps --help                            # onboard a VPS (operator)
EOF
