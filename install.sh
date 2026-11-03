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

# Find a real Python 3 interpreter (skip the Windows Store alias stub).
BOOT=""
for cand in python3 python py; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)' >/dev/null 2>&1; then
            BOOT="$cand"
            break
        fi
    fi
done
if [ -z "$BOOT" ]; then
    echo "error: no Python >= 3.11 found on PATH (tried python3, python, py)" >&2
    exit 1
fi
echo ">> Using interpreter: $($BOOT -c 'import sys; print(sys.executable)')"

echo ">> Creating virtualenv in $VENV"
"$BOOT" -m venv "$VENV"
# venv layout differs: POSIX -> bin/, Windows -> Scripts/
if [ -x "$VENV/bin/python" ]; then
    PY="$VENV/bin/python"
else
    PY="$VENV/Scripts/python.exe"
fi

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
