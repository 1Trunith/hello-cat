#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

VENV_PY=".venv/bin/python"
[ -f "$VENV_PY" ] || VENV_PY=".venv/Scripts/python.exe"

if [ ! -f "$VENV_PY" ]; then
    echo "[!] No virtual environment found. Run ./setup.sh once first."
    exit 1
fi

exec "$VENV_PY" hello-cat.py "$@"
