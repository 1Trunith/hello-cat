#!/usr/bin/env bash
# Hello Cat launcher - Linux/Mac/WSL
# Installs dependencies, then launches the interactive tool.
set -e
cd "$(dirname "$0")"

PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done
if [ -z "$PYTHON_BIN" ]; then
    echo "[!] No working Python interpreter found on PATH. Install Python 3 and try again."
    exit 1
fi

echo "[*] Installing dependencies..."
"$PYTHON_BIN" -m pip install -r requirements.txt --quiet \
    || "$PYTHON_BIN" -m pip install -r requirements.txt --break-system-packages --quiet \
    || echo "[!] Dependency install failed - continuing anyway, some modules may not work."

clear
exec "$PYTHON_BIN" hello-cat.py "$@"
