#!/usr/bin/env bash
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

VENV_DIR=".venv"
STAMP_FILE="$VENV_DIR/.deps_installed"
REQ_HASH_FILE="$VENV_DIR/.requirements_hash"

if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment in $VENV_DIR ..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

VENV_PY="$VENV_DIR/bin/python"
[ -f "$VENV_PY" ] || VENV_PY="$VENV_DIR/Scripts/python.exe"

CURRENT_HASH=$("$PYTHON_BIN" - <<'PYEOF'
import hashlib
with open("requirements.txt", "rb") as f:
    print(hashlib.sha256(f.read()).hexdigest())
PYEOF
)
PREVIOUS_HASH=""
[ -f "$REQ_HASH_FILE" ] && PREVIOUS_HASH=$(cat "$REQ_HASH_FILE")

if [ ! -f "$STAMP_FILE" ] || [ "$CURRENT_HASH" != "$PREVIOUS_HASH" ]; then
    echo "[*] Installing/updating dependencies into $VENV_DIR ..."
    "$VENV_PY" -m pip install --upgrade pip --quiet
    "$VENV_PY" -m pip install -r requirements.txt --quiet
    echo "$CURRENT_HASH" > "$REQ_HASH_FILE"
    touch "$STAMP_FILE"
    echo "[+] Setup complete. Dependencies installed permanently in $VENV_DIR."
else
    echo "[+] Dependencies already installed and up to date - nothing to do."
fi

echo "[*] Launching Hello Cat..."
echo
exec "$VENV_PY" hello-cat.py "$@"
