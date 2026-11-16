@echo off
REM Hello Cat launcher - Windows cmd/PowerShell
REM Installs dependencies, then launches the interactive tool.
cd /d "%~dp0"

echo [*] Installing dependencies...
python -m pip install -r requirements.txt --quiet >nul 2>&1
if errorlevel 1 (
    echo [!] Dependency install failed - continuing anyway, some modules may not work.
)

cls
python hello-cat.py %*
