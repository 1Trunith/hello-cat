@echo off
cd /d "%~dp0"

set VENV_PY=.venv\Scripts\python.exe

if not exist "%VENV_PY%" (
    echo [!] No virtual environment found. Run setup.bat once first.
    exit /b 1
)

"%VENV_PY%" hello-cat.py %*
