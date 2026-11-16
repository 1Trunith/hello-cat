@echo off
cd /d "%~dp0"

set VENV_DIR=.venv
set STAMP_FILE=%VENV_DIR%\.deps_installed
set REQ_HASH_FILE=%VENV_DIR%\.requirements_hash

if not exist "%VENV_DIR%" (
    echo [*] Creating virtual environment in %VENV_DIR% ...
    python -m venv "%VENV_DIR%"
)

set VENV_PY=%VENV_DIR%\Scripts\python.exe

for /f %%i in ('%VENV_PY% -c "import hashlib;print(hashlib.sha256(open('requirements.txt','rb').read()).hexdigest())"') do set CURRENT_HASH=%%i

set PREVIOUS_HASH=
if exist "%REQ_HASH_FILE%" set /p PREVIOUS_HASH=<"%REQ_HASH_FILE%"

if not exist "%STAMP_FILE%" (
    goto :install
)
if not "%CURRENT_HASH%"=="%PREVIOUS_HASH%" (
    goto :install
)
echo [+] Dependencies already installed and up to date - nothing to do.
goto :launch

:install
echo [*] Installing/updating dependencies into %VENV_DIR% ...
"%VENV_PY%" -m pip install --upgrade pip --quiet
"%VENV_PY%" -m pip install -r requirements.txt --quiet
> "%REQ_HASH_FILE%" echo %CURRENT_HASH%
type nul > "%STAMP_FILE%"
echo [+] Setup complete. Dependencies installed permanently in %VENV_DIR%.

:launch
echo [*] Launching Hello Cat...
echo.
"%VENV_PY%" hello-cat.py %*
