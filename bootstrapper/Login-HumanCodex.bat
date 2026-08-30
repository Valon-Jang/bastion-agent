@echo off
setlocal EnableExtensions
set "HC_ROOT=%~dp0"
set "HC_PYTHON=%HC_ROOT%runtime\python\python.exe"
set "HC_CODEX=%HC_ROOT%runtime\codex\codex.exe"
set "HUMAN_CODEX_DATA_ROOT=%HC_ROOT%HumanCodexData"

if not exist "%HC_PYTHON%" goto :missing
if not exist "%HC_CODEX%" goto :missing
if not exist "%HC_ROOT%source\core\human_codex\__main__.py" goto :missing

if not exist "%HUMAN_CODEX_DATA_ROOT%" mkdir "%HUMAN_CODEX_DATA_ROOT%" 2>nul
if not exist "%HC_ROOT%Workspace" mkdir "%HC_ROOT%Workspace" 2>nul
if not exist "%HUMAN_CODEX_DATA_ROOT%" goto :not_writable
if not exist "%HC_ROOT%Workspace" goto :not_writable

rem Use only bundled runtimes and the app-specific Codex home inside this folder.
set "PYTHONHOME="
set "PYTHONPATH=%HC_ROOT%source\core"
set "PYTHONNOUSERSITE=1"
set "PYTHONDONTWRITEBYTECODE=1"
set "PYTHONSAFEPATH=1"
set "PYTHONSTARTUP="
set "PYTHONINSPECT="
set "PYTHONUSERBASE="
set "NODE_OPTIONS="
set "ELECTRON_RUN_AS_NODE="
set "PATH=%HC_ROOT%runtime\codex;%SystemRoot%\System32;%SystemRoot%"

echo Human Codex will open the ChatGPT sign-in flow in your browser.
"%HC_PYTHON%" -B -s -m human_codex codex login
set "HC_EXIT=%ERRORLEVEL%"
if not "%HC_EXIT%"=="0" goto :login_failed

echo.
echo Login completed. You can now run Launch-HumanCodex.bat.
pause
exit /b 0

:login_failed
echo.
echo Human Codex login did not complete. Check company browser and network policy.
pause
exit /b %HC_EXIT%

:not_writable
echo Human Codex cannot write to this folder. Move the full folder to a writable NTFS/ReFS location and try again.
pause
exit /b 2

:missing
echo Human Codex portable runtime is incomplete. Extract the full release folder and try again.
pause
exit /b 2
