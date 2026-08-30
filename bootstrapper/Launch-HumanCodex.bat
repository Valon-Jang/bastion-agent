@echo off
setlocal EnableExtensions
set "HC_ROOT=%~dp0"
set "HC_PYTHON=%HC_ROOT%runtime\python\python.exe"
set "HC_CODEX=%HC_ROOT%runtime\codex\codex.exe"
set "HC_ELECTRON=%HC_ROOT%node_modules\electron\dist\electron.exe"
set "HUMAN_CODEX_DATA_ROOT=%HC_ROOT%HumanCodexData"

if not exist "%HC_PYTHON%" goto :missing
if not exist "%HC_CODEX%" goto :missing
if not exist "%HC_ELECTRON%" goto :missing
if not exist "%HC_ROOT%app\electron\main.cjs" goto :missing

if not exist "%HUMAN_CODEX_DATA_ROOT%" mkdir "%HUMAN_CODEX_DATA_ROOT%" 2>nul
if not exist "%HC_ROOT%Workspace" mkdir "%HC_ROOT%Workspace" 2>nul
if not exist "%HUMAN_CODEX_DATA_ROOT%" goto :not_writable
if not exist "%HC_ROOT%Workspace" goto :not_writable

rem Process-scoped only: no registry, installer, or global PATH change.
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
set "PATH=%HC_ROOT%runtime\codex;%PATH%"

if /I not "%~1"=="--portable-smoke" goto :launch
if not "%HUMAN_CODEX_PORTABLE_SMOKE%"=="1" goto :smoke_denied
"%HC_ELECTRON%" "%HC_ROOT%app\electron\smoke.cjs"
exit /b %ERRORLEVEL%

:launch
start "Human Codex" "%HC_ELECTRON%" "%HC_ROOT%app\electron\main.cjs"
exit /b 0

:smoke_denied
echo Human Codex portable smoke mode requires the isolated verifier environment.
exit /b 2

:not_writable
echo Human Codex cannot write to this folder. Move the full folder to a writable NTFS/ReFS location and try again.
pause
exit /b 2

:missing
echo Human Codex portable runtime is incomplete. Extract the full release folder and try again.
exit /b 2
