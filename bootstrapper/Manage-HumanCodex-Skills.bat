@echo off
setlocal
set "HC_SKILL_ROOT=%~dp0"
if not exist "%HC_SKILL_ROOT%source\core\human_codex" set "HC_SKILL_ROOT=%~dp0.."
for %%I in ("%HC_SKILL_ROOT%") do set "HC_SKILL_ROOT=%%~fI"
set "PYTHONPATH=%HC_SKILL_ROOT%\source\core"
set "PYTHONDONTWRITEBYTECODE=1"
set "PYTHONIOENCODING=utf-8"
set "HUMAN_CODEX_DATA_ROOT=%HC_SKILL_ROOT%\HumanCodexData"
if exist "%HC_SKILL_ROOT%\runtime\python\python.exe" (
  set "PYTHONNOUSERSITE=1"
  set "PYTHONSAFEPATH=1"
  "%HC_SKILL_ROOT%\runtime\python\python.exe" -m human_codex skills %*
  exit /b %ERRORLEVEL%
)
py -3.12 -m human_codex skills %*
exit /b %ERRORLEVEL%
