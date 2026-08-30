@echo off
setlocal
set "PYTHONPATH=%~dp0..\source\core"
py -3.12 -m human_codex diagnostics --json --output "%~dp0..\artifacts\diagnostics\gate0-latest.json"
exit /b %ERRORLEVEL%
