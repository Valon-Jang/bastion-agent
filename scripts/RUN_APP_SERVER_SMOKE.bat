@echo off
setlocal
set "PYTHONPATH=%~dp0..\source\core"
py -3.12 -m human_codex app-server smoke --json --output "%~dp0..\artifacts\test\app-server-smoke-latest.json"
exit /b %ERRORLEVEL%
