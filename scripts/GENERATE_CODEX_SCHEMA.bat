@echo off
setlocal
set "PYTHONPATH=%~dp0..\source\core"
py -3.12 -m human_codex schema generate
exit /b %ERRORLEVEL%
