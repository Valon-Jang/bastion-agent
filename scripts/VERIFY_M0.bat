@echo off
setlocal
set "PYTHONPATH=%~dp0..\source\core"
pushd "%~dp0.."
py -3.12 -m unittest discover -s tests -v
if errorlevel 1 goto :failed
py -3.12 -m human_codex schema verify
if errorlevel 1 goto :failed
py -3.12 -m human_codex diagnostics --json --output "artifacts\diagnostics\gate0-latest.json"
if errorlevel 1 goto :failed
py -3.12 -m human_codex app-server smoke --json --output "artifacts\test\app-server-smoke-latest.json"
if errorlevel 1 goto :failed
popd
exit /b 0

:failed
set "VERIFY_EXIT=%ERRORLEVEL%"
popd
exit /b %VERIFY_EXIT%
