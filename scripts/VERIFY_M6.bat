@echo off
setlocal
set "PYTHONPATH=%~dp0..\source\core;."
pushd "%~dp0.."

py -3.12 -m unittest discover -s tests -v
if errorlevel 1 goto :failed
node --test tests\node\*.test.cjs
if errorlevel 1 goto :failed
py -3.12 -m human_codex schema verify
if errorlevel 1 goto :failed
py -3.12 scripts\security_config_smoke.py
if errorlevel 1 goto :failed
call npm run build
if errorlevel 1 goto :failed
py -3.12 scripts\m6_portable_smoke.py
if errorlevel 1 goto :smoke_failed
findstr /C:"\"status\": \"pass\"" "artifacts\test\m6-portable-smoke.json" >nul
if errorlevel 1 goto :smoke_failed

popd
exit /b 0

:smoke_failed
echo M6 portable smoke failed. Inspect artifacts\test\m6-portable-smoke.json.
popd
exit /b 2

:failed
set "VERIFY_EXIT=%ERRORLEVEL%"
popd
exit /b %VERIFY_EXIT%
