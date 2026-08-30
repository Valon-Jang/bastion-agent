@echo off
setlocal
set "PYTHONPATH=%~dp0..\source\core"
pushd "%~dp0.."

py -3.12 -m unittest discover -s tests -v
if errorlevel 1 goto :failed
node --test tests\node\*.test.cjs
if errorlevel 1 goto :failed
py -3.12 -m human_codex schema verify
if errorlevel 1 goto :failed
call npm run build
if errorlevel 1 goto :failed

if exist "artifacts\test\m3-safe-edit-smoke.json" del /q "artifacts\test\m3-safe-edit-smoke.json"
py -3.12 scripts\m3_safe_edit_smoke.py
if errorlevel 1 goto :turn_failed
findstr /C:"\"status\": \"pass\"" "artifacts\test\m3-safe-edit-smoke.json" >nul
if errorlevel 1 goto :turn_failed

popd
exit /b 0

:turn_failed
echo M3 real safe edit/test smoke failed. Inspect artifacts\test\m3-safe-edit-smoke.json.
popd
exit /b 2

:failed
set "VERIFY_EXIT=%ERRORLEVEL%"
popd
exit /b %VERIFY_EXIT%
