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
if exist "artifacts\test\m2-real-turn-smoke.json" del /q "artifacts\test\m2-real-turn-smoke.json"
py -3.12 -m human_codex app-server turn-smoke --json --output "artifacts\test\m2-real-turn-smoke.json" --timeout 120
if errorlevel 1 goto :turn_failed
if not exist "artifacts\test\m2-real-turn-smoke.json" goto :turn_failed
findstr /C:"\"status\": \"pass\"" "artifacts\test\m2-real-turn-smoke.json" >nul
if errorlevel 1 goto :turn_failed

popd
exit /b 0

:turn_failed
echo Real Codex Turn verification failed. Check app-specific login with:
echo   py -3.12 -m human_codex codex status --json
echo Login requires user interaction:
echo   py -3.12 -m human_codex codex login --device-auth
popd
exit /b 2

:failed
set "VERIFY_EXIT=%ERRORLEVEL%"
popd
exit /b %VERIFY_EXIT%
