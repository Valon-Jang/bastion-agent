@echo off
setlocal
set "PYTHONPATH=%~dp0..\source\core"
pushd "%~dp0.."

py -3.12 -m unittest discover -s tests -v
if errorlevel 1 goto :failed
node --test tests\node\*.test.cjs
if errorlevel 1 goto :failed

if not exist "node_modules\electron\package.json" goto :dependency_needed
if not exist "node_modules\react\package.json" goto :dependency_needed
if not exist "node_modules\vite\package.json" goto :dependency_needed

call npm run build
if errorlevel 1 goto :failed
if exist "artifacts\test\m1-electron-smoke.json" del /q "artifacts\test\m1-electron-smoke.json"
call "node_modules\.bin\electron.cmd" "app\electron\smoke.cjs"
if errorlevel 1 goto :failed
if not exist "artifacts\test\m1-electron-smoke.json" goto :artifact_failed
findstr /C:"\"status\": \"pass\"" "artifacts\test\m1-electron-smoke.json" >nul
if errorlevel 1 goto :artifact_failed

popd
exit /b 0

:dependency_needed
echo Electron/React runtime dependencies are not installed. No installation was attempted.
echo Review DEPENDENCY_PLAN.md and, after approval, run its exact npm install commands.
popd
exit /b 3

:failed
set "VERIFY_EXIT=%ERRORLEVEL%"
popd
exit /b %VERIFY_EXIT%

:artifact_failed
echo Electron smoke artifact is missing or does not report PASS.
popd
exit /b 2
