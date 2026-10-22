@echo off
setlocal DisableDelayedExpansion
set "DEMO_NODE=%~dp0runtime\win-x64\node.exe"
if not exist "%DEMO_NODE%" goto missing
cd /d "%~dp0"
set "UWS_USE_FALLBACK=1"
"%DEMO_NODE%" "%~dp0verify-package.mjs" --integrity
if errorlevel 1 goto failed
"%DEMO_NODE%" --test "%~dp0app\test\delivery-flow.test.mjs"
if errorlevel 1 goto failed
echo.
echo PASS: package integrity, real payment, two modes and idempotency checks.
pause
exit /b 0
:missing
echo Bundled Node is missing. Fully extract the delivery ZIP first.
goto failed
:failed
echo CHECK FAILED. Keep this output for diagnosis.
pause
exit /b 1
