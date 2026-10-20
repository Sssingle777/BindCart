@echo off
setlocal DisableDelayedExpansion
set "DEMO_NODE=%~dp0runtime\win-x64\node.exe"
if not exist "%DEMO_NODE%" goto missing
"%DEMO_NODE%" "%~dp0portable.mjs" start %*
set "DEMO_RESULT=%ERRORLEVEL%"
if "%DEMO_RESULT%"=="0" exit /b 0
echo.
echo Startup failed. Read the log paths above.
pause
exit /b %DEMO_RESULT%
:missing
echo The bundled Windows runtime is missing. Extract the whole ZIP first.
pause
exit /b 1
