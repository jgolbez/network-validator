@echo off
REM Debug version - shows console window so we can see what's happening

REM Get the directory where this batch file is located
setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0

echo.
echo ========================================
echo Network Validator - Debug Mode
echo ========================================
echo.
echo Script Directory: %SCRIPT_DIR%
echo.

REM Run PowerShell script with visible output
echo Running validator...
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%run_validator.ps1"

echo.
echo ========================================
echo Validator completed. Keeping window open for 10 seconds...
echo ========================================
echo.

timeout /t 10

exit /b 0
