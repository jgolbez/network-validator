@echo off
REM Batch file to run the validator silently and open results in Chrome
REM This file is called by the Windows desktop shortcut

setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0

REM Run PowerShell script silently with no profile and unrestricted execution
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%SCRIPT_DIR%run_validator.ps1"

exit /b 0
