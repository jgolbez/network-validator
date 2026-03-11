@echo off
REM Batch file to run the validator silently and open results in Chrome
REM This file is called by the Windows desktop shortcut

REM Get the directory where this batch file is located
setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0

REM Run PowerShell script silently
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%run_validator.ps1"

REM Exit without leaving a window open
exit /b 0
