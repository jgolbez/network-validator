@echo off
setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%SCRIPT_DIR%start_docs.ps1"
exit /b 0
