@echo off
setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%SCRIPT_DIR%run_validator_network2.ps1"
exit /b 0
