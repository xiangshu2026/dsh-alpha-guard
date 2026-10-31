@echo off
title alpha-guard - approve one install
cd /d "%~dp0"

echo.
echo  ============================================
echo    alpha-guard  -  approve ONE install
echo    valid for 2 minutes, single use
echo  ============================================
echo.

where powershell >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] powershell not found.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0approve-install.ps1"

echo.
pause
