@echo off
title alpha-guard - temporary disable
cd /d "%~dp0"

echo.
echo  ============================================
echo    alpha-guard  temporary disable
echo    default: 2 minutes, then auto re-enable
echo  ============================================
echo.

where powershell >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] powershell not found.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0guard-pause.ps1" -Minutes 2

if errorlevel 1 (
    echo.
    echo  [FAILED] The script exited with an error. Nothing was left changed.
    pause
)
