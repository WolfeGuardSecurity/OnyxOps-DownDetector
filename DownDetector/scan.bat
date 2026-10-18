@echo off
setlocal
title OnyxOps Sentinel - Deep Target Scanner

if "%~1"=="" (
    echo ===================================================
    echo     OnyxOps Sentinel - Target Scanner
    echo ===================================================
    set /p TARGET_URL="Enter Target URL to Deep Scan: "
) else (
    set TARGET_URL=%~1
)

set "PYTHON_BIN=python"
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set "PYTHON_BIN=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    ) else if exist "C:\Program Files\Python311\python.exe" (
        set "PYTHON_BIN=C:\Program Files\Python311\python.exe"
    ) else (
        echo [!] Python was not found in PATH or standard installation directories.
        pause
        exit /b 1
    )
)

"%PYTHON_BIN%" main.py scan %TARGET_URL%
pause
