@echo off
setlocal
title OnyxOps Sentinel - Down Detector & Threat Diagnostic Bot
chcp 65001 >nul

set "PYTHON_BIN=python"
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
        set "PYTHON_BIN=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    ) else if exist "C:\Program Files\Python311\python.exe" (
        set "PYTHON_BIN=C:\Program Files\Python311\python.exe"
    ) else (
        echo [!] Python was not found in PATH or standard installation directories.
        echo [*] Run: winget install Python.Python.3.11
        pause
        exit /b 1
    )
)

"%PYTHON_BIN%" main.py %*
pause
