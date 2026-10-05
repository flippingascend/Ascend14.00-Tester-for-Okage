@echo off
setlocal
title Send ELF to PS5 loader

cd /d "%~dp0"

set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo [x] No Python 3 found. Install from https://www.python.org/downloads/
    pause
    exit /b 1
)

set "IP=%~1"
set "ELF=%~2"

if "%IP%"=="" (
    echo Scanning the LAN for the loader...
    echo.
    %PY% send_elf.py scan
    echo.
    echo Usage: SEND_ELF.bat ^<console-ip^> ^<payload.elf^>
    pause
    exit /b 0
)

if "%ELF%"=="" (
    echo [x] No payload given.
    echo     SEND_ELF.bat ^<console-ip^> ^<payload.elf^>
    pause
    exit /b 1
)

%PY% send_elf.py %IP% "%ELF%"
echo.
pause