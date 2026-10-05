@echo off
setlocal
title PSN DNS Blocker

rem --- work from this script's own folder, whatever the current directory is ---
cd /d "%~dp0"

rem --- port 53 is privileged, so re-launch elevated if we are not already ---
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights for port 53...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

rem --- find a working Python 3 ---
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo [x] No Python 3 found. Install from https://www.python.org/downloads/
    echo     and tick "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)

rem --- the Windows DNS Client service owns 0.0.0.0:53 and blocks the bind ---
echo.
echo   Freeing UDP/TCP 53 from the Windows DNS Client service...
net stop Dnscache >nul 2>&1
sc config Dnscache start= demand >nul 2>&1

rem --- confirm the port is actually free before starting ---
for /f "tokens=5" %%p in ('netstat -ano -p UDP ^| findstr ":53 "') do set "PIDS=%%p"
if defined PIDS (
    echo [!] Something still holds UDP 53. PIDs: %PIDS%
    echo     Close anything suspicious, or check:  Get-Process -Id %PIDS%
    pause
    exit /b 1
)

setlocal enabledelayedexpansion
for /f "tokens=5" %%p in ('netstat -ano -p UDP ^| findstr ":53 "') do (
    echo [!] UDP 53 still occupied by PID %%p
    echo     Stop that process, then run this again.
    pause
    exit /b 1
)
endlocal

echo.
echo   Python   : %PY%
for /f "tokens=2" %%i in ('powershell -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 ^| Where-Object {$_.InterfaceAlias -eq 'Ethernet'} ^| Select-Object -First 1).IPAddress"') do set "MYIP=%%i"
if not defined MYIP set "MYIP=192.168.0.189"
echo   PC IP    : %MYIP%
echo.
echo   IMPORTANT: on the PS5 go to
echo     Settings ^> Network ^> Set Up Internet Connection ^> your WiFi ^> Custom
echo   and set DNS to Manual with primary AND secondary both = %MYIP%
echo.
echo   If the console stays on Automatic DHCP DNS it will never ask this
echo   server for anything and nothing will be blocked.
echo.
echo   Press Ctrl+C to stop.
echo.

%PY% psn-dns-blocker\psn_block_dns.py --port 53 --verbose

rem --- put the DNS Client service back the way we found it ---
echo.
echo Restoring the Windows DNS Client service...
sc config Dnscache start= auto >nul 2>&1
net start Dnscache >nul 2>&1
echo Done. Blocker exited with code %ERRORLEVEL%.
pause