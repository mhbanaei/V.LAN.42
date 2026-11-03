@echo off
REM ============================================================
REM  V.Lan.42 - VPS server starter
REM  coded by Hossein & Erfan  -  https://github.com/mhbanaei
REM
REM  Put vlan42_server.py (and vlan42_check.py, if you have it) next
REM  to this file on your VPS and run this script.
REM  Ports used (both must be open on the VPS):
REM     TCP 4242  (control channel: login, rooms, friends, chat)
REM     UDP 4242  (game traffic relay)
REM ============================================================
cd /d "%~dp0"
title V.Lan.42 Server

where python >nul 2>&1
if errorlevel 1 (
    echo Python was not found. Install Python 3.10+ from https://www.python.org/downloads/
    echo ^(tick "Add python.exe to PATH" during install^), then run this file again.
    pause
    exit /b 1
)

echo Checking dependencies ^(cryptography^)...
python -m pip install -q cryptography
if errorlevel 1 (
    echo ERROR: could not install packages. Check the internet connection of the VPS.
    pause
    exit /b 1
)

REM Firewall rules (needs an admin shell; without them players cannot connect)
netsh advfirewall firewall show rule name="V-Lan-42-server-TCP" >nul 2>&1
if errorlevel 1 (
    echo Opening firewall ports TCP/UDP 4242 ...
    netsh advfirewall firewall add rule name="V-Lan-42-server-TCP" dir=in action=allow protocol=TCP localport=4242 >nul 2>&1
    netsh advfirewall firewall add rule name="V-Lan-42-server-UDP" dir=in action=allow protocol=UDP localport=4242 >nul 2>&1
    if errorlevel 1 (
        echo NOTE: could not add firewall rules - run this file as Administrator once,
        echo       or open ports TCP/UDP 4242 in the control panel of your VPS.
    )
)

echo.
echo Default VPS address for players: v42.ir
echo    Players never type an address - the app dials v42.ir and then the extra
echo    lines of vlan42_servers.txt. Make v42.ir a DNS A record for THIS VPS.
echo    To use another address, run:  start_server.bat  domain-or-ip
set SERVERADDR=v42.ir
if not "%~1"=="" set SERVERADDR=%~1

REM Keep the team's file; create it with the default when it is missing.
if not exist "vlan42_servers.txt" (
    >"vlan42_servers.txt" echo # V.Lan.42 addresses the clients try, in this order.
    >>"vlan42_servers.txt" echo # One "domain", "ip" or "ip:port" per line. Lines with # are notes.
    >>"vlan42_servers.txt" echo %SERVERADDR%
    echo vlan42_servers.txt created with %SERVERADDR%
)

echo.
echo Finding the public address of this VPS ...
set PUBLICIP=
for /f "usebackq delims=" %%I in (`powershell -NoProfile -Command "(Invoke-RestMethod 'https://api.ipify.org?format=json').ip"`) do set PUBLICIP=%%I
if defined PUBLICIP (
    echo This VPS public IP : %PUBLICIP%
    REM The raw IP joins the list as a fallback, so a DNS problem does not lock everyone out.
    findstr /x /c:"%PUBLICIP%" "vlan42_servers.txt" >nul 2>&1
    if errorlevel 1 (
        >>"vlan42_servers.txt" echo %PUBLICIP%
        echo Added %PUBLICIP% to vlan42_servers.txt ^(after %SERVERADDR%^).
    )
) else (
    echo NOTE: could not detect the public IP. Write it into vlan42_servers.txt yourself:
    echo       one line with the VPS IP, for example  203.0.113.10
)
echo.
echo ============================================================
echo  V.Lan.42 server starting - keep this window OPEN.
echo.
echo  Players sign in with a username and password only. The address
echo  they connect to comes from %SERVERADDR% ^(plus any extra lines in
echo  vlan42_servers.txt^), which build_exe.bat bundles into the exe -
echo  ship that file next to V.Lan.42.exe if you change it.
echo  Ports: TCP 4242 + UDP 4242 must stay open - inside Windows
echo  AND in the firewall/security panel of your hosting company.
echo  UDP is the one people forget: without it players can log in
echo  and see the rooms, but entering a room fails.
echo ============================================================
echo.
REM Check both channels a few seconds after start; the result window
REM stays open so you can see it. Players can run the same file later.
if exist vlan42_check.py (
    start "V.Lan.42 self-check" /min cmd /c "timeout /t 6 >nul & python vlan42_check.py 127.0.0.1 & echo. & echo Copy this window to the team, then close it. & pause"
)
python vlan42_server.py
pause
