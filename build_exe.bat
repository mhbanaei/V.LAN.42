@echo off
setlocal
cd /d "%~dp0"
REM Builds ONE file (dist\V.Lan.42.exe) that your friends can run - no Python needed.
REM Keep these next to this script:  vplan42.py  and  V.Lan.42.ico  and, if you have it, wintun.dll
REM
REM MODE: --onefile = a single exe (easy to send).
REM       --onedir  = a folder (starts faster, fewer antivirus false alarms).
set MODE=--onefile

echo Installing required packages...
pip install -q --upgrade pyinstaller customtkinter cryptography pillow
if errorlevel 1 (
    echo.
    echo ERROR: required packages could not be installed. Check your internet connection and run this again.
    pause
    exit /b 1
)
echo Installing optional packages (each one is skipped if it fails)...
pip install -q "qrcode[pil]" || echo   qrcode not installed - the QR button is disabled.

set ICON=
set DATA=
if exist V.Lan.42.ico (
    set ICON=--icon V.Lan.42.ico
    set DATA=--add-data "V.Lan.42.ico;."
    echo V.Lan.42.ico found - it becomes the exe icon and the app logo.
) else (
    echo WARNING: V.Lan.42.ico not found next to this script - a built-in icon is used instead.
    python vplan42.py --make-icon V.Lan.42.ico >nul 2>&1
    if exist V.Lan.42.ico set ICON=--icon V.Lan.42.ico
)

set EXTRA=
if exist wintun.dll (
    set EXTRA=--add-binary "wintun.dll;."
    echo wintun.dll found - it will be bundled into the exe.
) else (
    echo WARNING: wintun.dll not found - run the app once first so it can find or download it!
)

if exist vlan42_servers.txt (
    set DATA=%DATA% --add-data "vlan42_servers.txt;."
    echo vlan42_servers.txt found - the VPS address is built into the exe.
) else (
    echo NOTE: no vlan42_servers.txt here. Players never type a server address, so put
    echo       that file ^(one VPS IP per line^) next to this script before building,
    echo       or next to V.Lan.42.exe after building.
)

pyinstaller --noconfirm --clean %MODE% --windowed --uac-admin --noupx --collect-all customtkinter %ICON% %DATA% %EXTRA% --name V.Lan.42 vplan42.py
echo.
if "%MODE%"=="--onefile" (
    echo Done: dist\V.Lan.42.exe  ^(send only this file to your friends^)
) else (
    echo Done: dist\V.Lan.42\  ^(zip this folder and send it^)
)
pause
