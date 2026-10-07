@echo off
rem Builds dist\Umbra.exe (single file). Needs Python 3.10+ and internet (pip).
setlocal
cd /d "%~dp0"
set "PY=py -3"
where py >nul 2>nul || set "PY=python"
%PY% --version >nul 2>nul
if errorlevel 1 (
  echo Python 3.10+ not found. Install it from python.org and tick "Add python.exe to PATH".
  goto :fail
)

rem A running Umbra.exe locks the file, and the build cannot replace it.
:waitexit
tasklist /FI "IMAGENAME eq Umbra.exe" 2>nul | find /I "Umbra.exe" >nul
if errorlevel 1 goto :notrunning
echo.
echo Umbra.exe is running, so the build cannot replace it.
echo Exit the program: tray icon near the clock, right click, the last menu item.
echo Then press any key here.
pause >nul
goto :waitexit
:notrunning

echo [1/4] Creating the build environment (.build-venv)...
if not exist ".build-venv\Scripts\python.exe" %PY% -m venv .build-venv
if not exist ".build-venv\Scripts\python.exe" goto :fail

echo [2/4] Installing PyInstaller...
".build-venv\Scripts\python.exe" -m pip install --quiet --upgrade pip pyinstaller
if errorlevel 1 goto :fail

echo [3/4] Building Umbra.exe...
".build-venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --log-level WARN --onefile --windowed --name Umbra --icon "assets\icon.ico" --add-data "umbra\web;umbra\web" launcher.py
if errorlevel 1 goto :fail
if not exist "dist\Umbra.exe" goto :fail

echo [4/4] Adding the Xray core for offline use...
set "CORE=%APPDATA%\Umbra\core"
rem before the rename the core lived in the old folder
if not exist "%CORE%\xray.exe" set "CORE=%APPDATA%\VlessClient\core"
if not exist "%CORE%\xray.exe" goto :nocore
if not exist "dist\core" mkdir "dist\core"
copy /y "%CORE%\xray.exe" "dist\core" >nul
copy /y "%CORE%\geoip.dat" "dist\core" >nul
copy /y "%CORE%\geosite.dat" "dist\core" >nul
echo       core copied to dist\core
goto :done
:nocore
echo       core not found on this PC: the exe will download it on the first connect
:done
echo.
echo DONE. Take the whole "dist" folder to another computer and run Umbra.exe
echo To make an installer instead, run build_installer.bat
explorer "dist"
pause
exit /b 0

:fail
echo.
echo BUILD FAILED - see the messages above.
pause
exit /b 1
