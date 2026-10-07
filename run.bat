@echo off
cd /d "%~dp0"
where pyw >nul 2>nul
if not errorlevel 1 (
  start "" pyw -3 -m umbra
  exit /b 0
)
where pythonw >nul 2>nul
if not errorlevel 1 (
  start "" pythonw -m umbra
  exit /b 0
)
echo Python 3.10+ not found. Install it from python.org and tick "Add python.exe to PATH".
pause
