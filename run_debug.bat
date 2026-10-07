@echo off
rem Same as run.bat, but with a console window and verbose log (for debugging).
cd /d "%~dp0"
python -m umbra --verbose
pause
