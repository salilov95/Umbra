@echo off
rem Use this if the internet "died" after the client crashed: puts the Windows proxy back.
cd /d "%~dp0"
python -m umbra --restore-proxy
pause
