@echo off
rem Packs dist\Umbra.exe (+ dist\core) into a setup program with Inno Setup 6.
setlocal
cd /d "%~dp0"
if not exist "dist\Umbra.exe" (
  echo dist\Umbra.exe not found. Run build_exe.bat first.
  goto :fail
)
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
  echo Inno Setup 6 not found. Install it from https://jrsoftware.org/isdl.php and run this file again.
  goto :fail
)
set "PY=py -3"
where py >nul 2>nul || set "PY=python"
set "VER="
for /f "usebackq delims=" %%v in (`%PY% -c "import umbra; print(umbra.__version__)"`) do set "VER=%%v"
if "%VER%"=="" (
  echo Could not read the version from umbra\__init__.py
  goto :fail
)
echo Building the installer for version %VER%...
"%ISCC%" /Qp "/DAppVersion=%VER%" "installer\Umbra.iss"
if errorlevel 1 goto :fail
echo.
echo DONE: dist\Umbra-Setup-%VER%.exe
explorer "dist"
pause
exit /b 0

:fail
echo.
echo INSTALLER BUILD FAILED - see the messages above.
pause
exit /b 1
