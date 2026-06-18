@echo off
setlocal
cd /d "%~dp0"
echo SOC2 Sentinel v2.4 — mock evidence run
echo.
bin\sentinel.exe run-all --provider mock
if errorlevel 1 (
  echo.
  echo Failed. If bin\sentinel.exe is missing, use setup.ps1 or see QUICKSTART-BUYER.md
  pause
  exit /b 1
)
echo.
echo Done. Check the evidence\ folder.
pause