@echo off
setlocal
cd /d "%~dp0"

if exist .env (
  for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
    if /I "%%A"=="VAS_LAUNCHER" set "VAS_LAUNCHER=%%B"
    if /I "%%A"=="VAS_STOPPER" set "VAS_STOPPER=%%B"
  )
)

if defined VAS_LAUNCHER (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\vas-control.ps1" -Action stop -Launcher "%VAS_LAUNCHER%" -Stopper "%VAS_STOPPER%"
) else if defined VAS_STOPPER (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\vas-control.ps1" -Action stop -Launcher "configured" -Stopper "%VAS_STOPPER%"
)

docker compose -f docker-compose.yml -f docker-compose.full.yml --profile dvwa --profile mock --profile full down
endlocal
