@echo off
setlocal
cd /d "%~dp0"

echo ============================================
echo   Attack Surface Scanner - Local Start
echo ============================================

where docker >nul 2>nul
if errorlevel 1 (
  echo Error: Docker is not installed or not on PATH.
  if not defined CI pause
  exit /b 1
)

docker compose version >nul 2>nul
if errorlevel 1 (
  echo Error: Docker Compose v2 is required.
  if not defined CI pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\ensure-docker.ps1"
if errorlevel 1 (
  echo Error: Docker Engine is not ready.
  if not defined CI pause
  exit /b 1
)

if not exist .env (
  copy /Y .env.example .env >nul
  echo Created .env from .env.example. Change passwords before exposing this host.
)

for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
  if /I "%%A"=="API_PORT" set "API_PORT=%%B"
  if /I "%%A"=="FRONTEND_PORT" set "FRONTEND_PORT=%%B"
  if /I "%%A"=="DVWA_PORT" set "DVWA_PORT=%%B"
  if /I "%%A"=="MOCK_HTTP_PORT" set "MOCK_HTTP_PORT=%%B"
  if /I "%%A"=="OPENVAS_ENABLED" set "OPENVAS_ENABLED=%%B"
  if /I "%%A"=="VAS_LAUNCHER" set "VAS_LAUNCHER=%%B"
  if /I "%%A"=="VAS_STOPPER" set "VAS_STOPPER=%%B"
)
if not defined API_PORT set "API_PORT=8000"
if not defined FRONTEND_PORT set "FRONTEND_PORT=3000"
if not defined DVWA_PORT set "DVWA_PORT=8081"
if not defined MOCK_HTTP_PORT set "MOCK_HTTP_PORT=18000"
if not defined OPENVAS_ENABLED set "OPENVAS_ENABLED=false"

if /I "%OPENVAS_ENABLED%"=="true" (
  echo OpenVAS is enabled; starting the full scanner profile.
  docker compose -f docker-compose.yml -f docker-compose.full.yml --profile full --profile dvwa --profile mock up -d --build
  if errorlevel 1 (
    echo Error: docker compose with OpenVAS failed.
    docker compose -f docker-compose.yml -f docker-compose.full.yml --profile full --profile dvwa --profile mock ps
    if not defined CI pause
    exit /b 1
  )
) else (
  docker compose --profile dvwa --profile mock up -d --build
  if errorlevel 1 (
    echo Error: docker compose failed.
    docker compose --profile dvwa --profile mock ps
    if not defined CI pause
    exit /b 1
  )
)

echo Waiting for API health at http://127.0.0.1:%API_PORT%/health ...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$deadline=(Get-Date).AddSeconds(180); while((Get-Date) -lt $deadline){ try { $r=Invoke-WebRequest -UseBasicParsing ('http://127.0.0.1:%API_PORT%/health') -TimeoutSec 3; if($r.StatusCode -eq 200){ exit 0 } } catch {}; Start-Sleep -Seconds 3 }; exit 1"
if errorlevel 1 (
  echo API did not become healthy in 180 seconds.
  docker compose ps
  echo Run: docker compose logs --tail=200 backend worker
  if not defined CI pause
  exit /b 1
)

echo.
echo Frontend: http://127.0.0.1:%FRONTEND_PORT%
echo API docs: http://127.0.0.1:%API_PORT%/docs
echo DVWA:     http://127.0.0.1:%DVWA_PORT% (admin/password)
echo Mock:     http://127.0.0.1:%MOCK_HTTP_PORT% (container target http://mock:8000)
if /I "%OPENVAS_ENABLED%"=="true" echo OpenVAS:  internal GMP service openvas:9390
echo Login with ADMIN_USERNAME/ADMIN_PASSWORD from .env.
echo First DVWA visit may require Create/Reset Database.

if defined VAS_LAUNCHER (
  echo Starting VAS launcher: %VAS_LAUNCHER%
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\vas-control.ps1" -Action start -Launcher "%VAS_LAUNCHER%" -Stopper "%VAS_STOPPER%"
  if errorlevel 1 echo Warning: VAS launcher could not be started.
)

if not defined CI pause
endlocal
