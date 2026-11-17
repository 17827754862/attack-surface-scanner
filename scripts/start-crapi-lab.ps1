param(
    [string]$ProjectRoot = "E:\传智杯\测试靶场\crAPI",
    [string]$ScannerRoot = "D:\桌面\传智杯\attack-surface-scanner"
)

$ErrorActionPreference = "Stop"
$composeRoot = Join-Path $ProjectRoot "deploy\docker"
$workshopRoot = Join-Path $ProjectRoot "services\workshop"

docker compose `
    -f (Join-Path $composeRoot "docker-compose.yml") `
    -f (Join-Path $composeRoot "docker-compose.scanner.yml") `
    up -d postgresdb mongodb

while ($true) {
    $postgres = docker inspect postgresdb --format "{{.State.Health.Status}}"
    $mongo = docker inspect mongodb --format "{{.State.Health.Status}}"
    if ($postgres -eq "healthy" -and $mongo -eq "healthy") {
        break
    }
    Start-Sleep -Seconds 2
}

& (Join-Path $ScannerRoot "scripts\start-crapi-identity.ps1")
while (-not (Test-NetConnection -ComputerName 127.0.0.1 -Port 8989 -InformationLevel Quiet)) {
    Start-Sleep -Seconds 2
}

$env:DB_HOST = "127.0.0.1"
$env:DB_PORT = "5433"
$env:DB_NAME = "crapi"
$env:DB_USER = "admin"
$env:DB_PASSWORD = "crapisecretpassword"
$env:MONGO_DB_HOST = "127.0.0.1"
$env:MONGO_DB_PORT = "27018"
$env:MONGO_DB_NAME = "crapi"
$env:MONGO_DB_USER = "admin"
$env:MONGO_DB_PASSWORD = "crapisecretpassword"
$env:SECRET_KEY = "crapi"
$env:SERVER_PORT = "18080"
$env:TLS_ENABLED = "false"
$env:IDENTITY_SERVICE = "127.0.0.1:8989"
$env:API_GATEWAY_URL = "https://api.mypremiumdealership.com"

$python = Join-Path $workshopRoot ".venv-host\Scripts\python.exe"
Push-Location $workshopRoot
try {
    & $python manage.py migrate --noinput
    & $python manage.py seed_database
}
finally {
    Pop-Location
}

& (Join-Path $ScannerRoot "scripts\start-crapi-workshop.ps1")
while (-not (Test-NetConnection -ComputerName 127.0.0.1 -Port 18080 -InformationLevel Quiet)) {
    Start-Sleep -Seconds 2
}

& (Join-Path $ScannerRoot "scripts\start-crapi-community.ps1")
docker exec scanner-target-proxy nginx -t
docker exec scanner-target-proxy nginx -s reload

Write-Host "crAPI lab is ready at http://crapi.test/"
