param(
    [string]$SourceRoot = "E:\传智杯\测试靶场\crAPI\services\workshop"
)

$ErrorActionPreference = "Stop"
$existing = Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -match "^python" -and
        $_.CommandLine -match "manage\.py runserver 0\.0\.0\.0:18080"
    }
if ($existing) {
    Write-Host "crAPI workshop is already running as PID $($existing.ProcessId -join ',')"
    exit 0
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

$python = Join-Path $SourceRoot ".venv-host\Scripts\python.exe"
$process = Start-Process `
    -FilePath $python `
    -ArgumentList @("manage.py", "runserver", "0.0.0.0:18080", "--noreload") `
    -WorkingDirectory $SourceRoot `
    -RedirectStandardOutput (Join-Path $SourceRoot "workshop.stdout.log") `
    -RedirectStandardError (Join-Path $SourceRoot "workshop.stderr.log") `
    -WindowStyle Hidden `
    -PassThru

Write-Host "crAPI workshop started as PID $($process.Id)"
