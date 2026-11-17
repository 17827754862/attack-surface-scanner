param(
    [string]$SourceRoot = "E:\传智杯\测试靶场\crAPI\services\identity",
    [string]$Java = "D:\ctf-tools\jdk\jdk-21.0.12+8\bin\java.exe"
)

$ErrorActionPreference = "Stop"
$existing = Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -match "^java" -and
        $_.CommandLine -match "identity-service-1\.0-SNAPSHOT\.jar"
    }
if ($existing) {
    Write-Host "crAPI identity is already running as PID $($existing.ProcessId -join ',')"
    exit 0
}

$env:DB_HOST = "127.0.0.1"
$env:DB_PORT = "5433"
$env:DB_NAME = "crapi"
$env:DB_USER = "admin"
$env:DB_PASSWORD = "crapisecretpassword"
$env:SERVER_PORT = "8989"
$env:ENABLE_SHELL_INJECTION = "false"
$env:JWT_SECRET = "crapi"
$env:MAILHOG_HOST = "127.0.0.1"
$env:MAILHOG_PORT = "1025"
$env:MAILHOG_DOMAIN = "example.com"
$env:SMTP_HOST = "127.0.0.1"
$env:SMTP_PORT = "1025"
$env:SMTP_EMAIL = "user@example.com"
$env:SMTP_PASS = "unused"
$env:SMTP_FROM = "no-reply@example.com"
$env:SMTP_AUTH = "false"
$env:SMTP_STARTTLS = "false"
$env:JWT_EXPIRATION = "604800000"
$env:ENABLE_LOG4J = "false"
$env:API_GATEWAY_URL = "https://api.mypremiumdealership.com"
$env:TLS_ENABLED = "false"
$env:LOG_LEVEL = "INFO"
$env:JAVA_TOOL_OPTIONS = "-Xmx512m"

$jar = (Resolve-Path (Join-Path $SourceRoot "build\libs\identity-service-1.0-SNAPSHOT.jar")).Path
$jwks = [Convert]::ToBase64String(
    [IO.File]::ReadAllBytes((Resolve-Path (Join-Path $SourceRoot "jwks.json")).Path)
)
$process = Start-Process `
    -FilePath $Java `
    -ArgumentList @("-jar", $jar, "--app.jwksJson=$jwks") `
    -WorkingDirectory $SourceRoot `
    -RedirectStandardOutput (Join-Path $SourceRoot "identity.stdout.log") `
    -RedirectStandardError (Join-Path $SourceRoot "identity.stderr.log") `
    -WindowStyle Hidden `
    -PassThru

Write-Host "crAPI identity started as PID $($process.Id)"
