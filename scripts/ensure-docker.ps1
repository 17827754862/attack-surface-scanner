$ErrorActionPreference = "Stop"

function Test-DockerEngine {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    & docker info *> $null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous
    return $code -eq 0
}

if (Test-DockerEngine) {
    Write-Output "Docker Engine: ready"
    exit 0
}

$candidates = @(
    "C:\Program Files\Docker\Docker\Docker Desktop.exe",
    "D:\Docker\Docker\Docker Desktop.exe",
    "$env:LOCALAPPDATA\Docker\Docker Desktop.exe"
)
$desktop = $candidates |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
if (-not $desktop) {
    Write-Error "Docker Desktop executable was not found. Install Docker Desktop or start Docker manually."
    exit 2
}

Write-Output "Docker Engine is not running; starting Docker Desktop..."
Start-Process -FilePath $desktop -WindowStyle Hidden
$deadline = (Get-Date).AddMinutes(3)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    if (Test-DockerEngine) {
        Write-Output "Docker Engine: ready"
        exit 0
    }
}

Write-Error "Docker Engine did not become ready within 3 minutes."
exit 1
