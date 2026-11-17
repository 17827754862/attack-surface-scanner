param(
    [string]$ContainerName = "metasploitable3-qemu"
)

$ErrorActionPreference = "Stop"
$running = docker ps --filter "name=^/${ContainerName}$" --format "{{.Names}}"
if (-not $running) {
    Write-Host "Metasploitable 3 container is not running"
    exit 0
}

docker exec $ContainerName sh -c `
    "if test -f /vm/vm/metasploitable3.pid; then kill -TERM `$(cat /vm/vm/metasploitable3.pid) 2>/dev/null || true; fi"
Start-Sleep -Seconds 3
docker stop $ContainerName | Out-Null
Write-Host "Metasploitable 3 stopped"
