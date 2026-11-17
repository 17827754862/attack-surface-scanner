param(
    [string]$Name = "crapi-community",
    [string]$Image = "crapi/crapi-community:latest",
    [string]$Network = "docker_default",
    [string]$TargetNetwork = "scanner-targets"
)

$ErrorActionPreference = "Stop"
$running = docker ps --filter "name=^/${Name}$" --format "{{.Names}}"
if ($running) {
    Write-Host "crAPI community is already running"
    exit 0
}

$existing = docker ps -a --filter "name=^/${Name}$" --format "{{.Names}}"
if ($existing) {
    docker start $Name | Out-Null
}
else {
    docker run -d `
        --name $Name `
        --network $Network `
        --network-alias $Name `
        -p "127.0.0.1:8087:8087" `
        -e "IDENTITY_SERVICE=host.docker.internal:8989" `
        -e "DB_NAME=crapi" `
        -e "DB_USER=admin" `
        -e "DB_PASSWORD=crapisecretpassword" `
        -e "DB_HOST=postgresdb" `
        -e "DB_PORT=5432" `
        -e "SERVER_PORT=8087" `
        -e "MONGO_DB_HOST=mongodb" `
        -e "MONGO_DB_PORT=27017" `
        -e "MONGO_DB_USER=admin" `
        -e "MONGO_DB_PASSWORD=crapisecretpassword" `
        -e "MONGO_DB_NAME=crapi" `
        -e "TLS_ENABLED=false" `
        -e "LOG_LEVEL=INFO" `
        $Image | Out-Null
}

$networks = docker inspect $Name --format "{{json .NetworkSettings.Networks}}"
if ($networks -notmatch "scanner-targets") {
    docker network connect $TargetNetwork $Name
}
Write-Host "crAPI community started"
