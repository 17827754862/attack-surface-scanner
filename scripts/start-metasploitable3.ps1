param(
    [string]$ContainerName = "metasploitable3-qemu",
    [string]$Image = "metasploitable3-qemu:ubuntu1404",
    [string]$VmRoot = "E:\传智杯\测试靶场\Metasploitable3"
)

$ErrorActionPreference = "Stop"
$network = "scanner-targets"

if (-not (docker network inspect $network 2>$null)) {
    docker network create $network | Out-Null
}

$existing = docker ps -a --filter "name=^/${ContainerName}$" --format "{{.Names}}"
if ($existing) {
    $running = docker ps --filter "name=^/${ContainerName}$" --format "{{.Names}}"
    if (-not $running) {
        docker start $ContainerName | Out-Null
    }
}
else {
    docker run -d `
        --name $ContainerName `
        --network $network `
        --network-alias metasploitable3.test `
        --network-alias metasploitable3 `
        -v "${VmRoot}:/vm" `
        $Image sleep infinity | Out-Null
}

$overlay = "/vm/vm/metasploitable3-overlay.qcow2"
docker exec $ContainerName sh -c "test -f $overlay" 2>$null
if ($LASTEXITCODE -ne 0) {
    docker exec $ContainerName qemu-img create -f qcow2 -F vmdk `
        -b "/vm/vm/metasploitable3-ub1404-disk001.vmdk" `
        $overlay
}

$runningPid = docker exec $ContainerName sh -c `
    "test -f /vm/vm/metasploitable3.pid && kill -0 `$(cat /vm/vm/metasploitable3.pid) 2>/dev/null && cat /vm/vm/metasploitable3.pid" `
    2>$null
if ($runningPid) {
    Write-Host "Metasploitable 3 is already running as PID $runningPid"
    exit 0
}

docker exec $ContainerName qemu-system-x86_64 `
    -name metasploitable3 `
    -machine pc `
    -accel tcg,thread=multi `
    -cpu qemu64 `
    -smp 2 `
    -m 2048 `
    -drive "file=$overlay,format=qcow2,if=ide" `
    -netdev "user,id=net0,hostfwd=tcp::21-:21,hostfwd=tcp::22-:22,hostfwd=tcp::25-:25,hostfwd=tcp::53-:53,hostfwd=tcp::80-:80,hostfwd=tcp::110-:110,hostfwd=tcp::139-:139,hostfwd=tcp::143-:143,hostfwd=tcp::443-:443,hostfwd=tcp::445-:445,hostfwd=tcp::3306-:3306,hostfwd=tcp::8080-:8080,hostfwd=tcp::8484-:8484" `
    -device e1000,netdev=net0 `
    -display none `
    -serial "file:/vm/vm/metasploitable3-serial.log" `
    -monitor "unix:/vm/vm/metasploitable3-monitor.sock,server,nowait" `
    -daemonize `
    -pidfile "/vm/vm/metasploitable3.pid"

$pidValue = docker exec $ContainerName cat /vm/vm/metasploitable3.pid
Write-Host "Metasploitable 3 started as PID $pidValue"
