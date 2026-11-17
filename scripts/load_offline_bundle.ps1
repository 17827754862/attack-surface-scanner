param(
    [string]$BundleDir = "offline-bundle"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$bundlePath = Join-Path $projectRoot $BundleDir

if (-not (Test-Path -LiteralPath $bundlePath -PathType Container)) {
    throw "bundle directory not found: $bundlePath"
}

Push-Location $projectRoot
try {
    $checksums = Get-Content -LiteralPath (Join-Path $bundlePath "SHA256SUMS") -Encoding ascii
    foreach ($line in $checksums) {
        if ($line -notmatch "^([0-9a-fA-F]{64})\s{2}(.+)$") {
            throw "invalid checksum line: $line"
        }
        $expected = $Matches[1].ToLowerInvariant()
        $name = $Matches[2]
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $bundlePath $name)).Hash.ToLowerInvariant()
        if ($actual -ne $expected) {
            throw "checksum mismatch: $name"
        }
    }

    & docker load -i (Join-Path $bundlePath "images.tar")
    if ($LASTEXITCODE -ne 0) {
        throw "docker load failed"
    }

    $openvasTar = Join-Path $bundlePath "openvas.tar"
    if (Test-Path -LiteralPath $openvasTar) {
        & docker load -i $openvasTar
        if ($LASTEXITCODE -ne 0) {
            throw "docker load failed for OpenVAS"
        }
    }

    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot ".env"))) {
        Copy-Item -LiteralPath (Join-Path $projectRoot ".env.example") -Destination (Join-Path $projectRoot ".env")
        Write-Output "Created .env from .env.example; change every default secret before sharing."
    }

    & docker compose --profile dvwa --profile mock up -d
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose up failed"
    }

    Write-Output "Frontend: http://127.0.0.1:3000"
    Write-Output "API docs: http://127.0.0.1:8000/docs"
    Write-Output "DVWA: http://127.0.0.1:8081"
}
finally {
    Pop-Location
}
