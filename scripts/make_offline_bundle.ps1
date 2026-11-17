param(
    [string]$BundleDir = "offline-bundle",
    [switch]$IncludeOpenVAS
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$bundlePath = Join-Path $projectRoot $BundleDir

Push-Location $projectRoot
try {
    New-Item -ItemType Directory -Force -Path $bundlePath | Out-Null

    & docker compose --profile dvwa --profile mock build
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose build failed"
    }

    $images = @(
        & docker compose --profile dvwa --profile mock config --images |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and $_ -notmatch "(^|/)immauss/openvas:" } |
            Sort-Object -Unique
    )
    if ($LASTEXITCODE -ne 0 -or $images.Count -eq 0) {
        throw "could not resolve images for the offline bundle"
    }

    $imagesPath = Join-Path $bundlePath "images.txt"
    $imagesTar = Join-Path $bundlePath "images.tar"
    $openvasTar = Join-Path $bundlePath "openvas.tar"
    $versionPath = Join-Path $bundlePath "VERSION"
    $checksumsPath = Join-Path $bundlePath "SHA256SUMS"
    $images | Set-Content -LiteralPath $imagesPath -Encoding ascii

    & docker save -o $imagesTar @images
    if ($LASTEXITCODE -ne 0) {
        throw "docker save failed"
    }

    if ($IncludeOpenVAS) {
        $openvasImage = "immauss/openvas:26.07.27.01"
        & docker image inspect $openvasImage *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "OpenVAS image not found: $openvasImage. Pull it before creating the bundle."
        }
        & docker save -o $openvasTar $openvasImage
        if ($LASTEXITCODE -ne 0) {
            throw "docker save failed for OpenVAS"
        }
    } elseif (Test-Path -LiteralPath $openvasTar) {
        Remove-Item -LiteralPath $openvasTar -Force
    }

    @(
        (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        "architecture=amd64"
        "openvas_included=$($IncludeOpenVAS.ToString().ToLowerInvariant())"
        "features=memory,ai-analysis,bilingual-ui,risk-groups,auth-profiles,no-deadline,active-validation,oast"
    ) | Set-Content -LiteralPath $versionPath -Encoding ascii

    $artifacts = @("images.tar", "images.txt", "VERSION")
    if ($IncludeOpenVAS) {
        $artifacts += "openvas.tar"
    }
    $checksums = foreach ($name in $artifacts) {
        $path = Join-Path $bundlePath $name
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    $checksums | Set-Content -LiteralPath $checksumsPath -Encoding ascii

    Write-Output "Offline bundle created: $bundlePath"
    Write-Output "Images: $($images.Count)"
    Write-Output "Bundle size: $([math]::Round((Get-Item $imagesTar).Length / 1GB, 2)) GiB"
    if ($IncludeOpenVAS) {
        Write-Output "OpenVAS image: $([math]::Round((Get-Item $openvasTar).Length / 1GB, 2)) GiB"
    }
}
finally {
    Pop-Location
}
