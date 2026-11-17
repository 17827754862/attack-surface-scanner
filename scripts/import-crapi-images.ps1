param(
    [string[]]$Images = @(
        "crapi/crapi-identity:latest",
        "crapi/crapi-community:latest",
        "crapi/crapi-workshop:latest",
        "crapi/crapi-web:latest",
        "crapi/gateway-service:latest",
        "crapi/mailhog:latest"
    ),
    [string]$Mirror = "docker.1panel.live",
    [string]$Regctl = "E:\传智杯\测试靶场\tools\regctl.exe",
    [string]$WorkRoot = "E:\传智杯\测试靶场\images\docker-load",
    [int]$Concurrency = 6
)

$ErrorActionPreference = "Stop"

function Download-Blob {
    param(
        [string]$Repository,
        [string]$Digest,
        [long]$ExpectedSize,
        [string]$Destination
    )

    if ((Test-Path -LiteralPath $Destination) -and
        (Get-Item -LiteralPath $Destination).Length -eq $ExpectedSize) {
        Write-Host "Using cached blob $Digest"
        return
    }
    if ($ExpectedSize -eq 0) {
        [System.IO.File]::WriteAllBytes($Destination, [byte[]]@())
        return
    }

    $url = "https://$Mirror/v2/$Repository/blobs/$Digest"
    if ($ExpectedSize -ge 8MB) {
        if (Test-Path -LiteralPath $Destination) {
            & curl.exe -sS -L --retry 4 --retry-delay 2 --max-time 0 `
                -C - -o $Destination $url
        }
        else {
            & curl.exe -sS -L --retry 4 --retry-delay 2 --max-time 0 `
                -o $Destination $url
        }
        if ($LASTEXITCODE -ne 0) {
            throw "curl failed for ${Digest}"
        }
        $streamedSize = (Get-Item -LiteralPath $Destination).Length
        if ($streamedSize -ne $ExpectedSize) {
            throw "Blob size mismatch for ${Digest}: expected $ExpectedSize, got $streamedSize"
        }
        return
    }

    $partsDir = "$Destination.parts"
    New-Item -ItemType Directory -Path $partsDir -Force | Out-Null
    $chunkSize = 1MB
    $chunkCount = [math]::Max(
        1,
        [math]::Ceiling($ExpectedSize / $chunkSize)
    )
    0..($chunkCount - 1) | ForEach-Object -Parallel {
        $index = $_
        $start = $index * $using:chunkSize
        $end = [math]::Min(
            $using:ExpectedSize - 1,
            $start + $using:chunkSize - 1
        )
        if ($using:ExpectedSize -eq 0) {
            return
        }
        $part = Join-Path $using:partsDir ("part-{0:D5}.bin" -f $index)
        $expectedChunkSize = $end - $start + 1
        if ((Test-Path -LiteralPath $part) -and
            (Get-Item -LiteralPath $part).Length -eq $expectedChunkSize) {
            return
        }
        & curl.exe -sS -L --retry 4 --retry-delay 2 --max-time 0 `
            -r "$start-$end" -o $part $using:url
        if ($LASTEXITCODE -ne 0) {
            throw "curl failed for chunk $index of $using:Digest"
        }
    } -ThrottleLimit $Concurrency

    $stream = [System.IO.File]::Open(
        $Destination,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        for ($index = 0; $index -lt $chunkCount; $index++) {
            $part = Join-Path $partsDir ("part-{0:D5}.bin" -f $index)
            $partStream = [System.IO.File]::OpenRead($part)
            try {
                $partStream.CopyTo($stream)
            }
            finally {
                $partStream.Dispose()
            }
        }
    }
    finally {
        $stream.Dispose()
    }

    $actualSize = (Get-Item -LiteralPath $Destination).Length
    if ($actualSize -ne $ExpectedSize) {
        throw "Blob size mismatch for ${Digest}: expected $ExpectedSize, got $actualSize"
    }
}

foreach ($image in $Images) {
    $separator = $image.LastIndexOf(":")
    $repository = $image.Substring(0, $separator)
    $tag = $image.Substring($separator + 1)
    $safeName = $repository.Replace("/", "_").Replace(":", "_")
    $imageDir = Join-Path $WorkRoot $safeName
    New-Item -ItemType Directory -Path $imageDir -Force | Out-Null

    Write-Host "Resolving $Mirror/$image"
    $manifestJson = & $Regctl manifest get --platform linux/amd64 `
        "$Mirror/$image" --format "{{json .}}"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to resolve $image"
    }
    $manifest = $manifestJson | ConvertFrom-Json

    $configFile = Join-Path $imageDir "config.json"
    Download-Blob `
        -Repository $repository `
        -Digest $manifest.config.digest `
        -ExpectedSize $manifest.config.size `
        -Destination $configFile

    $layerFiles = @()
    for ($index = 0; $index -lt $manifest.layers.Count; $index++) {
        $layer = $manifest.layers[$index]
        $layerName = "layer-{0:D2}.tar.gz" -f $index
        $layerFile = Join-Path $imageDir $layerName
        Write-Host "Downloading $image layer $($index + 1)/$($manifest.layers.Count)"
        Download-Blob `
            -Repository $repository `
            -Digest $layer.digest `
            -ExpectedSize $layer.size `
            -Destination $layerFile
        $layerFiles += $layerName
    }

    $dockerManifest = @(
        [ordered]@{
            Config = "config.json"
            RepoTags = @($image)
            Layers = $layerFiles
        }
    )
    $manifestPath = Join-Path $imageDir "manifest.json"
    $manifestText = ConvertTo-Json -InputObject $dockerManifest -Depth 5
    [System.IO.File]::WriteAllText(
        $manifestPath,
        $manifestText,
        [System.Text.UTF8Encoding]::new($false)
    )

    $archive = Join-Path $WorkRoot "$safeName.tar"
    Write-Host "Creating Docker archive $archive"
    & tar.exe -cf $archive -C $imageDir manifest.json config.json @layerFiles
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to create $archive"
    }

    Write-Host "Loading $image"
    & docker load -i $archive
    if ($LASTEXITCODE -ne 0) {
        throw "docker load failed for $image"
    }
}
