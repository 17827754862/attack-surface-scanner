param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("start", "stop")]
    [string]$Action,
    [string]$Launcher = "",
    [string]$Stopper = ""
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$pidFile = Join-Path $root ".vas-launcher.pid"


function Resolve-CommandPath {
    param([string]$Value)

    $candidate = $Value.Trim()
    if (-not [System.IO.Path]::IsPathRooted($candidate)) {
        $candidate = Join-Path $root $candidate
    }
    return (Resolve-Path -LiteralPath $candidate).Path
}


function Start-ConfiguredCommand {
    param(
        [string]$Value,
        [switch]$Wait,
        [switch]$Hidden
    )

    if ($Value -match '^https?://') {
        return Start-Process -FilePath $Value -PassThru
    }

    $path = Resolve-CommandPath $Value
    $extension = [System.IO.Path]::GetExtension($path).ToLowerInvariant()
    $windowStyle = if ($Hidden) { "Hidden" } else { "Normal" }
    $startArgs = @{
        WorkingDirectory = $root
        PassThru = $true
        WindowStyle = $windowStyle
    }
    if ($Wait) {
        $startArgs.Wait = $true
    }

    if ($extension -eq ".ps1") {
        return Start-Process -FilePath "powershell.exe" `
            -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$path`"") `
            @startArgs
    }
    if ($extension -in @(".cmd", ".bat")) {
        return Start-Process -FilePath "cmd.exe" `
            -ArgumentList @("/c", "`"`"$path`"`"") `
            @startArgs
    }
    return Start-Process -FilePath $path @startArgs
}


function Get-TrackedProcess {
    if (-not (Test-Path -LiteralPath $pidFile)) {
        return $null
    }
    try {
        $processId = [int](Get-Content -LiteralPath $pidFile -Raw)
        return Get-Process -Id $processId -ErrorAction Stop
    }
    catch {
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        return $null
    }
}


if ($Action -eq "start") {
    if (-not $Launcher.Trim()) {
        Write-Output "VAS launcher is not configured; skipping."
        exit 0
    }

    $tracked = Get-TrackedProcess
    if ($tracked) {
        Write-Output "VAS launcher is already running (pid $($tracked.Id))."
        exit 0
    }

    $process = Start-ConfiguredCommand -Value $Launcher
    if ($process -and -not $process.HasExited) {
        Set-Content -LiteralPath $pidFile -Value $process.Id -Encoding ascii
        Write-Output "VAS launcher started (pid $($process.Id))."
    }
    else {
        Write-Output "VAS launcher command was dispatched."
    }
    exit 0
}

if ($Stopper.Trim()) {
    Start-ConfiguredCommand -Value $Stopper -Wait -Hidden | Out-Null
    Write-Output "VAS stopper completed."
}

$tracked = Get-TrackedProcess
if ($tracked) {
    Stop-Process -Id $tracked.Id -Force -ErrorAction SilentlyContinue
    Write-Output "VAS launcher stopped (pid $($tracked.Id))."
}

Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
if (-not $Stopper.Trim() -and -not $tracked) {
    Write-Output "No running VAS launcher was tracked."
}
