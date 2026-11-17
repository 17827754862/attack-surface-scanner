$ErrorActionPreference = "Stop"
$hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$entries = @(
    "dvwa.test",
    "webgoat.test",
    "juice-shop.test",
    "vampi.test",
    "crapi.test",
    "cve-2018-14574.test",
    "cve-2019-14234.test",
    "cve-2021-35042.test",
    "cve-2022-34265.test",
    "cve-2024-23334.test",
    "metasploitable3.test"
)

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this script from an elevated PowerShell window."
}

$existing = Get-Content -LiteralPath $hostsPath
$missing = $entries | Where-Object {
    $name = $_
    -not ($existing | Where-Object {
        $_ -match "^\s*127\.0\.0\.1\s+$([regex]::Escape($name))\s*$"
    })
}

if ($missing) {
    Add-Content -LiteralPath $hostsPath -Value "" -Encoding ascii
    foreach ($name in $missing) {
        Add-Content `
            -LiteralPath $hostsPath `
            -Value "127.0.0.1       $name" `
            -Encoding ascii
    }
}

Write-Host "Local scanner target domains are configured."
