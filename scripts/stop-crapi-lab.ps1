$ErrorActionPreference = "Stop"

Get-CimInstance Win32_Process |
    Where-Object {
        ($_.Name -match "^python" -and
            $_.CommandLine -match "manage\.py runserver 0\.0\.0\.0:18080") -or
        ($_.Name -match "^java" -and
            $_.CommandLine -match "identity-service-1\.0-SNAPSHOT\.jar")
    } |
    ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }

docker stop crapi-community postgresdb mongodb 2>$null | Out-Null
Write-Host "crAPI lab stopped"
