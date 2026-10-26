# Deployment-Watchdog.ps1
# Windows Server 2019 / PowerShell 5.1
# Run as Administrator

$WatchPaths = @(
    "C:\Users\Public",
    "C:\Windows\Temp",
    "C:\Temp",
    "C:\ProgramData"
)

$SuspiciousExtensions = @(
    ".exe", ".dll", ".ps1", ".bat",
    ".cmd", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".scr", ".msi"
)

$LogDir = "C:\BlueTeam\Logs"
$LogFile = Join-Path $LogDir "Deployment-Watchdog.log"

New-Item -ItemType Directory -Path $LogDir -Force |
    Out-Null

# Track files already present
$KnownFiles = @{}

function Get-WatchedFiles {
    foreach ($Path in $WatchPaths) {
        if (Test-Path -LiteralPath $Path) {
            Get-ChildItem -LiteralPath $Path `
                -File -Recurse -Force `
                -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "Initializing file monitoring..." -ForegroundColor Cyan

foreach ($File in Get-WatchedFiles) {
    $KnownFiles[$File.FullName] = $true
}

Write-Host "Deployment watchdog active." -ForegroundColor Green

while ($true) {

    foreach ($File in Get-WatchedFiles) {

        if (-not $KnownFiles.ContainsKey($File.FullName)) {

            $KnownFiles[$File.FullName] = $true

            $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            $Message = "$Time | NEW FILE | $($File.FullName)"

            if ($File.Extension.ToLowerInvariant() -in $SuspiciousExtensions) {

                $Message += " | POTENTIALLY EXECUTABLE"

                Write-Host $Message -ForegroundColor Red

            } else {

                Write-Host $Message -ForegroundColor Yellow
            }

            Add-Content -Path $LogFile -Value $Message
        }
    }

    Start-Sleep -Seconds 3
}
