# Deploy-BlueOps.ps1
# Run once per host as local/domain admin.
# Creates the SYSTEM-run worker, the scheduled task, and locks down all 6 services.

$baseDir = "C:\BlueOps"
New-Item -ItemType Directory -Path $baseDir -Force | Out-Null

$services = @{
    "AD"       = "NTDS"
    "DNS"      = "DNS"
    "Openfire" = "openfire"      # VERIFY actual service name on this host before running
    "Telnet"   = "TlntSvr"
    "IIS"      = "W3SVC"
    "CA"       = "CertSvc"
}

# SYSTEM only gets stop/start/modify rights. Administrators + everyone else: read-only.
$lockedSDDL = "D:(D;;DCWPDTSD;;;AU)(A;;CCLCSWLORC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)"

# --- Write the SYSTEM-run worker script ---
$workerScript = @'
$requestFile = "C:\BlueOps\request.json"
if (-not (Test-Path $requestFile)) { exit }

$req = Get-Content $requestFile | ConvertFrom-Json
$map = @{ "AD"="NTDS"; "DNS"="DNS"; "Openfire"="openfire"; "Telnet"="TlntSvr"; "IIS"="W3SVC"; "CA"="CertSvc" }
$svcName = $map[$req.Service]

$lockedSDDL = "D:(D;;DCWPDTSD;;;AU)(A;;CCLCSWLORC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)"
$unlockedSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)"

sc.exe sdset $svcName $unlockedSDDL | Out-Null

switch ($req.Action) {
    "Stop"    { Stop-Service -Name $svcName -Force }
    "Start"   { Start-Service -Name $svcName }
    "Restart" { Restart-Service -Name $svcName -Force }
}

Start-Sleep -Seconds 2
sc.exe sdset $svcName $lockedSDDL | Out-Null
"$(Get-Date -Format u) - $($req.Service) -> $($req.Action) by $(whoami)" | Out-File "C:\BlueOps\audit.log" -Append
Remove-Item $requestFile -Force
'@
$workerScript | Out-File "$baseDir\Svc-Control-Worker.ps1" -Force -Encoding UTF8

# --- Lock down each service that exists on this host ---
foreach ($entry in $services.GetEnumerator()) {
    $svcName = $entry.Value
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "[SKIP] $($entry.Key) ($svcName) not found on this host." -ForegroundColor Yellow
        continue
    }

    sc.exe sdset $svcName $lockedSDDL | Out-Null
    sc.exe failure $svcName reset=0 actions=restart/5000/restart/5000/restart/5000 | Out-Null
    sc.exe failureflag $svcName 1 | Out-Null

    if ($svc.Status -ne "Running") { Start-Service -Name $svcName }
    Write-Host "[LOCKED] $($entry.Key) ($svcName) - stop denied to all but SYSTEM, auto-restart armed." -ForegroundColor Green
}

Write-Host "`nDeployment complete. Use Svc-Control.ps1 to make changes from now on." -ForegroundColor Cyan
