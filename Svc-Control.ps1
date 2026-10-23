# Svc-Control.ps1
param(
    [Parameter(Mandatory)][ValidateSet("AD","DNS","Openfire","Telnet","IIS","CA")][string]$Service,
    [Parameter(Mandatory)][ValidateSet("Stop","Start","Restart")][string]$Action
)

$requestFile = "C:\BlueOps\request.json"
@{ Service = $Service; Action = $Action } | ConvertTo-Json | Out-File $requestFile -Force

Start-ScheduledTask -TaskName "BlueOps-SvcControl"
Start-Sleep -Seconds 3

if (Test-Path $requestFile) {
    Write-Host "Request still pending or task failed — check Task Scheduler history for BlueOps-SvcControl." -ForegroundColor Yellow
} else {
    Write-Host "$Action on $Service completed." -ForegroundColor Green
}
