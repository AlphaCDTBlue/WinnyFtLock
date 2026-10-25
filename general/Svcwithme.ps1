param(
    [Parameter(Mandatory)][ValidateSet("AD","DNS","Openfire","Telnet","IIS","CA")][string]$Service,
    [Parameter(Mandatory)][ValidateSet("Stop","Start","Restart")][string]$Action
)

$requestFile = "C:\BlueOps\request.json"
@{ Service = $Service; Action = $Action } | ConvertTo-Json | Out-File $requestFile -Force

$taskName = "BthServiceMonitor"
$taskPath = "\Microsoft\Windows\Bluetooth\"

$tAction = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\BlueOps\Svc-Control-Worker.ps1"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $tAction -Principal $principal -Force | Out-Null

Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath

$timeout = 15
while ((Test-Path $requestFile) -and $timeout -gt 0) {
    Start-Sleep -Seconds 1
    $timeout--
}

Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false

if (Test-Path $requestFile) {
    Write-Host "Request still pending or task failed." -ForegroundColor Yellow
} else {
    Write-Host "$Action on $Service completed." -ForegroundColor Green
}
