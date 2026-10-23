# FullRestoreService.ps1
param(
    [Parameter(Mandatory)][ValidateSet("AD","DNS","Openfire","Telnet","IIS","CA")][string]$Service
)

$map = @{ "AD"="NTDS"; "DNS"="DNS"; "Openfire"="openfire"; "Telnet"="TlntSvr"; "IIS"="W3SVC"; "CA"="CertSvc" }
$svcName = $map[$Service]

$fixedSDDL = "D:(D;;DCWPDTSD;;;AU)(A;;CCLCSWLORC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)"

$cmdFile = "C:\BlueOps\restore_$svcName.cmd"
"sc sdset $svcName `"$fixedSDDL`"" | Out-File $cmdFile -Encoding ASCII

schtasks /create /tn "WindowsServiceHealthCheck" /tr $cmdFile /sc once /st 00:00 /ru SYSTEM /f | Out-Null
schtasks /run /tn "WindowsServiceHealthCheck" | Out-Null
Start-Sleep -Seconds 3
schtasks /delete /tn "WindowsServiceHealthCheck" /f | Out-Null
Remove-Item $cmdFile -Force -ErrorAction SilentlyContinue

sc.exe sdshow $svcName
Write-Host "`n$Service permissions restored to query+control baseline." -ForegroundColor Green
