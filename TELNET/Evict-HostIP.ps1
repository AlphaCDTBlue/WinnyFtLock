
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
 [Parameter(Mandatory=$true)][string]$IP,
 [int]$LogoffSessionId = -1
)
$ErrorActionPreference='Stop'
$parsed=$null
if(-not [System.Net.IPAddress]::TryParse($IP,[ref]$parsed)) { throw 'Provide one valid IPv4 or IPv6 address.' }
if($parsed.IsIPv6LinkLocal -or $parsed.IsIPv6Multicast -or [System.Net.IPAddress]::IsLoopback($parsed) -or $parsed.Equals([System.Net.IPAddress]::Any)) { throw 'Refusing to block loopback, wildcard, link-local, or multicast addresses.' }
Write-Host "=== Connections involving $IP ==="
Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object RemoteAddress -eq $IP |
 Select-Object State,LocalPort,RemoteAddress,RemotePort,OwningProcess | Format-Table -AutoSize
Write-Host '=== Windows sessions (IP-to-session mapping is NOT established) ==='
quser 2>&1 | Out-Host
Write-Warning 'Verify this is NOT scoring infrastructure, Grey Team, a shared jumpbox, or your own management IP. CDT prohibits blocking scoring infrastructure.'
$ack=Read-Host "Type BLOCK $IP to create two host-wide firewall rules"
if($ack -cne "BLOCK $IP") { Write-Host 'Cancelled.'; return }
$tag=($IP -replace '[^0-9a-fA-F:.]','_')
foreach($dir in @('Inbound','Outbound')) {
 $name="CDT-Block-$dir-$tag"
 if(-not (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)) {
   if($PSCmdlet.ShouldProcess("$IP $dir",'Create block firewall rule')) {
     New-NetFirewallRule -Name $name -DisplayName $name -Direction $dir -Action Block -RemoteAddress $IP -Profile Any | Out-Null
   }
 }
}
Write-Host 'Firewall rule status:'
Get-NetFirewallRule -Name "CDT-Block-*-$tag" -ErrorAction SilentlyContinue | Select-Object Name,Direction,Enabled,Action | Format-Table
if($LogoffSessionId -ge 0) {
 Write-Warning "You requested logoff of session ID $LogoffSessionId. This script CANNOT prove that session belongs to $IP."
 $sessions=(quser 2>&1 | Out-String)
 Write-Host $sessions
 $current=[string]$env:SESSIONNAME
 Write-Warning "Current session name: $current. Do not log off your own or Grey Team sessions."
 $confirm=Read-Host "After independently confirming ownership, type LOGOFF $LogoffSessionId"
 if($confirm -ceq "LOGOFF $LogoffSessionId") {
   if($PSCmdlet.ShouldProcess("Windows session $LogoffSessionId",'Log off session')) { logoff $LogoffSessionId }
 } else { Write-Host 'Session logoff skipped.' }
} else {
 Write-Host 'No Windows logon session terminated. To log off a VERIFIED session, rerun with -LogoffSessionId <ID>.'
}
Write-Host 'NOTE: firewall blocks may not immediately end established connections. Do not kill a shared service process to disconnect a client.'
