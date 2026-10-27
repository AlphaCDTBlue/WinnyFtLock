#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Block-IP.ps1 - blocks one IP address in Windows Firewall (inbound and outbound).

.DESCRIPTION
  Run in an elevated PowerShell:
      .\Block-IP.ps1 -Ask
  Type the IP when asked. That is all it does. Without -Ask nothing happens.

  Creates two rules, "Block IP <ip> In" and "Block IP <ip> Out". Block rules
  win over allow rules in Windows Firewall. Undo with Unblock-IP.ps1.
#>
[CmdletBinding()]
param([switch]$Ask)

$ErrorActionPreference = 'Stop'

# nothing happens unless -Ask is given
if (-not $Ask) {
    Write-Host 'Nothing done. Run with -Ask:  .\Block-IP.ps1 -Ask'
    exit 0
}

$text = (Read-Host 'IP address to block').Trim()

# must look like a real IPv4 (a.b.c.d) or IPv6 address
$ip = $null
$looksRight = ($text -match '^\d{1,3}(\.\d{1,3}){3}$') -or ($text -match ':')
if ((-not $looksRight) -or (-not [System.Net.IPAddress]::TryParse($text, [ref]$ip))) {
    Write-Host "'$text' is not a valid IP address." -ForegroundColor Red
    exit 1
}
$text = $ip.IPAddressToString

# never block these
if ($ip.Equals([System.Net.IPAddress]::Any) -or $ip.Equals([System.Net.IPAddress]::IPv6Any) -or $ip.Equals([System.Net.IPAddress]::Broadcast) -or [System.Net.IPAddress]::IsLoopback($ip)) {
    Write-Host "Refusing to block $text." -ForegroundColor Red
    exit 1
}
$mine = @(Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $text })
if ($mine.Count) {
    Write-Host "$text is an address on this server. Refusing." -ForegroundColor Red
    exit 1
}

$nameIn  = "Block IP $text In"
$nameOut = "Block IP $text Out"

if (Get-NetFirewallRule -DisplayName $nameIn -ErrorAction SilentlyContinue) {
    Write-Host "$text is already blocked." -ForegroundColor Yellow
    exit 0
}

# warn if blocking would cut a live connection (for example your own RDP jumpbox)
$live = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -eq $text })
if ($live.Count) {
    $ports = ($live | ForEach-Object { $_.LocalPort } | Select-Object -Unique) -join ', '
    Write-Host "Warning: $text has $($live.Count) active connection(s) to this server (local port $ports)." -ForegroundColor Yellow
    Write-Host "Blocking it will cut them. If that is your RDP session, you will be locked out." -ForegroundColor Yellow
    if ((Read-Host 'Block anyway? (y/N)') -ne 'y') { Write-Host 'Nothing changed.'; exit 0 }
}

New-NetFirewallRule -DisplayName $nameIn  -Direction Inbound  -Action Block -RemoteAddress $text -Profile Any -Enabled True | Out-Null
New-NetFirewallRule -DisplayName $nameOut -Direction Outbound -Action Block -RemoteAddress $text -Profile Any -Enabled True | Out-Null

# confirm both rules exist and are on
$ok = @(Get-NetFirewallRule -DisplayName $nameIn, $nameOut -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
if ($ok.Count -eq 2) {
    Write-Host "Blocked $text (inbound and outbound)." -ForegroundColor Green
} else {
    Write-Host "Something went wrong: only $($ok.Count) of 2 rules are active for $text." -ForegroundColor Red
}

# rules do nothing if the firewall itself is off
$off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
if ($off.Count) {
    Write-Host "Warning: Windows Firewall is OFF for profile(s): $($off -join ', '). These rules will not work until it is turned on." -ForegroundColor Yellow
}
