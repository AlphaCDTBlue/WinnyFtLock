#Requires -Version 5.1
#Requires -RunAsAdministrator
# CDT: Block/unblock one verified remote IP. Does not change baseline allow rules.
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][string]$IP,
    [switch]$Unblock,
    [int]$LogoffSessionId = -1
)
$ErrorActionPreference = 'Stop'
$address = $null
if (-not [Net.IPAddress]::TryParse($IP, [ref]$address) -or
    $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'Enter one IPv4 address (not a hostname or subnet).'
}
$IP = $address.ToString()
if ($IP -eq '0.0.0.0' -or $IP -eq '255.255.255.255' -or
    $IP.StartsWith('127.') -or $IP.StartsWith('169.254.') -or
    [int]($IP.Split('.')[0]) -ge 224) {
    throw 'Refusing to use a loopback, link-local, multicast, broadcast or unspecified address.'
}
if ($Unblock -and $LogoffSessionId -ge 0) {
    throw '-Unblock cannot be combined with -LogoffSessionId.'
}
$names = @("CDT-Block-Inbound-$IP", "CDT-Block-Outbound-$IP")

if ($Unblock) {
    $found = @(foreach ($name in $names) {
        Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    })
    if (-not $found.Count) {
        Write-Host "No CDT block rules found for $IP. Nothing to remove."
        return
    }
    $found | Select-Object Name,Direction,Enabled,Action | Format-Table -AutoSize | Out-Host
    if (-not $WhatIfPreference) {
        $answer = Read-Host "Type UNBLOCK $IP to remove ONLY these rules"
        if ($answer -cne "UNBLOCK $IP") { Write-Host 'Cancelled.'; return }
    }
    foreach ($rule in $found) {
        if ($PSCmdlet.ShouldProcess($rule.Name, 'Remove CDT firewall block')) {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
        }
    }
    $remaining = @(foreach ($name in $names) { Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue })
    if ($remaining.Count) { Write-Warning "Some CDT block rules still exist for $IP." }
    elseif (-not $WhatIfPreference) { Write-Host "CDT block rules removed for $IP. Existing firewall policy still applies." -ForegroundColor Green }
    return
}

# Preflight: identify active Windows network profiles, then check their firewall state.
$connections = @(Get-NetConnectionProfile -ErrorAction Stop)
if (-not $connections.Count) { throw 'Cannot determine active network profile; refusing to create an unverified block.' }
$profileNames = @($connections | ForEach-Object {
    if ($_.NetworkCategory -eq 'DomainAuthenticated') { 'Domain' }
    else { [string]$_.NetworkCategory }
} | Sort-Object -Unique)
$profiles = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { $profileNames -contains $_.Name })
if (-not $profiles.Count) { throw 'Could not match an active Windows Firewall profile.' }
$profiles | Select-Object Name,Enabled,DefaultInboundAction | Format-Table -AutoSize | Out-Host
if (@($profiles | Where-Object { $_.Enabled -ne $true }).Count -gt 0) {
    throw 'Windows Firewall is disabled on an active network profile. No rules created. Coordinate firewall configuration before blocking.'
}
Write-Host "=== Connections involving $IP ==="
Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object RemoteAddress -eq $IP |
    Select-Object State,LocalPort,RemoteAddress,RemotePort,OwningProcess | Format-Table -AutoSize | Out-Host
Write-Host '=== Interactive sessions (IP is NOT automatically linked to session IDs) ==='
& quser.exe 2>&1 | Out-Host
Write-Warning 'Confirm the IP is not scoring infrastructure, Grey Team, your jumpbox, or an approved management host.'
if (-not $WhatIfPreference) {
    $answer = Read-Host "Type BLOCK $IP to create inbound and outbound block rules"
    if ($answer -cne "BLOCK $IP") { Write-Host 'Cancelled.'; return }
}
foreach ($direction in @('Inbound','Outbound')) {
    $name = "CDT-Block-$direction-$IP"
    $existing = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    if ($existing) {
        $filter = $existing | Get-NetFirewallAddressFilter
        if ($existing.Action -ne 'Block' -or $existing.Direction -ne $direction -or
            $existing.Enabled -ne 'True' -or $filter.RemoteAddress -ne $IP) {
            throw "Existing rule $name has unexpected settings. Review it manually."
        }
        Write-Host "Already present: $name"
    } elseif ($PSCmdlet.ShouldProcess("$IP ($direction)", 'Create Windows Firewall block rule')) {
        New-NetFirewallRule -Name $name -DisplayName $name -Direction $direction `
            -Action Block -Protocol Any -RemoteAddress $IP -Profile Any -Enabled True | Out-Null
    }
}
Write-Host '=== CDT block rule status ==='
foreach ($name in $names) {
    Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue |
        Select-Object Name,Direction,Enabled,Action | Format-Table -AutoSize | Out-Host
}
if ($LogoffSessionId -ge 0) {
    $mySession = (Get-Process -Id $PID).SessionId
    if ($LogoffSessionId -eq $mySession) { throw 'Refusing to log off the current PowerShell session.' }
    Write-Warning "The script CANNOT prove session $LogoffSessionId belongs to $IP. Verify with quser and approved session records."
    if (-not $WhatIfPreference) {
        $answer = Read-Host "Type LOGOFF $LogoffSessionId after verifying it is not a Grey Team or approved session"
        if ($answer -cne "LOGOFF $LogoffSessionId") { Write-Host 'Session logoff skipped.'; return }
    }
    if ($PSCmdlet.ShouldProcess("session $LogoffSessionId", 'Log off Windows session')) {
        & logoff.exe $LogoffSessionId
    }
}
Write-Host 'Note: Existing TCP connections may persist; test with a NEW connection.'
