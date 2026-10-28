#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Block-IP.ps1 - blocks (or unblocks) one IP address in Windows Firewall.

.DESCRIPTION
  Run in an elevated PowerShell:
      .\Block-IP.ps1 -Ask        block an IP: type it when asked
      .\Block-IP.ps1 -Reverse    undo a block: shows what is blocked, then type the IP
  With neither switch, nothing happens. Use one, not both.

  Block (-Ask) makes two rules, "Block IP <ip> In" and "Block IP <ip> Out".
  Block rules win over allow rules. If the rules already exist it CHECKS them
  (enabled, block, right direction, right address, all ports and protocols)
  and repairs any that are missing, disabled or changed. So running it again
  also re-asserts a block that red team switched off.

  Before blocking, be sure the IP is not the scoring engine, Grey Team, or a
  jumpbox you use. The script cannot know those addresses. It only warns when
  the IP has a live connection to this server right now.
#>
[CmdletBinding()]
param(
    [switch]$Ask,
    [switch]$Reverse
)

$ErrorActionPreference = 'Stop'

if ($Ask -and $Reverse) {
    Write-Host 'Use only one of -Ask (block) or -Reverse (unblock).' -ForegroundColor Red
    exit 1
}
if ((-not $Ask) -and (-not $Reverse)) {
    Write-Host 'Nothing done. Use -Ask to block an IP or -Reverse to undo a block:'
    Write-Host '  .\Block-IP.ps1 -Ask'
    Write-Host '  .\Block-IP.ps1 -Reverse'
    exit 0
}

# ---------------------------- helpers ----------------------------
function Read-Ip([string]$prompt) {
    $entry = (Read-Host $prompt).Trim()
    $ip = $null
    $looksRight = ($entry -match '^\d{1,3}(\.\d{1,3}){3}$') -or ($entry -match ':')
    if ((-not $looksRight) -or (-not [System.Net.IPAddress]::TryParse($entry, [ref]$ip))) {
        Write-Host "'$entry' is not a valid IP address." -ForegroundColor Red
        exit 1
    }
    return $ip
}

# Returns matching rules, or an empty list if there are none. A real error is
# shown and stops the script; it is never reported as "none found".
function Get-BlockRules([string]$name) {
    try {
        return @(Get-NetFirewallRule -DisplayName $name -ErrorAction Stop)
    } catch {
        if (($_.FullyQualifiedErrorId -match 'NotFound') -or ($_.Exception.Message -match 'No MSFT_NetFirewallRule objects found')) {
            return @()
        }
        Write-Host "ERROR: could not read firewall rules: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# true only if the rule really blocks this one address, in this direction, everywhere
function Test-RuleGood($rule, [string]$dir, [string]$text) {
    if (-not $rule) { return $false }
    try {
        $addr = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress)
        $port = $rule | Get-NetFirewallPortFilter
        return (
            ($rule.Enabled -eq 'True') -and ($rule.Action -eq 'Block') -and
            ($rule.Direction -eq $dir) -and ($rule.Profile -eq 'Any') -and
            ($addr.Count -eq 1) -and ($addr[0] -ieq $text) -and
            ($port.Protocol -eq 'Any') -and (@($port.LocalPort) -contains 'Any') -and (@($port.RemotePort) -contains 'Any')
        )
    } catch {
        return $false
    }
}

# ============================ REVERSE ============================
if ($Reverse) {
    $all = @(Get-BlockRules 'Block IP *')
    if (-not $all.Count) {
        Write-Host 'No blocked IPs found (no "Block IP ..." rules).'
        exit 0
    }
    Write-Host 'Currently blocked:'
    $all | ForEach-Object { $_.DisplayName -replace '^Block IP ', '' -replace ' (In|Out)$', '' } | Select-Object -Unique | ForEach-Object { Write-Host "  $_" }
    Write-Host ''

    $ip = Read-Ip 'IP address to unblock'
    $text = $ip.IPAddressToString

    $rules = @(Get-BlockRules "Block IP $text In") + @(Get-BlockRules "Block IP $text Out")
    if (-not $rules.Count) {
        Write-Host "$text is not blocked by this script." -ForegroundColor Yellow
        exit 0
    }
    try {
        $rules | Remove-NetFirewallRule -ErrorAction Stop
    } catch {
        Write-Host "ERROR: could not remove the rules: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    $left = @(Get-BlockRules "Block IP $text *")
    if ($left.Count) {
        Write-Host "ERROR: $($left.Count) rule(s) for $text are still there." -ForegroundColor Red
        exit 1
    }
    Write-Host "Unblocked $text (removed $($rules.Count) rule(s))." -ForegroundColor Green
    exit 0
}

# ============================== BLOCK ==============================
$ip = Read-Ip 'IP address to block'
$text = $ip.IPAddressToString

# never block these
if ($ip.Equals([System.Net.IPAddress]::Any) -or $ip.Equals([System.Net.IPAddress]::IPv6Any) -or $ip.Equals([System.Net.IPAddress]::Broadcast) -or [System.Net.IPAddress]::IsLoopback($ip)) {
    Write-Host "Refusing to block $text." -ForegroundColor Red
    exit 1
}
$mine = @()
try { $mine = @(Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.IPAddress -eq $text }) }
catch { Write-Host "Note: could not check this server's own addresses ($($_.Exception.Message))." -ForegroundColor Yellow }
if ($mine.Count) {
    Write-Host "$text is an address on this server. Refusing." -ForegroundColor Red
    exit 1
}

Write-Host 'Reminder: do not block the scoring engine, Grey Team, or your own jumpbox.' -ForegroundColor Yellow

$spec = @(
    @{ Name = "Block IP $text In";  Dir = 'Inbound';  Good = $false },
    @{ Name = "Block IP $text Out"; Dir = 'Outbound'; Good = $false }
)

# check what already exists
foreach ($s in $spec) {
    $r = @(Get-BlockRules $s.Name)
    $s.Good = ($r.Count -eq 1) -and (Test-RuleGood $r[0] $s.Dir $text)
}
if ($spec[0].Good -and $spec[1].Good) {
    Write-Host "$text is already blocked. Both rules checked: on, block, correct address." -ForegroundColor Green
    exit 0
}

# warn if blocking would cut a live connection (for example your own RDP jumpbox)
$live = @()
try {
    $live = @(Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object { $_.RemoteAddress -eq $text })
} catch {
    if (($_.FullyQualifiedErrorId -notmatch 'NotFound') -and ($_.Exception.Message -notmatch 'No MSFT_NetTCPConnection objects found')) {
        Write-Host "Note: could not check for live connections ($($_.Exception.Message))." -ForegroundColor Yellow
    }
}
if ($live.Count) {
    $ports = ($live | ForEach-Object { $_.LocalPort } | Select-Object -Unique) -join ', '
    Write-Host "Warning: $text has $($live.Count) active connection(s) to this server (local port $ports)." -ForegroundColor Yellow
    Write-Host 'Blocking it will cut them. If that is your RDP session, you will be locked out.' -ForegroundColor Yellow
    if ((Read-Host 'Block anyway? (y/N)') -ne 'y') { Write-Host 'Nothing changed.'; exit 0 }
}

# create or repair only the rules that are missing or wrong
foreach ($s in $spec) {
    if ($s.Good) { continue }
    try {
        $old = @(Get-BlockRules $s.Name)
        if ($old.Count) { $old | Remove-NetFirewallRule -ErrorAction Stop }
        New-NetFirewallRule -DisplayName $s.Name -Description 'Created by Block-IP.ps1' -Direction $s.Dir -Action Block -RemoteAddress $text -Profile Any -Enabled True -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "ERROR creating '$($s.Name)': $($_.Exception.Message)" -ForegroundColor Red
    }
}

# check again
$bad = @()
foreach ($s in $spec) {
    $r = @(Get-BlockRules $s.Name)
    if (-not (($r.Count -eq 1) -and (Test-RuleGood $r[0] $s.Dir $text))) { $bad += $s.Name }
}
if ($bad.Count) {
    Write-Host "NOT fully blocked. These rules are missing or wrong: $($bad -join ', ')" -ForegroundColor Red
    Write-Host "Run it again, or check Windows Defender Firewall with Advanced Security." -ForegroundColor Red
} else {
    Write-Host "Blocked $text (inbound and outbound). Undo with: .\Block-IP.ps1 -Reverse" -ForegroundColor Green
}

# rules do nothing if the firewall itself is off
try {
    $off = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
    if ($off.Count) {
        Write-Host "Warning: Windows Firewall is OFF for profile(s): $($off -join ', '). These rules will not work until it is turned on." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Note: could not check whether Windows Firewall is on ($($_.Exception.Message))." -ForegroundColor Yellow
}
