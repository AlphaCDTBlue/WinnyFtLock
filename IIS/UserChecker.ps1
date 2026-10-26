# UserChecker.ps1 - run as Administrator, NO arguments.
# Loops every 10 seconds (Ctrl+C to stop). Each pass removes every LOCAL user
# that isn't the one expected local admin account or on the grey team list.
# Keep this window open. Disconnecting RDP is fine, but do not log off.
#
# The 11 packet usernames (mrkrabs, spongebob, etc.) are DOMAIN accounts on
# this box, per team policy - they should never exist as LOCAL accounts here.
# A local account using one of those names is not legitimate: it's either a
# leftover mistake or a red-team account impersonating a real packet user to
# hide from a name-based allow-list. Those names are therefore NOT allowed
# below; they're only kept in $WatchForImpostorNames so a match gets called
# out loudly instead of being removed silently like ordinary junk accounts.

# ===== EDIT: the one local admin account name on this box =====
$LocalAdminAccount = 'jellyfish'
$GreyTeamUsers = @(
    'kingneptune',
    'paintythepirate',
    'greyteamadmin'
)
# Domain-only usernames: flagged specially if ever seen as a LOCAL account.
$WatchForImpostorNames = @(
    'mrkrabs', 'spongebob', 'squidward', 'patrick', 'sandy',
    'gary', 'puff', 'larry', 'mermaidman', 'barnacleboy'
)
# ================================================================
$IntervalSeconds = 10

$ErrorActionPreference = 'Continue'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this as Administrator.' -ForegroundColor Red; exit 1 }
if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2) {
    Write-Host 'This is a domain controller - local accounts do not exist here. Aborting.' -ForegroundColor Red; exit 1
}

$meName = $id.Name.Split('\')[-1]
$allowed = @{}
foreach ($n in (@($LocalAdminAccount) + @($GreyTeamUsers))) {
    if ($n -and $n.Trim()) { $allowed[$n.Trim()] = $true }
}
$impostorWatch = @{}
foreach ($n in $WatchForImpostorNames) { if ($n -and $n.Trim()) { $impostorWatch[$n.Trim()] = $true } }
if ($allowed.Count -eq 0 -or ($allowed.Keys -match '^REPLACE')) {
    Write-Host 'Set $LocalAdminAccount (and the grey list) at the top first. Aborting.' -ForegroundColor Red; exit 1
}

$LogDir = Join-Path $env:ProgramData 'BlueOps'
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$LogFile = Join-Path $LogDir 'UserChecker.log'
function Log([string]$m) { Add-Content -Path $LogFile -Value ((Get-Date -Format s) + '  ' + $m) }

# Prints a line over the in-place heartbeat line
function Say([string]$m, [string]$c = 'Gray') {
    Write-Host ("`r" + $m + (' ' * 30)) -ForegroundColor $c
}

function Get-SessionIds([string]$UserName) {
    $ids = @()
    $lines = & quser 2>$null
    foreach ($line in $lines) {
        if ($line -match 'USERNAME') { continue }
        $parts = ($line -replace '^\s*>', ' ').Trim() -split '\s{2,}'
        if ($parts.Count -lt 2) { continue }
        if ($parts[0] -ieq $UserName) {
            foreach ($p in $parts[1..($parts.Count - 1)]) {
                if ($p -match '^\d+$') { $ids += [int]$p; break }
            }
        }
    }
    return $ids
}

function Stop-UserProcesses($Names) {
    $set = @{}
    foreach ($n in $Names) { $set[$n] = $true }
    foreach ($p in (Get-CimInstance Win32_Process)) {
        try {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($o.User -and $set.ContainsKey($o.User) -and ($o.Domain -ieq $env:COMPUTERNAME)) {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
            }
        } catch { }
    }
}

$warned = @{}
$script:changes = 0

function Invoke-UserCheck {
    $localUsers = @(Get-LocalUser)
    $toRemove = @()
    $toDisable = @()
    foreach ($u in $localUsers) {
        if ($allowed.ContainsKey($u.Name)) { continue }
        $sid = $u.SID.Value
        $rid = $sid.Substring($sid.LastIndexOf('-') + 1)
        if ($u.Name -ieq $meName) {
            if (-not $warned.ContainsKey($u.Name)) { $warned[$u.Name] = $true; Say "SKIP  $($u.Name) - that is the account running this script, not in the list" 'Yellow' }
            continue
        }
        if ($rid -eq '500') {
            if (-not $warned.ContainsKey($u.Name)) { $warned[$u.Name] = $true; Say "WARN  built-in Administrator ($($u.Name)) is not in the list and cannot be deleted - handle it yourself" 'Yellow' }
            continue
        }
        if (@('501', '503', '504') -contains $rid) { $toDisable += $u; continue }
        if ($impostorWatch.ContainsKey($u.Name)) {
            Say "IMPOSTOR  local account '$($u.Name)' uses a DOMAIN-only packet username - this should never exist as a local account. Removing it." 'Red'
            Log "IMPOSTOR $($u.Name) SID=$($u.SID.Value) - domain-only packet username found as a local account"
        }
        $toRemove += $u
    }

    foreach ($u in $toDisable) {
        try {
            if ($u.Enabled) {
                Disable-LocalUser -SID $u.SID -ErrorAction Stop
                $script:changes++
                Say "DISABLED built-in $($u.Name)" 'Cyan'
                Log "DISABLED $($u.Name)"
            }
        } catch { Say "FAIL disabling $($u.Name): $($_.Exception.Message)" 'Red' }
    }

    if ($toRemove.Count -gt 0) {
        $script:changes++
        foreach ($u in $toRemove) { try { Disable-LocalUser -SID $u.SID -ErrorAction Stop } catch { } }
        foreach ($u in $toRemove) { foreach ($s in (Get-SessionIds $u.Name)) { & logoff $s 2>$null } }
        Stop-UserProcesses ($toRemove | ForEach-Object { $_.Name })
        foreach ($u in $toRemove) {
            try {
                Remove-LocalUser -SID $u.SID -ErrorAction Stop
                Say ("REMOVED  $($u.Name)  ($($u.SID.Value))  at " + (Get-Date -Format 'HH:mm:ss')) 'Green'
                Log "REMOVED $($u.Name) SID=$($u.SID.Value) WasEnabled=$($u.Enabled) LastLogon=$($u.LastLogon)"
            } catch {
                Say "FAIL removing $($u.Name): $($_.Exception.Message)" 'Red'
                Log "FAILED $($u.Name): $($_.Exception.Message)"
            }
        }
    }
}

# ---- startup info (once) ----
Write-Host "UserChecker running every $IntervalSeconds seconds. Ctrl+C to stop. Log: $LogFile" -ForegroundColor Cyan
Write-Host 'Local Administrators group right now:' -ForegroundColor Cyan
& net localgroup Administrators | Out-Host

# ---- main loop ----
$cycle = 0
while ($true) {
    $cycle++
    $script:changes = 0
    try { Invoke-UserCheck } catch { Say ('Cycle error: ' + $_.Exception.Message) 'Red' }
    if ($script:changes -eq 0) {
        Write-Host ("`r[{0}] pass {1}: no unauthorized users" -f (Get-Date -Format 'HH:mm:ss'), $cycle) -NoNewline
    }
    Start-Sleep -Seconds $IntervalSeconds
}
