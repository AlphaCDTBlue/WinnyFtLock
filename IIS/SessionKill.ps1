# SessionKill.ps1 - run as Administrator, NO arguments.
# Logs off every RDP/console session except the one you're running this from.

$ErrorActionPreference = 'Continue'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this as Administrator.' -ForegroundColor Red; exit 1 }

$mySessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId

function Get-Sessions {
    $sessions = @()
    $lines = & quser 2>$null
    foreach ($line in $lines) {
        if ($line -match 'USERNAME') { continue }
        $clean = ($line -replace '^\s*>', ' ').Trim()
        if (-not $clean) { continue }
        $parts = $clean -split '\s{2,}'
        if ($parts.Count -lt 3) { continue }
        $idIndex = -1
        for ($i = 1; $i -lt $parts.Count; $i++) {
            if ($parts[$i] -match '^\d+$') { $idIndex = $i; break }
        }
        if ($idIndex -lt 0) { continue }
        $sessions += [pscustomobject]@{
            UserName  = $parts[0]
            SessionId = [int]$parts[$idIndex]
            Raw       = $clean
        }
    }
    return $sessions
}

$sessions = @(Get-Sessions)
$others = @($sessions | Where-Object { $_.SessionId -ne $mySessionId })

Write-Host "Your session: ID $mySessionId (kept)" -ForegroundColor Cyan

if ($others.Count -eq 0) {
    Write-Host 'No other sessions found - nothing to log off.' -ForegroundColor Green
    exit 0
}

foreach ($s in $others) {
    Write-Host "Logging off session $($s.SessionId)  ($($s.UserName))  -  $($s.Raw)" -ForegroundColor Yellow
    $out = & logoff $s.SessionId 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host '  done' -ForegroundColor Green
    } else {
        Write-Host "  FAILED: $out" -ForegroundColor Red
    }
}

Write-Host ''
Write-Host 'Remaining sessions:' -ForegroundColor Cyan
& quser 2>$null
