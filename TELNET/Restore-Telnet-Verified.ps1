
#Requires -Version 5.1
# CDT Telnet configuration verification and conditional restore.
[CmdletBinding()]
param(
    [string]$BackupRoot = (Join-Path $PSScriptRoot 'TelnetBackups'),
    [string]$BackupPath,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'

if (-not $BackupPath) {
    $candidate = Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction Stop |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'manifest.json') } |
        Sort-Object Name -Descending | Select-Object -First 1
    if (-not $candidate) { throw 'No Telnet backup with manifest.json found.' }
    $BackupPath = $candidate.FullName
}
$BackupPath = (Resolve-Path -LiteralPath $BackupPath).Path
$manifest = Get-Content -LiteralPath (Join-Path $BackupPath 'manifest.json') -Raw | ConvertFrom-Json
if ($manifest.Hostname -ne $env:COMPUTERNAME) { throw 'Backup belongs to a different computer.' }
if (@($manifest.Services).Count -eq 0) { throw 'Backup did not identify a Telnet service. Cannot safely restore.' }
if (@($manifest.Warnings).Count -gt 0) { Write-Warning 'Backup recorded warnings; review its manifest before trusting this snapshot.' }

# Registry exports include a header and blank lines. Compare the exported key
# contents after normalizing line endings and removing the header.
function Get-RegContent([string]$File) {
    $raw = Get-Content -LiteralPath $File -Raw -Encoding Unicode
    return (($raw -replace "`r`n", "`n") -replace '^Windows Registry Editor Version 5\.00\s*', '').Trim()
}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('CDT-Telnet-Verify-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
$changes = New-Object System.Collections.Generic.List[object]
try {
    foreach ($name in @($manifest.Services)) {
        if ($name -notmatch '^[A-Za-z0-9_. -]+$') { throw "Invalid service name: $name" }
        $saved = Join-Path $BackupPath "service-$name.reg"
        if (-not (Test-Path -LiteralPath $saved -PathType Leaf)) { throw "Missing registry backup: $saved" }
        $current = Join-Path $temporary "service-$name.reg"
        $key = "HKLM\SYSTEM\CurrentControlSet\Services\$name"
        & reg.exe export $key $current /y 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $changes.Add([pscustomobject]@{Type='Registry';Name=$name;Status='MISSING';Saved=$saved;Target=$key})
        } elseif ((Get-RegContent $saved) -cne (Get-RegContent $current)) {
            $changes.Add([pscustomobject]@{Type='Registry';Name=$name;Status='CHANGED';Saved=$saved;Target=$key})
        }
    }
    $allowed = Join-Path $env:SystemRoot 'System32\tlntsvr.exe.config'
    foreach ($item in @($manifest.Files)) {
        if ($item.Source -ine $allowed) {
            Write-Warning "Unrecognized backup file skipped: $($item.Source)"
            continue
        }
        $saved = Join-Path $BackupPath ('config-files\' + ($item.Source -replace '[:\\/]', '_'))
        if (-not (Test-Path -LiteralPath $saved -PathType Leaf)) { throw "Backup config file missing: $saved" }
        $status = if (-not (Test-Path -LiteralPath $allowed -PathType Leaf)) { 'MISSING' }
                  elseif ((Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash -ne
                          (Get-FileHash -LiteralPath $allowed -Algorithm SHA256).Hash) { 'CHANGED' }
                  else { 'OK' }
        if ($status -ne 'OK') {
            $changes.Add([pscustomobject]@{Type='File';Name='tlntsvr.exe.config';Status=$status;Saved=$saved;Target=$allowed})
        }
    }
    Write-Host "Backup: $BackupPath"
    if ($changes.Count -eq 0) {
        Write-Host 'No differences detected in backed-up service registry keys or files.' -ForegroundColor Green
        Write-Host 'This does not prove the service works or that all Telnet settings were backed up.'
        return
    }
    Write-Warning 'Differences found compared with the baseline:'
    $changes | Select-Object Type,Name,Status,Target | Format-Table -AutoSize | Out-Host
    Write-Host 'Firewall settings are not compared or restored.'
    if (-not $Apply) { Write-Host 'Preview only. Re-run with -Apply to restore the items above.'; return }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run as Administrator to apply changes.'
    }
    $answer = Read-Host 'Type RESTORE to apply only the listed differences'
    if ($answer -cne 'RESTORE') { Write-Host 'Cancelled; nothing restored.'; return }
    $rollback = Join-Path $BackupPath ('pre-restore-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $rollback | Out-Null
    # Save all current states before applying any change. Missing keys have no current export.
    foreach ($change in $changes) {
        if ($change.Type -eq 'Registry' -and $change.Status -eq 'CHANGED') {
            & reg.exe export $change.Target (Join-Path $rollback "service-$($change.Name).reg") /y | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Cannot create rollback for $($change.Name). No changes applied." }
        }
        if ($change.Type -eq 'File' -and $change.Status -eq 'CHANGED') {
            Copy-Item -LiteralPath $change.Target -Destination (Join-Path $rollback 'tlntsvr.exe.config') -Force
        }
    }
    foreach ($change in $changes) {
        if ($change.Type -eq 'Registry') {
            & reg.exe import $change.Saved | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Registry restore failed for $($change.Name). Check rollback: $rollback" }
        } else {
            Copy-Item -LiteralPath $change.Saved -Destination $change.Target -Force
        }
        Write-Host "Restored $($change.Type): $($change.Name)"
    }
    Write-Host "Rollback snapshot: $rollback"
    Write-Host 'Port 23 listeners:'
    Get-NetTCPConnection -LocalPort 23 -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize
    Write-Warning 'A controlled service restart may be required for registry changes to take effect. Verify Telnet functionality and scoring.'
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
