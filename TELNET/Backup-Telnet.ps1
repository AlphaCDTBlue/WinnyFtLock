
#Requires -Version 5.1
# Backup-Telnet.ps1 - CDT Telnet service snapshot (read-only)
[CmdletBinding()]
param([string]$BackupRoot = (Join-Path $PSScriptRoot 'TelnetBackups'))
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$destination = Join-Path $BackupRoot $stamp
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$manifest = [ordered]@{ Timestamp=(Get-Date).ToString('o'); Hostname=$env:COMPUTERNAME; Services=@(); Files=@(); Warnings=@() }
function Save-FileIfPresent([string]$Path) {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $folder = Join-Path $destination 'config-files'
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $safeName = ($Path -replace '[:\\/]', '_')
        $target = Join-Path $folder $safeName
        Copy-Item -LiteralPath $Path -Destination $target -Force
        $manifest.Files += [ordered]@{ Source=$Path; Backup=$target }
    }
}
try {
    $services = @(Get-CimInstance Win32_Service | Where-Object {
        $_.Name -match '(?i)telnet|tlnt|inetd' -or $_.DisplayName -match '(?i)telnet|tlnt|inetd'
    })
    $services | Select-Object Name,DisplayName,State,StartMode,PathName,StartName |
        Export-Clixml -Path (Join-Path $destination 'services.xml')
    foreach ($svc in $services) {
        $manifest.Services += $svc.Name
        $key = "HKLM\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
        & reg.exe export $key (Join-Path $destination "service-$($svc.Name).reg") /y | Out-Null
        if ($LASTEXITCODE -ne 0) { $manifest.Warnings += "Registry export failed: $($svc.Name)" }
        & sc.exe qc $svc.Name | Out-File -FilePath (Join-Path $destination "service-$($svc.Name)-qc.txt") -Encoding utf8
    }
    # Common legacy Windows Telnet configuration (only if present).
    Save-FileIfPresent "$env:SystemRoot\System32\tlntsvr.exe.config"
    # Snapshot TCP listeners on Telnet's default port (does not assume service identity).
    Get-NetTCPConnection -LocalPort 23 -ErrorAction SilentlyContinue |
        Select-Object LocalAddress,LocalPort,State,OwningProcess |
        Export-Csv -NoTypeInformation -Path (Join-Path $destination 'port23-connections.csv')
    # Full firewall policy export is more reliable for restoring rule dependencies.
    & netsh.exe advfirewall export (Join-Path $destination 'firewall-policy.wfw') | Out-Null
    if ($LASTEXITCODE -ne 0) { $manifest.Warnings += 'Firewall policy export failed.' }
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match '(?i)telnet|port.?23' -or $_.Name -match '(?i)telnet|port.?23' } |
        Select-Object Name,DisplayName,Enabled,Direction,Action,Profile |
        Export-Csv -NoTypeInformation -Path (Join-Path $destination 'telnet-named-firewall-rules.csv')
} catch {
    $manifest.Warnings += $_.Exception.Message
} finally {
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $destination 'manifest.json') -Encoding UTF8
}
Write-Host "Telnet backup saved: $destination"
if ($manifest.Services.Count -eq 0) { Write-Warning 'No named Telnet/inetd service found. Verify which process owns port 23.' }
foreach ($warning in $manifest.Warnings) { Write-Warning $warning }
if ($manifest.Warnings.Count -gt 0) { exit 1 }
