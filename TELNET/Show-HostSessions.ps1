
# Show-HostSessions.ps1 - CDT Windows host session snapshot
# Read-only. Run in elevated Windows PowerShell for access to Security events.
[CmdletBinding()]
param(
    [ValidateRange(1,10080)][int]$Minutes = 60
)
$ErrorActionPreference = 'Stop'
$currentSessionId = (Get-Process -Id $PID).SessionId

# Reuse the WTS client-address lookup from the team's sessionrevokewin.ps1.
if (-not ('CDTSessionClientAddress' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Runtime.InteropServices;
public static class CDTSessionClientAddress {
    [DllImport("Wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytesReturned);
    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
    public static string Get(int sessionId) {
        IntPtr buffer; int length;
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, 14, out buffer, out length)) return "Unavailable";
        try {
            if (buffer == IntPtr.Zero || length < 22) return "Unknown";
            byte[] address = new byte[20];
            Marshal.Copy(IntPtr.Add(buffer, 2), address, 0, address.Length);
            ushort family = unchecked((ushort)Marshal.ReadInt16(buffer));
            if (family == 2) {
                byte[] ipv4 = new byte[] { address[0], address[1], address[2], address[3] };
                if (ipv4[0]==0 && ipv4[1]==0 && ipv4[2]==0 && ipv4[3]==0) return "Local/unknown";
                return new IPAddress(ipv4).ToString();
            }
            if (family == 23) {
                byte[] ipv6 = new byte[16]; Array.Copy(address, ipv6, 16);
                return new IPAddress(ipv6).ToString();
            }
            return "Local/unknown";
        } finally { WTSFreeMemory(buffer); }
    }
}
'@
}

Write-Host "`n=== INTERACTIVE WINDOWS SESSIONS ===" -ForegroundColor Cyan
$quserOutput = @(& "$env:SystemRoot\System32\quser.exe" 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-Warning "quser unavailable: $($quserOutput -join ' ')"
} else {
    $sessions = @(
        foreach ($line in ($quserOutput | Select-Object -Skip 1)) {
            if ($line -match '^\s*>?\s*(\S+)\s+(?:(\S+)\s+)?(\d+)\s+(\S+)') {
                [pscustomobject]@{
                    User = $Matches[1]
                    SessionName = $Matches[2]
                    Id = [int]$Matches[3]
                    State = $Matches[4]
                    OriginIP = [CDTSessionClientAddress]::Get([int]$Matches[3])
                    Current = ([int]$Matches[3] -eq $currentSessionId)
                }
            }
        }
    )
    if ($sessions.Count) { $sessions | Format-Table -AutoSize | Out-Host }
    else { Write-Host 'No interactive sessions parsed.' }
}

Write-Host "`n=== ESTABLISHED TCP CONNECTIONS ===" -ForegroundColor Cyan
try {
    $connections = @(Get-NetTCPConnection -State Established -ErrorAction Stop |
        Where-Object { $_.RemoteAddress -notin @('127.0.0.1','::1') } |
        Sort-Object RemoteAddress, LocalPort |
        Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess)
    if ($connections.Count) { $connections | Format-Table -AutoSize | Out-Host }
    else { Write-Host 'No established remote TCP connections.' }
} catch { Write-Warning "Could not enumerate TCP connections: $($_.Exception.Message)" }

Write-Host "`n=== RECENT WINDOWS AUTHENTICATION EVENTS (LAST $Minutes MIN) ===" -ForegroundColor Cyan
try {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddMinutes(-$Minutes)
    } -ErrorAction Stop)
    $rows = @(
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $fields = @{}
            foreach ($field in $xml.Event.EventData.Data) { $fields[[string]$field.Name] = [string]$field.'#text' }
            $sourceIP = $fields['IpAddress']
            if ([string]::IsNullOrWhiteSpace($sourceIP) -or $sourceIP -eq '-') { continue }
            [pscustomobject]@{
                Time = $event.TimeCreated
                Result = if ($event.Id -eq 4624) {'SUCCESS'} else {'FAILED'}
                User = $fields['TargetUserName']
                SourceIP = $sourceIP
                LogonType = $fields['LogonType']
            }
        }
    )
    if ($rows.Count) { $rows | Sort-Object Time -Descending | Format-Table -AutoSize | Out-Host }
    else { Write-Host 'No authentication events with source IPs in this time window.' }
} catch {
    Write-Warning "Could not read Security events (admin rights/audit policy may be needed): $($_.Exception.Message)"
}
Write-Host "`nNOTE: WTS OriginIP identifies interactive client addresses when available."
Write-Host 'Security events and TCP connections are separate evidence; do not assume they map to a session ID.'
Write-Host 'WinRM, SSH and independent backdoors may not appear as interactive quser sessions.'
