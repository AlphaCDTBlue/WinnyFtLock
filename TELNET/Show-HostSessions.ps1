
# Show-HostSessions.ps1
# CDT Windows Host Session Snapshot
#
# Read-only monitoring script.
# Run in elevated Windows PowerShell for Security event access.
#
# Displays:
#   1. Interactive Windows sessions
#   2. Established TCP connections
#   3. Recent Windows authentication events (4624 / 4625)
#
# Usage:
#   .\Show-HostSessions.ps1
#   .\Show-HostSessions.ps1 -Minutes 60
#   .\Show-HostSessions.ps1 -Minutes 120

[CmdletBinding()]
param(
    [ValidateRange(1, 10080)]
    [int]$Minutes = 60
)

$ErrorActionPreference = 'Stop'

$currentSessionId = (Get-Process -Id $PID).SessionId


# ============================================================
# WTS CLIENT ADDRESS LOOKUP
# ============================================================

if (-not ('CDTSessionClientAddress' -as [type])) {

    Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Runtime.InteropServices;

public static class CDTSessionClientAddress {

    [DllImport("Wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr server,
        int sessionId,
        int infoClass,
        out IntPtr buffer,
        out int bytesReturned
    );

    [DllImport("Wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    public static string Get(int sessionId) {

        IntPtr buffer;
        int length;

        if (!WTSQuerySessionInformation(
            IntPtr.Zero,
            sessionId,
            14,
            out buffer,
            out length
        )) {
            return "Unavailable";
        }

        try {

            if (buffer == IntPtr.Zero || length < 22)
                return "Unknown";

            byte[] address = new byte[20];

            Marshal.Copy(
                IntPtr.Add(buffer, 2),
                address,
                0,
                address.Length
            );

            ushort family = unchecked(
                (ushort)Marshal.ReadInt16(buffer)
            );

            if (family == 2) {

                byte[] ipv4 = new byte[] {
                    address[0],
                    address[1],
                    address[2],
                    address[3]
                };

                if (
                    ipv4[0] == 0 &&
                    ipv4[1] == 0 &&
                    ipv4[2] == 0 &&
                    ipv4[3] == 0
                ) {
                    return "Local/unknown";
                }

                return new IPAddress(ipv4).ToString();
            }

            if (family == 23) {

                byte[] ipv6 = new byte[16];

                Array.Copy(address, ipv6, 16);

                return new IPAddress(ipv6).ToString();
            }

            return "Local/unknown";

        } finally {

            WTSFreeMemory(buffer);
        }
    }
}
'@

}


# ============================================================
# 1. INTERACTIVE WINDOWS SESSIONS
# ============================================================

Write-Host "`n=== INTERACTIVE WINDOWS SESSIONS ===" -ForegroundColor Cyan

try {

    $quserOutput = @(
        & "$env:SystemRoot\System32\quser.exe" 2>&1
    )

    if ($LASTEXITCODE -ne 0) {

        Write-Warning "quser unavailable: $($quserOutput -join ' ')"

    } else {

        $sessions = @(

            foreach ($line in ($quserOutput | Select-Object -Skip 1)) {

                if ($line -match '^\s*>?\s*(\S+)\s+(?:(\S+)\s+)?(\d+)\s+(\S+)') {

                    $sessionId = [int]$Matches[3]

                    [pscustomobject]@{
                        User        = $Matches[1]
                        SessionName = $Matches[2]
                        Id          = $sessionId
                        State       = $Matches[4]
                        OriginIP    = [CDTSessionClientAddress]::Get($sessionId)
                        Current     = ($sessionId -eq $currentSessionId)
                    }
                }
            }
        )

        if ($sessions.Count) {

            $sessions |
                Format-Table -AutoSize |
                Out-Host

        } else {

            Write-Host 'No interactive sessions parsed.'
        }
    }

} catch {

    Write-Warning "Could not enumerate interactive sessions: $($_.Exception.Message)"
}


# ============================================================
# 2. ESTABLISHED TCP CONNECTIONS
# ============================================================

Write-Host "`n=== ESTABLISHED TCP CONNECTIONS ===" -ForegroundColor Cyan

try {

    $connections = @(

        Get-NetTCPConnection -State Established -ErrorAction Stop |

            Where-Object {
                $_.RemoteAddress -notin @(
                    '127.0.0.1',
                    '::1'
                )
            } |

            Sort-Object RemoteAddress, LocalPort |

            Select-Object `
                LocalAddress,
                LocalPort,
                RemoteAddress,
                RemotePort,
                OwningProcess
    )

    if ($connections.Count) {

        $connections |
            Format-Table -AutoSize |
            Out-Host

    } else {

        Write-Host 'No established remote TCP connections.'
    }

} catch {

    Write-Warning "Could not enumerate TCP connections: $($_.Exception.Message)"
}


# ============================================================
# 3. WINDOWS AUTHENTICATION EVENTS
# ============================================================

Write-Host "`n=== RECENT WINDOWS AUTHENTICATION EVENTS (LAST $Minutes MIN) ===" -ForegroundColor Cyan

try {

    $events = @(

        Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624, 4625
            StartTime = (Get-Date).AddMinutes(-$Minutes)
        } -ErrorAction Stop
    )

    $rows = @(

        foreach ($eventRecord in $events) {

            try {

                # Read event properties directly.
                # This avoids malformed XML conversion errors.
                #
                # Common event field indexes:
                #
                # Event 4624:
                #   TargetUserName = 5
                #   LogonType      = 8
                #   IpAddress      = 18 (v0/v1), 19 (v2)
                #
                # Event 4625:
                #   TargetUserName = 5
                #   LogonType      = 10
                #   IpAddress      = 19
                #
                # Check event version before extracting fields.

                $properties = $eventRecord.Properties

                if ($null -eq $properties) {
                    continue
                }

                $usernameIndex = 5
                $logonTypeIndex = $null
                $sourceIPIndex = $null

                if ($eventRecord.Id -eq 4624) {

                    $logonTypeIndex = 8

                    if ($eventRecord.Version -ge 2) {
                        $sourceIPIndex = 19
                    } else {
                        $sourceIPIndex = 18
                    }

                } elseif ($eventRecord.Id -eq 4625) {

                    $logonTypeIndex = 10
                    $sourceIPIndex = 19

                } else {

                    continue
                }

                $maxIndex = @(
                    $usernameIndex,
                    $logonTypeIndex,
                    $sourceIPIndex
                ) | Measure-Object -Maximum |
                    Select-Object -ExpandProperty Maximum

                if ($properties.Count -le $maxIndex) {
                    continue
                }

                $username = [string]$properties[$usernameIndex].Value
                $logonType = [string]$properties[$logonTypeIndex].Value
                $sourceIP = [string]$properties[$sourceIPIndex].Value

                # Skip events without usable remote IP addresses.
                if (
                    [string]::IsNullOrWhiteSpace($sourceIP) -or
                    $sourceIP -eq '-'
                ) {
                    continue
                }

                [pscustomobject]@{
                    Time      = $eventRecord.TimeCreated
                    Result    = if ($eventRecord.Id -eq 4624) {
                        'SUCCESS'
                    } else {
                        'FAILED'
                    }
                    User      = $username
                    SourceIP  = $sourceIP
                    LogonType = $logonType
                }

            } catch {

                Write-Warning "Skipping event record $($eventRecord.RecordId): $($_.Exception.Message)"
            }
        }
    )

    if ($rows.Count) {

        $rows |
            Sort-Object Time -Descending |
            Format-Table -AutoSize |
            Out-Host

    } else {

        Write-Host 'No authentication events with source IPs in this time window.'
    }

} catch {

    Write-Warning "Could not read Security events: $($_.Exception.Message)"
}


# ============================================================
# OPERATOR NOTES
# ============================================================

Write-Host "`n=== CDT OPERATOR NOTES ===" -ForegroundColor Cyan

Write-Host 'WTS OriginIP identifies interactive client addresses when available.'

Write-Host 'Security events and TCP connections are separate evidence; do not assume they map to a session ID.'

Write-Host 'WinRM, SSH and independent backdoors may not appear as interactive quser sessions.'

Write-Host 'An unknown IP is not automatically malicious. Verify against approved scoring, management and Grey Team addresses.'

Write-Host "`nSnapshot complete." -ForegroundColor Green
