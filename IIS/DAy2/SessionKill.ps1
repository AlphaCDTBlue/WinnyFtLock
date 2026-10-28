#Requires -RunAsAdministrator
<#
.SYNOPSIS
  SessionKill.ps1 - signs out every other session and keeps the one you are in.

.DESCRIPTION
  Run in an elevated PowerShell, no arguments:
      .\SessionKill.ps1

  1. Lists every session (user, id, state, origin IP) and marks yours as "YOU".
  2. Closes inbound SSH sessions (not the sshd service), except the one you are
     running in if you came in by SSH.
  3. Logs off every other session by id. Your own session is never touched.
  4. Shows what is left and writes the same record to C:\BlueLogs\sessionkill.log.

  It does not ask first and does not skip Grey Team: anyone else who is signed in
  is signed out. It does not stop anyone from signing in again.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

$mySessionId = (Get-Process -Id $PID).SessionId
$logDir  = 'C:\BlueLogs'
$logFile = Join-Path $logDir 'sessionkill.log'

function Log([string]$text) {
    try {
        if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        Add-Content -LiteralPath $logFile -Value ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $text)
    } catch {}
}

if (-not ('SkClientAddress' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Runtime.InteropServices;

public static class SkClientAddress
{
	[DllImport("Wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	private static extern bool WTSQuerySessionInformation(
		IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytesReturned);

	[DllImport("Wtsapi32.dll")]
	private static extern void WTSFreeMemory(IntPtr memory);

	public static string Get(int sessionId)
	{
		IntPtr buffer;
		int length;
		if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, 14, out buffer, out length))
			return "Unavailable";
		try
		{
			if (buffer == IntPtr.Zero || length < 22)
				return "Unknown";
			byte[] address = new byte[20];
			Marshal.Copy(IntPtr.Add(buffer, 2), address, 0, address.Length);
			ushort family = unchecked((ushort)Marshal.ReadInt16(buffer));
			if (family == 2)
			{
				byte[] ipv4 = new byte[] { address[0], address[1], address[2], address[3] };
				if (ipv4[0] == 0 && ipv4[1] == 0 && ipv4[2] == 0 && ipv4[3] == 0)
					return "Local/unknown";
				return new IPAddress(ipv4).ToString();
			}
			if (family == 23)
				return new IPAddress(new byte[] { address[0], address[1], address[2], address[3],
					address[4], address[5], address[6], address[7], address[8], address[9],
					address[10], address[11], address[12], address[13], address[14], address[15] }).ToString();
			return "Local/unknown";
		}
		finally
		{
			WTSFreeMemory(buffer);
		}
	}
}
'@
}

# ---- read the session list (an error is never reported as "no sessions") ----
function Get-Sessions {
    $out = & quser.exe 2>&1
    $text = ($out | ForEach-Object { [string]$_ }) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        if ($text -match 'No User exists') { return @() }
        throw "Could not list sessions: $text"
    }
    $list = @()
    foreach ($line in ($out | Select-Object -Skip 1)) {
        # a disconnected session has no session name, so that column is optional
        if ([string]$line -match '^\s*>?\s*(\S+)\s+(?:(\S+)\s+)?(\d+)\s+(\S+)') {
            $list += [pscustomobject]@{
                User     = $Matches[1]
                Name     = $Matches[2]
                Id       = [int]$Matches[3]
                State    = $Matches[4]
                OriginIP = [SkClientAddress]::Get([int]$Matches[3])
            }
        }
    }
    return $list
}

try { $sessions = @(Get-Sessions) }
catch { Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }

Write-Host ''
Write-Host "Your session: ID $mySessionId (kept)" -ForegroundColor Cyan
Write-Host ''
if ($sessions.Count) {
    $sessions | ForEach-Object {
        [pscustomobject]@{
            Keep     = $(if ($_.Id -eq $mySessionId) { 'YOU' } else { '' })
            User     = $_.User
            Id       = $_.Id
            State    = $_.State
            OriginIP = $_.OriginIP
        }
    } | Format-Table -AutoSize | Out-Host
}

$others = @($sessions | Where-Object { $_.Id -ne $mySessionId })
$failed = 0
Log "RUN by session $mySessionId; $($others.Count) other session(s) found"

# ---- close inbound SSH sessions (the sshd service keeps running) ----
try {
    # never close the SSH connection this script is running inside
    $mine = @{}
    $cur = $PID
    while ($cur -and -not $mine.ContainsKey($cur)) {
        $mine[$cur] = $true
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$cur" -ErrorAction SilentlyContinue
        if (-not $p) { break }
        $cur = [int]$p.ParentProcessId
    }

    $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
    if ($svc -and $svc.State -eq 'Running') {
        $svcPid = [int]$svc.ProcessId
        $ports = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.OwningProcess -eq $svcPid } | Select-Object -ExpandProperty LocalPort -Unique)
        $sshProcs = @(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" | ForEach-Object { [int]$_.ProcessId })
        $targets = @(
            Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                Where-Object { ($_.LocalPort -in $ports) -and ($_.OwningProcess -ne $svcPid) -and ($_.OwningProcess -in $sshProcs) -and (-not $mine.ContainsKey([int]$_.OwningProcess)) } |
                Select-Object -ExpandProperty OwningProcess -Unique
        )
        if (-not $targets.Count) {
            Write-Host 'No other SSH sessions.'
        } else {
            foreach ($t in $targets) {
                try {
                    Stop-Process -Id $t -Force -ErrorAction Stop
                    Write-Host "Closed SSH session process $t" -ForegroundColor Green
                    Log "CLOSED ssh process $t"
                } catch {
                    Write-Host "FAILED to close SSH session process ${t}: $($_.Exception.Message)" -ForegroundColor Red
                    Log "FAILED ssh process $t"
                    $failed++
                }
            }
        }
    }
} catch {
    Write-Host "Note: could not check SSH sessions ($($_.Exception.Message))." -ForegroundColor Yellow
}

# ---- log off everyone else ----
if (-not $others.Count) {
    Write-Host 'No other sessions - nothing to log off.' -ForegroundColor Green
} else {
    foreach ($s in $others) {
        Write-Host "Logging off session $($s.Id)  $($s.User)  from $($s.OriginIP)" -ForegroundColor Yellow
        $out = & logoff.exe $s.Id 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host '  done' -ForegroundColor Green
            Log "LOGGED OFF session $($s.Id) user=$($s.User) ip=$($s.OriginIP) state=$($s.State)"
        } else {
            Write-Host "  FAILED: $(($out | ForEach-Object { [string]$_ }) -join ' ')" -ForegroundColor Red
            Log "FAILED session $($s.Id) user=$($s.User) ip=$($s.OriginIP)"
            $failed++
        }
    }
}

# ---- what is left ----
Start-Sleep -Seconds 2
Write-Host ''
Write-Host 'Remaining sessions:' -ForegroundColor Cyan
try {
    $left = @(Get-Sessions)
    if ($left.Count) {
        $left | ForEach-Object { [pscustomobject]@{ User = $_.User; Id = $_.Id; State = $_.State; OriginIP = $_.OriginIP } } | Format-Table -AutoSize | Out-Host
        $stillOthers = @($left | Where-Object { $_.Id -ne $mySessionId })
        if ($stillOthers.Count) { Write-Host "Warning: $($stillOthers.Count) other session(s) are still listed. Run it again." -ForegroundColor Yellow }
    } else {
        Write-Host '  (none listed)'
    }
} catch {
    Write-Host "Could not list the remaining sessions: $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}
if ($failed) { exit 1 }
