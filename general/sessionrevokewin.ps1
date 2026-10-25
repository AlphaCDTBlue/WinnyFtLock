[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# List local Windows interactive sessions and allow selected sessions to be
# signed out. This does not affect sessions on other computers/servers or SSH.
$currentSessionId = (Get-Process -Id $PID -ErrorAction Stop).SessionId

$quser = Join-Path $env:SystemRoot 'System32\quser.exe'
$logoff = Join-Path $env:SystemRoot 'System32\logoff.exe'

Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Runtime.InteropServices;

public static class SessionClientAddress
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

$output = & $quser 2>&1
if ($LASTEXITCODE -ne 0) {
	throw "Could not enumerate Windows sessions: $($output -join ' ')"
}

$sessions = foreach ($line in ($output | Select-Object -Skip 1)) {
	# quser rows may include a leading current-session marker and may omit the
	# session name for disconnected sessions.
	if ($line -match '^\s*>?\s*(\S+)\s+(?:(\S+)\s+)?(\d+)\s+(\S+)') {
		[pscustomobject]@{
			User        = $Matches[1]
			SessionName = $Matches[2]
			Id          = [int]$Matches[3]
			State       = $Matches[4]
			OriginIP    = [SessionClientAddress]::Get([int]$Matches[3])
		}
	}
}

if (@($sessions).Count -eq 0) {
	throw 'No interactive Windows sessions were found.'
}

Write-Host 'Logged-in Windows sessions:'
$sessions | Format-Table User, SessionName, Id, State, OriginIP -AutoSize | Out-Host
#$choice = Read-Host 'Enter session IDs separated by commas, or ALL to select every session'
#if ($choice -ceq 'ALL') {
$selected = @($sessions)
#}
#else {
#	$ids = @($choice -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
#	if ($ids.Count -eq 0 -or @($ids | Where-Object { $_ -notmatch '^\d+$' }).Count -gt 0) {
#		throw 'Enter one or more listed session IDs, or ALL.'
#	}
#	$requestedIds = @($ids | ForEach-Object { [int]$_ } | Sort-Object -Unique)
#	$selected = @($sessions | Where-Object { $_.Id -in $requestedIds })
#	if ($selected.Count -ne $requestedIds.Count) {
#		throw 'One or more IDs were not listed; no sessions were signed out.'
#	}
#}

Write-Host "Sessions selected for sign-out: $(($selected | ForEach-Object { "$($_.User) (ID $($_.Id))" }) -join ', ')"

# Close active inbound OpenSSH sessions without stopping the sshd service.
$sshdService = Get-CimInstance Win32_Service -Filter "Name='sshd'"
if ($null -eq $sshdService -or $sshdService.State -ne 'Running') {
	Write-Host 'No running OpenSSH server service was found; no SSH sessions to close.'
}
else {
	$sshdProcessId = [int]$sshdService.ProcessId
	$sshListenerPorts = @(
		Get-NetTCPConnection -State Listen |
			Where-Object { $_.OwningProcess -eq $sshdProcessId } |
			Select-Object -ExpandProperty LocalPort -Unique
	)
	$sshSessionProcessIds = @(
		Get-NetTCPConnection -State Established |
			Where-Object { $_.LocalPort -in $sshListenerPorts -and $_.OwningProcess -ne $sshdProcessId } |
			Select-Object -ExpandProperty OwningProcess -Unique
	)
	$sshdProcesses = @(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'")
	$sshSessionProcessIds = @(
		$sshSessionProcessIds | Where-Object {
			$sessionProcessId = $_
			@($sshdProcesses | Where-Object { $_.ProcessId -eq $sessionProcessId }).Count -gt 0
		}
	)

	if ($sshSessionProcessIds.Count -eq 0) {
		Write-Host 'No active inbound SSH sessions were found.'
	}
	else {
		Write-Host "Closing inbound SSH session process(es): $($sshSessionProcessIds -join ', ')"
		$failedSshProcessIds = @()
		foreach ($sshSessionProcessId in $sshSessionProcessIds) {
			try {
				Stop-Process -Id $sshSessionProcessId -Force -ErrorAction Stop
			}
			catch {
				$failedSshProcessIds += $sshSessionProcessId
				Write-Warning "Could not close SSH session process ${sshSessionProcessId}: $($_.Exception.Message)"
			}
		}

		if ($failedSshProcessIds.Count -gt 0) {
			throw "Failed to close SSH session process(es): $($failedSshProcessIds -join ', '). Run elevated or contact your administrator."
		}
	}
}

# Sign out the current session last so this script can process the remaining IDs.
$selectedIds = @($selected | ForEach-Object { $_.Id })
$orderedSessions = @($selectedIds | Where-Object { $_ -ne $currentSessionId })
if ($currentSessionId -in $selectedIds) {
	$orderedSessions += $currentSessionId
}
$failed = @()
foreach ($id in $orderedSessions) {
	& $logoff $id
	if ($LASTEXITCODE -ne 0) {
		$failed += $id
		Write-Warning "Could not sign out session $id (exit code $LASTEXITCODE)."
	}
}

if ($failed.Count -gt 0) {
	throw "Failed to sign out session(s): $($failed -join ', '). Run elevated or contact your administrator."
}
