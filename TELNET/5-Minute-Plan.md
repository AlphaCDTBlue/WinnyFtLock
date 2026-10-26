
# CDT — Telnet Five-Minute Defense Plan

Machine: kelpdelivery
IP: 10.111.2.5
OS: Windows Server 2019
Service: Telnet
Domain: krusty.krab

## Goal

Secure the Windows machine hosting Telnet before red team
begins attacking it, while keeping Telnet available for scoring.

The first actions are to back up Telnet, deploy BlueOps,
coordinate with AD/DNS for password rotation, revoke old
sessions, and reconnect.

Afterward, investigate unauthorized sessions, suspicious
processes, and persistence. If red team damages Telnet,
restore its configuration from the initial backup.

## Before Starting

Copy these scripts onto kelpdelivery:

- Backup-Telnet.ps1
- Restore-Telnet-Verified.ps1
- Show-HostSessions.ps1
- Evict-HostIP.ps1
- Deploy-BlueOps.ps1
- sessionrevokewin.ps1

Open Windows PowerShell as Administrator.

Navigate to the directory containing the scripts:

    cd C:\CDT-Telnet

If Windows blocks script execution, check the current
execution policy and whether the files are blocked:

    Get-ExecutionPolicy -List
    Get-Item .\Backup-Telnet.ps1 -Stream Zone.Identifier -ErrorAction SilentlyContinue

Use only execution-policy changes authorized by your team.

Keep a copy of the scripts and backups on an approved
management machine. GitHub can recover your scripts,
but it will not automatically recover your original
Telnet configuration.

---

## Step 1 — Back Up Telnet

Run immediately after accessing the machine:

    .\Backup-Telnet.ps1

The script attempts to:

- Detect Telnet/inetd-related Windows services
- Export service registry configuration
- Save service startup information
- Back up supported Telnet configuration files
- Export Windows Firewall policy
- Record port 23 listeners

Backups are saved under:

    .\TelnetBackups\<timestamp>\

Verify the backup folder exists and inspect manifest.json
for warnings.

If the script cannot identify the actual Telnet service,
do not assume the backup is complete.

Do not modify Telnet configuration until you have a
verified backup.

## Step 2 — Deploy BlueOps

Run:

    .\Deploy-BlueOps.ps1

This is the team-provided defensive deployment script.

Follow its output and check for errors.

If PowerShell logging is included, confirm the log
directory exists and transcripts are being generated.

Do not restart the server unless necessary.

## Step 3 — Wait for AD/DNS Password Rotation

The AD/DNS team manages domain password rotation
from treedome (10.111.2.1).

Wait for confirmation that passwords have been changed.

Before proceeding:

- Make sure you have the updated credentials
- Confirm you can reconnect through your jumpbox
- Coordinate with teammates using the same machine
- Do not revoke sessions prematurely

## Step 4 — Revoke Existing Sessions

After AD/DNS confirms password rotation:

    .\sessionrevokewin.ps1

The team-provided script:

- Enumerates interactive Windows sessions
- Displays usernames, session IDs, and source IPs
- Attempts to close inbound OpenSSH sessions
- Logs off all enumerated interactive sessions
- Logs off your current session last

IMPORTANT:

The current script does not ask for confirmation.

It does not exclude Grey Team sessions.

Confirm its use is approved and coordinate with
the team before running it.

Expect your own Windows session to disconnect.

## Step 5 — Reconnect

Log back into kelpdelivery using updated credentials.

Verify that you still have administrative access.

Check Telnet's listener:

    Get-NetTCPConnection -LocalPort 23 -State Listen

Find the actual Telnet service:

    Get-CimInstance Win32_Service |
      Where-Object {
        $_.Name -match 'telnet|tlnt|inetd' -or
        $_.DisplayName -match 'telnet|tlnt|inetd'
      } |
      Select-Object Name, State, StartMode, PathName

Confirm that Telnet is accepting connections using
an approved test from another machine.

A listening TCP port does not prove authentication works.

## Step 6 — Check Active Sessions

Run:

    .\Show-HostSessions.ps1 -Minutes 60

The script displays:

- Interactive Windows sessions
- Usernames and session IDs
- Originating IPs when Windows provides them
- Established TCP connections
- Recent successful authentication events (4624)
- Recent failed authentication events (4625)

Look for:

- Unknown users
- Unexpected remote IPs
- Suspicious successful logins
- Repeated failed logins
- Unexpected network connections

Do not assume an unfamiliar IP is malicious.

Check against your approved jumpbox, scoring,
Grey Team, and management addresses.

WinRM, SSH, and independent backdoors may not appear
as interactive Windows sessions.

## Step 7 — Inspect Suspicious Processes

Open Task Manager:

    Ctrl + Shift + Esc

Select More Details if needed.

Open the Details tab.

For suspicious processes:

1. Identify the process name and PID.
2. Right-click and select Open File Location.
3. Inspect the executable path and properties.
4. Check whether the process belongs to a Windows
   service or legitimate CDT application.
5. If confirmed malicious, end the task.
6. Investigate the mechanism that launches it.

Also check scheduled tasks:

    taskschd.msc

And Windows services:

    services.msc

Look for suspicious tasks or services that could
restart a malicious process.

Do not delete unfamiliar executables without
verifying their purpose.

Do not terminate Telnet, scoring components,
Grey Team tools, or critical Windows processes.

## Step 8 — Evict an Attacker IP

After identifying a confirmed unauthorized IP:

    .\Evict-HostIP.ps1 -IP "10.111.3.50"

Replace the example IP with the actual address.

The script displays matching TCP connections and
Windows sessions.

It then requires you to confirm the block.

The firewall rules block that IP across all ports,
both inbound and outbound.

If you have independently verified a Windows session ID
belongs to the attacker, you can also request logoff:

    .\Evict-HostIP.ps1 -IP "10.111.3.50" -LogoffSessionId 4

The script requires separate logoff confirmation.

IMPORTANT:

- The IP is blocked before session logoff confirmation.
- IP addresses do not always map directly to session IDs.
- Blocking an IP may not immediately close existing TCP sessions.
- Logoff does not necessarily terminate backdoor processes.
- Never block scoring or approved management infrastructure.

To review CDT block rules:

    Get-NetFirewallRule -Name "CDT-Block-*"

To remove a block created for the example IP:

    Get-NetFirewallRule -Name "CDT-Block-*-10.111.3.50" |
      Remove-NetFirewallRule

## Step 9 — Restore Telnet if Something Breaks

First check whether Telnet is running and listening.

If the service is simply stopped, investigate why.
A configuration restore may not be necessary.

Preview configuration differences:

    .\Restore-Telnet-Verified.ps1

The script compares supported backed-up registry keys
and files with their current versions.

If differences are found and restoration is appropriate:

    .\Restore-Telnet-Verified.ps1 -Apply

Type RESTORE when prompted.

The script attempts to:

- Identify changed or missing backed-up settings
- Save current settings for rollback
- Restore supported changed registry keys/files
- Check whether port 23 is listening

It does not restore the entire installation or
automatically restart Telnet.

Only restart the identified Telnet service if needed
to apply restored settings.

Verify Telnet functionality afterward.

## CDT Rules to Remember

- Do not remove Grey Team service accounts.
- Do not block scoring infrastructure.
- Do not use blanket or subnet-wide firewall blocks.
- Do not change IP addressing or network settings.
- Do not enable Windows Defender or similar antivirus.
- Back up service configuration before modifying it.
- Test defensive tools before competition use.
- Stop work immediately if Grey Team pauses competition.

## Quick Checklist

Initial actions:

- [ ] Back up Telnet and verify backup files
- [ ] Run Deploy-BlueOps.ps1
- [ ] Wait for AD/DNS password rotation confirmation
- [ ] Run sessionrevokewin.ps1
- [ ] Reconnect using updated credentials
- [ ] Verify Telnet works

After reconnecting:

- [ ] Review active sessions and authentication events
- [ ] Inspect suspicious processes and persistence
- [ ] Block confirmed attacker IPs when necessary
- [ ] Keep Telnet restore script ready

Remember: keeping the scored Telnet service operational
is more important than applying unnecessary changes.
