# CDT Blue Team Windows Tools: watchdogsgit and NewSession

Two independent PowerShell tools for Windows Server 2019 hosts. They use separate folders and scheduled tasks and do not interfere with each other.

| Tool | Script | Purpose | Intended host |
|---|---|---|---|
| watchdogsgit | `watchdogsgit.ps1` | Keeps IIS up and files/config at an approved baseline | bubblechat (10.111.2.4) |
| NewSession | `new_session.ps1` | Requires a second verification password after Windows login (RDP, SSH, WinRM) | windows-host-2 (10.110.20.102) |

---

## 1. watchdogsgit.ps1 (IIS watchdog)

### What it does
- Takes a baseline of the IIS site directories and `applicationHost.config`, `administration.config` and `redirection.config`, stored in a private Git repo, plus NTFS permissions.
- A SYSTEM scheduled task (`watchdogsgit`, starts at boot, relaunched every minute if it dies) checks every ~10 seconds:
  - Modified or deleted files are restored from the baseline; the changed copy goes to quarantine.
  - New files outside the exclusions are quarantined (or only reported with `-NewFiles Report`).
  - File and directory permissions are restored.
  - WAS, W3SVC, app pools and the website are started if stopped. W3SVC start/restart goes through BlueOps.
  - If a `.config` file was repaired, W3SVC is restarted.
  - After 3 failed health checks, running app pools are recycled (60-second cooldown).
- Writes the latest result to a status file, overwritten each cycle (no growing log).

### Usage
```powershell
# Check readiness (changes nothing)
.\watchdogsgit.ps1 -Action Preflight

# Install: baseline + first recovery pass + background task
.\watchdogsgit.ps1 -Action Setup
# optional: -SiteName "name" -HealthUrl "http://..." -ExpectedText "text" `
#           -Exclude App_Data,uploads,logs,temp,cache -NewFiles Quarantine|Report

# Check on it
.\watchdogsgit.ps1 -Action Status
```

| Action | Meaning |
|---|---|
| `Preflight` | Checks Git, IIS components, site selection and the health URL |
| `Setup` | Full install (baseline, test pass, background task) |
| `Status` | Task state, heartbeat age, last pass details |
| `Pause` / `Resume` | Stop / restart automatic recovery |
| `Rebaseline` | Replace the baseline (requires `Pause` first) |
| `Once` | Run a single pass |
| `Uninstall` | Pause and remove the task; baselines and quarantine are kept |

### Making an approved change (important)
Anything changed after baselining is reverted within ~10 seconds, including IIS Manager edits and inject-driven site changes.
```powershell
.\watchdogsgit.ps1 -Action Pause
# ...make and verify the change...
.\watchdogsgit.ps1 -Action Rebaseline
.\watchdogsgit.ps1 -Action Resume
```
Harden first, then baseline. A baseline taken from a tampered box restores the tampering.

### Tips
- Put anything the site writes at runtime (databases, session files, logs) in `-Exclude`, or it will be reverted, quarantined or cause scan errors.
- Junctions/symlinks inside the site make baselining fail by design.
- Files: `C:\ProgramData\watchdogs\` (`settings.json`, `status.json`, `paused`, `baselines\`, `quarantine\`).

---

## 2. new_session.ps1 (NewSession, post-login verification)

### What it does
Requires a separate verification password after a successful Windows login. No Windows passwords are changed.
- **RDP:** a SYSTEM watcher (`NewSession-Guard`, starts at boot) sees new RDP logons, waits `GraceSeconds` (default 15), then shows a prompt in the user's session. Wrong code, closed window, or no answer within `ResponseSeconds` (default 30) logs the session off.
- **SSH:** `sshd_config` gets a `ForceCommand` for all users except the grey accounts. Connect with `ssh -t` so the verification prompt works.
- **WinRM/PSRP:** the `Microsoft.PowerShell` endpoints get a startup script that checks a code sent by `-Action Connect`.
- **Grey accounts** (default `kingneptune`, `paintythepirate`) are exempt everywhere. All scoring accounts for RDP/SSH/WinRM must be listed.
- Sessions that exist at install time are trusted. Console sessions are never touched.

### Usage
```powershell
# Install (prompts for the verification password, 12 to 256 characters)
.\new_session.ps1 -Action Install -GreyAccounts kingneptune,paintythepirate
# optional: -Services Rdp,Ssh,WinRm  -GraceSeconds 15  -ResponseSeconds 30

# Status / removal
.\new_session.ps1 -Action Status
.\new_session.ps1 -Action Uninstall     # restores sshd_config and endpoint settings

# Connecting to a protected host over WinRM (from another machine)
.\new_session.ps1 -Action Connect -ComputerName <host> [-UseSSL]

# Connecting over SSH
ssh -t user@host
```
`Watch`, `Prompt`, `SshGate` and `WinRmGate` are internal actions; do not run them by hand.

### Team notes
- You get **one attempt per logon**. A typo or closed prompt logs you off; sign in again to retry.
- If the watcher stops, non-grey SSH/WinRM logins fail (the verifier lives in the watcher). Recover from the console/RDP: check `-Action Status`, or `-Action Uninstall`.
- Files: `C:\ProgramData\NewSession\` (`public.json`, `private.json`, `rollback.json`, `audit.log`, `status.json`). `rollback.json` is what Uninstall uses; do not delete it.

### Limits
This is a speed bump, not a hard boundary:
- An attacker with administrator rights can kill the task during the grace window.
- Only the `Microsoft.PowerShell` remoting endpoints are gated; `winrs`, WMI, SMB and PsExec are not.
- Install fails safe: if the watcher is not healthy, service settings are not changed.
