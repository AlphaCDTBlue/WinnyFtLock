# CDT Blue — IIS Host Toolkit

Standalone PowerShell tools for the IIS scored host (bubblechat, 10.111.2.4) and the RDP-gated host (windows-host-2, 10.110.20.102) in the CDT competition. Each script runs independently — install one, several, or all of them in any order. None of them reset Windows account passwords except `UserPassword.ps1`, which only touches the packet accounts listed in it.

Grey Team accounts (`kingneptune`, `paintythepirate`, `greyteamadmin`) are exempted by name in every script below; keep that list identical across all of them.

| File | What it does | Runs on |
|---|---|---|
| `Install.ps1` | Installs Git, Sysinternals Suite, Wireshark + Npcap | Any host |
| `UserChecker.ps1` | Loops every 10s; removes/disables any local user not on the approved list | Any host with local accounts |
| `UserPassword.ps1` | One-shot password reset for the packet's local users | Any host with local accounts |
| `SessionKill.ps1` | Logs off every RDP/console session except the one running it | Any host |
| `session.ps1` | Post-login verification gate (RDP/SSH/WinRM), Grey-exempt by SID | windows-host-2 |
| `gitat.ps1` | IIS file/config/service watchdog with Git-backed baselines | bubblechat (IIS host) |
| `Deploy-BlueOps.ps1` | One-time install of the locked-down service controller for AD/DNS/Openfire/Telnet/IIS/CA | Any host running one of those services |
| `Svcwithme.ps1` (Svc-Control) | Requests a start/stop/restart of a locked service through the controller | Any host after `Deploy-BlueOps.ps1` |

Run order for the 5-minute window suggested at the bottom.

---

## 1. `Install.ps1` — toolkit installer

Run as Administrator, no arguments. Installs Git for Windows, the Sysinternals Suite, and Wireshark + Npcap, in that order, so the Git step is ready before anything else needs it (e.g. `gitat.ps1`'s baselining).

- Downloads from GitHub (Git), sysinternals.com, wireshark.org, and npcap.com, with Authenticode signer checks on every downloaded installer before it runs.
- Wireshark: pulls the 4.6.x branch specifically — the "latest" 4.7+ builds dropped Server 2019 support — falling back to 4.4.x, then to a hardcoded version if the download page can't be read.
- Npcap has no silent-install switch for the free edition, so the script launches its GUI installer and **does not wait** for you to click through it; the summary at the end shows Npcap as `PENDING` rather than failing the whole run.
- Offline fallback: drop `SysinternalsSuite.zip`, `Wireshark-4.*-x64.exe`, or `npcap-*.exe` next to the script and it'll use those if the network download fails.
- Files land in `C:\Tools\` (`Sysinternals\`, `_downloads\`, `toolkit.log`); both dirs are added to the machine `PATH` (open a new shell to see it).
- Exit code is 0 only if Git, Sysinternals and Wireshark all succeeded (Npcap pending/failed doesn't fail the run).

Do **not** also deploy the older `Toolkit.ps1` draft — it's superseded by this file (no Git step, and it blocks on the Npcap installer instead of handing it off).

## 2. `UserChecker.ps1` — continuous local-user enforcement

Run as Administrator, no arguments, and **keep the window open** (Ctrl+C to stop; disconnecting RDP is fine, logging off is not). Refuses to run on a domain controller.

- Edit the two lists at the top (`$PacketUsers`, `$GreyTeamUsers`) to match the current packet before running.
- Every 10 seconds: any local user not on either list is logged off, has its processes killed, and is deleted. The three well-known built-in RIDs (Guest/501, etc.) are disabled instead of deleted. The built-in Administrator (RID 500) and the account you're running the script as are only warned about, never touched.
- Log: `C:\ProgramData\BlueOps\UserChecker.log`. A one-line heartbeat prints in place when nothing changed; a line is printed for every add/remove/warn event.

## 3. `UserPassword.ps1` — packet password reset

Run as Administrator. `-Ask` prompts for a password (with confirmation) instead of using the hardcoded default; use the same `$PacketUsers`/`$GreyTeamUsers` lists as `UserChecker.ps1`. Refuses to run on a domain controller. Grey Team accounts are explicitly skipped. Reports OK/MISS/FAIL per account and lists active sessions afterward so you can spot anyone still logged in under an old password.

## 4. `SessionKill.ps1` — drop every other session

Run as Administrator, no arguments. Parses `quser`, logs off every session except the one you're currently in, and prints the remaining session list. Useful immediately before running `session.ps1`'s installer or `gitat.ps1`'s setup, both of which refuse to install while other remote sessions are connected.

## 5. `session.ps1` — post-login verification guard

Independent **second-factor-style** gate after normal Windows login; does not reset Windows passwords and is not a replacement for Windows auth or a boundary against a full administrator.

```powershell
.\session.ps1                 # install, or repair + refresh policy on a later run
.\session.ps1 -Ask             # (re)set the separate verification password interactively
& "$env:ProgramData\Session\session-engine.ps1" -Action Status
.\session.ps1 -Remove          # restore original SSH/WinRM settings and remove the guard
```

- **RDP:** a SYSTEM task (`Session-Guard`) waits 15s after a new login, pops a verification box, gives 15s to answer. Wrong code / closed box / timeout logs off the *whole* RDP session (one attempt per logon).
- **SSH:** a 15s grace, then a 15s terminal prompt, before the real shell launches. Only works over an interactive client (`ssh -t`); SCP/SFTP/forwarding are incompatible — do file transfers before installing this.
- **WinRM:** disabled outright if possible; if it can't be disabled, only the standard `Microsoft.PowerShell`/`32` remoting endpoints get a fallback startup check (WinRS/custom endpoints are **not** covered).
- **Grey Team** (`kingneptune`, `paintythepirate`, `greyteamadmin`): resolved to real Windows SIDs at install time and stored in `public.json`; every gate checks the *authenticated token SID*, never a username, so this can't be spoofed by renaming an account. An unresolved Grey name is **not** exempted — rerun once the account exists.
- The hardcoded default password lives in the script's `$UserPassword` constant — anyone who can read the source can read it; only its PBKDF2 hash is installed (`private.json`, never world-readable). Use `-Ask` if that matters.
- State: `C:\ProgramData\Session\` (`public.json` readable, `private.json`/`rollback.json` restricted, `audit.log`, `status.json`).

## 6. `gitat.ps1` — IIS recovery watchdog

Standalone IIS file/service recovery. Run as Administrator, no arguments (rerunning preserves the existing baseline).

- First run: verifies the site is clean, then Git-baselines `inetpub` + local IIS physical roots + the three main IIS config files (`applicationHost.config`, `administration.config`, `redirection.config`).
- Every ~10 seconds: restores changed/missing protected files (quarantining the changed copy), quarantines unexpected new files, repairs NTFS ACLs, and recovers stopped IIS services/pools/sites. A `.config` repair triggers a W3SVC restart; W3SVC start/restart goes through the BlueOps worker (see `Deploy-BlueOps.ps1`/`Svcwithme.ps1`) because of a known legacy IIS ACL bug this script patches once before calling it.
- Two copies of the baseline: the primary in `C:\ProgramData\IISCache\`, and a hidden emergency copy under `C:\Users\Public\Pictures\.<GUID>\` — both still on this server, not an offline backup.
- Treats every editor the same, Grey Team included — no accounts/passwords/sessions are touched by this tool.
- Logs/temp/cache/history at each protected root are excluded by default. Database contents, remote shares, certificates and anything external are **not** backed up by this.
- **Make an approved change** by pausing first (check the script's `-Action` list — pause/rebaseline/resume), or it'll be reverted within ~10 seconds.

This file is identical to what's already in the repo — no change needed here.

## 7. `Deploy-BlueOps.ps1` — service lockdown (one-time per host)

Run once per host as admin. Creates `C:\BlueOps\Svc-Control-Worker.ps1` (runs as SYSTEM via a disguised scheduled task path, `\Microsoft\Windows\Bluetooth\BthServiceMonitor`, created on demand by `Svcwithme.ps1` and deleted after each use) and, for every service that exists on the host (AD/`NTDS`, DNS/`DNS`, Openfire/`openfire`, Telnet/`TlntSvr`, IIS/`W3SVC`, CA/`CertSvc`):
- Sets a restrictive SDDL so only SYSTEM can stop/start/modify it — Administrators and everyone else get read-only.
- Arms auto-restart (3 attempts, 5s apart) on service failure.
- Starts it if it isn't already running.

**Fix before committing:** line 11's `$services` map has `"Telnet" = "inetd"` (a Linux daemon name — doesn't exist on Windows), so the lockdown loop will always `[SKIP]` Telnet with a "not found on this host" message, even when `TlntSvr` is actually running. Change it to `"Telnet" = "TlntSvr"` to match the worker script's own map three lines below, or Telnet never gets the SDDL lock or the auto-restart.

## 8. `Svcwithme.ps1` (Svc-Control) — controlled service actions

Run after `Deploy-BlueOps.ps1` has deployed the worker on that host.

```powershell
.\Svcwithme.ps1 -Service IIS -Action Restart
# -Service: AD | DNS | Openfire | Telnet | IIS | CA
# -Action:  Stop | Start | Restart
```

Writes the request to `C:\BlueOps\request.json`, fires the one-shot SYSTEM task to pick it up (the worker temporarily loosens the SDDL, applies the action, re-locks it, logs to `C:\BlueOps\audit.log`, deletes the request file), then unregisters the task. Times out after 15 seconds if the request file is still there, telling you the task may have failed. This is the only supported way to change one of these services once `Deploy-BlueOps.ps1` has locked it down — direct `Stop-Service`/`sc.exe` calls will be denied.

---

## Suggested order for the 5-minute window

Matches the team minimums (credential rotation, service backup, kill unauthorized processes) plus your own items:

1. `SessionKill.ps1` — clear any session you don't recognize, first, so nothing fights you during setup.
2. `UserPassword.ps1` (or `-Ask`) and leave `UserChecker.ps1` running in its own window — covers "change local credentials."
3. `Deploy-BlueOps.ps1` once per host, then `gitat.ps1` (baseline + watchdog) on the IIS host — covers "back up the service" and ongoing recovery.
4. `session.ps1` on windows-host-2 — the RDP/SSH/WinRM verification gate.
5. `Install.ps1` for Sysinternals/Wireshark once you've confirmed internet access on the box — this can wait; it's not a team minimum.

Once the corrected `session.ps1`, `Install.ps1`, and the `Deploy-BlueOps.ps1` fix are the versions you push — and `Toolkit.ps1` is left out — this set is consistent and ready to write the Five Minute Plan against.
