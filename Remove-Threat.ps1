#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Blue-team threat removal tool: take ownership (ICACLS) -> stop related
    processes -> quarantine or delete a malicious EXE/DLL.
 
.DESCRIPTION
    Run locally on each host (Windows Server 2019, PowerShell 5.1).
    Flow per file:
      1. Report (hash, signature, owner, size) and safety checks
      2. Take ownership with icacls (original ACL is saved first)
      3. Find processes running/loading the file; optionally stop them
      4. Quarantine (recommended, reversible) or delete (permanent)
      5. Report persistence that still references the file (read-only)
 
    It never touches firewall, network, RDP, accounts, or reboots the host,
    so it will not interfere with the grey team scoring checks by itself.
    It does guard against stopping processes that host services or listen
    on ports (likely scored) without an explicit typed YES.
 
.PARAMETER Path
    One or more file paths (wildcards allowed). If omitted, Get-ThreatPath.bat
    (must sit next to this script) asks for the path interactively.
.PARAMETER Action
    Prompt (default) | Quarantine | Delete | Both
    Both = keep a hash-verified evidence copy in quarantine, then delete the original.
    Any value other than Prompt skips the confirmation menu.
.PARAMETER StopProcesses
    Prompt (default) | Yes | No
.PARAMETER DryRun
    Show what would happen; change nothing.
.PARAMETER Force
    Skip the protected-file refusal and the typed-YES gate. Use sparingly.
.PARAMETER Restore
    Restore a quarantined file by its ID.
.PARAMETER ListQuarantine
    List quarantined items.
 
.EXAMPLE
    .\Remove-Threat.ps1 -Path C:\Users\Public\update.exe -DryRun
.EXAMPLE
    .\Remove-Threat.ps1 -Path C:\Windows\Temp\*.dll -Action Quarantine
.EXAMPLE
    .\Remove-Threat.ps1 -ListQuarantine
    .\Remove-Threat.ps1 -Restore 3f2a9c...
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [ValidateSet('Prompt', 'Quarantine', 'Delete', 'Both')][string]$Action = 'Prompt',
    [ValidateSet('Prompt', 'Yes', 'No')][string]$StopProcesses = 'Prompt',
    [switch]$DryRun,
    [switch]$Force,
    [string]$Restore,
    [switch]$ListQuarantine
)
 
# ----------------------------------------------------------------------------
# CONFIG - edit for your environment
# ----------------------------------------------------------------------------
$QuarantineDir = Join-Path $env:ProgramData 'BT_Quarantine'
$LogFile       = Join-Path $QuarantineDir 'threat-removal.log'
$AdminSid      = '*S-1-5-32-544'   # BUILTIN\Administrators (locale-safe)
$SystemSid     = '*S-1-5-18'       # NT AUTHORITY\SYSTEM
 
# Processes this tool will never stop
$CriticalProcs = @('System', 'Idle', 'Registry', 'Memory Compression', 'smss', 'csrss',
                   'wininit', 'winlogon', 'services', 'lsass', 'lsaiso', 'dwm', 'fontdrvhost')
 
# Paths refused unless -Force (add your scored-service directories here)
$ProtectedPathPatterns = @(
    "$env:SystemRoot\NTDS*",
    "$env:SystemRoot\SYSVOL*",
    "$env:SystemRoot\WinSxS*",
    "$env:SystemRoot\servicing*",
    "$env:ProgramFiles\Cloudbase Solutions*",          # OpenStack cloudbase-init
    "${env:ProgramFiles(x86)}\Cloudbase Solutions*",
    "$QuarantineDir*"
    # 'C:\inetpub\wwwroot\*'   # example: scored web content
)
 
# ----------------------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------------------
function Initialize-Store {
    if (-not (Test-Path -LiteralPath $QuarantineDir)) {
        New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
        & icacls.exe $QuarantineDir /inheritance:r /grant:r "${SystemSid}:(OI)(CI)F" "${AdminSid}:(OI)(CI)F" 2>&1 | Out-Null
    }
}
 
function Write-Log {
    param([string]$Msg, [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO')
    $line = '{0:u} [{1}] [{2}\{3}] {4}' -f (Get-Date), $Level, $env:USERDOMAIN, $env:USERNAME, $Msg
    try { Add-Content -LiteralPath $LogFile -Value $line -ErrorAction Stop } catch {}
    $color = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'OK' { 'Green' } default { 'Gray' } }
    Write-Host "[$Level] $Msg" -ForegroundColor $color
}
 
function Read-Choice {
    param([string]$Prompt, [string[]]$Valid, [string]$Default)
    while ($true) {
        $r = Read-Host $Prompt
        if ([string]::IsNullOrWhiteSpace($r) -and $Default) { return $Default }
        if ($r -and ($Valid -contains $r.Trim().ToUpper())) { return $r.Trim().ToUpper() }
        Write-Host "  Enter one of: $($Valid -join ', ')" -ForegroundColor Yellow
    }
}
 
function Invoke-Icacls {
    param([string[]]$IcaclsArgs)
    $out = & icacls.exe @IcaclsArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls $($IcaclsArgs -join ' ') failed: $($out -join ' ')" }
}
 
function Get-FileReport {
    param([string]$Full)
    $r = [ordered]@{ Path = $Full; Size = $null; SHA256 = 'unavailable'; Signature = 'unknown'; Signer = ''; Owner = 'unknown' }
    try { $r.Size = (Get-Item -LiteralPath $Full -Force).Length } catch {}
    try { $r.SHA256 = (Get-FileHash -LiteralPath $Full -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Full
        $r.Signature = [string]$sig.Status
        if ($sig.SignerCertificate) { $r.Signer = $sig.SignerCertificate.Subject }
    } catch {}
    try { $r.Owner = (Get-Acl -LiteralPath $Full).Owner } catch {}
    [pscustomobject]$r
}
 
function Test-Protected {
    param([string]$Full, $Report)
    foreach ($pat in $ProtectedPathPatterns) {
        if ($Full -like $pat) { return "matches protected path pattern '$pat'" }
    }
    if ($Full -like "$env:SystemRoot\*" -and $Report.Signature -eq 'Valid' -and $Report.Signer -match 'O=Microsoft Corporation') {
        return 'validly signed Microsoft file under the Windows directory'
    }
    return $null
}
 
function Get-RelatedProcesses {
    param([string]$Full)
    $found = @{}
    try {
        Get-CimInstance Win32_Process -ErrorAction Stop |
            Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -ieq $Full) } |
            ForEach-Object { $found[[int]$_.ProcessId] = 'running image' }
    } catch {}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        if ($p.Id -in 0, 4, $PID) { continue }
        try {
            foreach ($m in $p.Modules) {
                if ($m.FileName -ieq $Full) {
                    if (-not $found.ContainsKey($p.Id)) { $found[$p.Id] = 'module loaded' }
                    break
                }
            }
        } catch {}   # access denied / 32-64 bit mismatch: skip
    }
 
    $svcAll = @()
    try { $svcAll = @(Get-CimInstance Win32_Service -ErrorAction Stop) } catch {}
    $listen = @()
    try { $listen = @(Get-NetTCPConnection -State Listen -ErrorAction Stop) } catch {}
 
    foreach ($id in $found.Keys) {
        $proc = Get-Process -Id $id -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        $svcs  = @($svcAll | Where-Object { $_.ProcessId -eq $id })
        $ports = @($listen | Where-Object { $_.OwningProcess -eq $id } | Select-Object -ExpandProperty LocalPort -Unique)
        [pscustomobject]@{
            Id       = $id
            Name     = $proc.ProcessName
            Why      = $found[$id]
            Critical = ($CriticalProcs -contains $proc.ProcessName)
            Services = $svcs
            Ports    = $ports
        }
    }
}
 
function Get-PersistenceRefs {
    param([string]$Full)
    $hits = New-Object System.Collections.Generic.List[string]
    $has = { param($s) $s -and ([Environment]::ExpandEnvironmentVariables([string]$s)).IndexOf($Full, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
 
    try {
        Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { & $has $_.PathName } |
            ForEach-Object { $hits.Add("Service: $($_.Name)  ($($_.PathName))") }
    } catch {}
    try {
        foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) {
            foreach ($a in $t.Actions) {
                $s = "$($a.Execute) $($a.Arguments)"
                if (& $has $s) { $hits.Add("Scheduled task: $($t.TaskPath)$($t.TaskName)  ($s)") }
            }
        }
    } catch {}
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($k in $runKeys) {
        try {
            $props = Get-ItemProperty -Path $k -ErrorAction Stop
            foreach ($n in ($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
                if (& $has $n.Value) { $hits.Add("Run key: $k\$($n.Name)  ($($n.Value))") }
            }
        } catch {}
    }
    $hits
}
 
function Stop-RelatedProcesses {
    param($Procs, [string]$Full, [string]$Mode)
 
    if (-not $Procs -or @($Procs).Count -eq 0) { return }
    if ($Mode -eq 'Prompt') {
        $c = Read-Choice 'Stop these processes? [Y]es / [N]o (default N)' @('Y', 'N') 'N'
        $Mode = if ($c -eq 'Y') { 'Yes' } else { 'No' }
    }
    if ($Mode -ne 'Yes') { Write-Log 'Process stop skipped by operator.'; return }
 
    foreach ($p in $Procs) {
        if ($p.Critical -or $p.Id -eq $PID) {
            Write-Log "Refusing to stop critical process $($p.Name) ($($p.Id)). Handle manually." 'WARN'
            continue
        }
        $risky = (@($p.Services).Count -gt 0) -or (@($p.Ports).Count -gt 0)
        if ($risky -and -not $Force) {
            Write-Host ""
            Write-Host "  $($p.Name) ($($p.Id)) may be tied to a scored service:" -ForegroundColor Yellow
            if (@($p.Services).Count) { Write-Host "    Services : $((@($p.Services) | ForEach-Object Name) -join ', ')" -ForegroundColor Yellow }
            if (@($p.Ports).Count)    { Write-Host "    Listening: $(@($p.Ports) -join ', ')" -ForegroundColor Yellow }
            $t = Read-Host "  Type YES (capitals) to stop it, anything else to skip"
            if ($t -cne 'YES') { Write-Log "Skipped stopping $($p.Name) ($($p.Id))." 'WARN'; continue }
        }
 
        try {
            if (@($p.Services).Count -gt 0) {
                # Stop through the Service Control Manager instead of killing a shared host
                foreach ($s in $p.Services) {
                    Stop-Service -Name $s.Name -Force -ErrorAction Stop
                    Write-Log "Stopped service $($s.Name)." 'OK'
                    if ($s.PathName -and $s.PathName.IndexOf($Full, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        Set-Service -Name $s.Name -StartupType Disabled
                        Write-Log "Disabled service $($s.Name) (its binary is the target)." 'OK'
                    }
                }
            } else {
                Stop-Process -Id $p.Id -Force -ErrorAction Stop
                Write-Log "Stopped process $($p.Name) ($($p.Id))." 'OK'
            }
        } catch {
            Write-Log "Could not stop $($p.Name) ($($p.Id)): $($_.Exception.Message)" 'ERROR'
        }
    }
 
    Start-Sleep -Seconds 1
    $left = @($Procs | Where-Object { Get-Process -Id $_.Id -ErrorAction SilentlyContinue })
    foreach ($l in $left) {
        Write-Log "Still running: $($l.Name) ($($l.Id)) - file may remain locked." 'WARN'
    }
}
 
function Get-QuarantineItems {
    Get-ChildItem -LiteralPath $QuarantineDir -Filter '*.json' -ErrorAction SilentlyContinue |
        ForEach-Object { try { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } catch {} }
}
 
function Restore-Quarantined {
    param([string]$Id)
    $metaFile = Join-Path $QuarantineDir "$Id.json"
    if (-not (Test-Path -LiteralPath $metaFile)) { Write-Log "No quarantine record for ID $Id." 'ERROR'; return }
    $m = Get-Content -LiteralPath $metaFile -Raw | ConvertFrom-Json
    $src = Join-Path $QuarantineDir "$Id.quar"
    if (Test-Path -LiteralPath $m.OriginalPath) { Write-Log "Original path already exists: $($m.OriginalPath)" 'ERROR'; return }
    $parent = Split-Path -Parent $m.OriginalPath
    if (-not (Test-Path -LiteralPath $parent)) { Write-Log "Original folder missing: $parent" 'ERROR'; return }
    Write-Host "Restoring $($m.OriginalPath) (SHA256 $($m.SHA256))" -ForegroundColor Yellow
    $c = Read-Choice 'Restoring puts a suspected-malicious file back. Continue? [Y]es / [N]o' @('Y', 'N') 'N'
    if ($c -ne 'Y') { return }
    Move-Item -LiteralPath $src -Destination $m.OriginalPath -Force
    $aclFile = Join-Path $QuarantineDir $m.AclFile
    if (Test-Path -LiteralPath $aclFile) { try { Invoke-Icacls @($parent, '/restore', $aclFile, '/c') } catch { Write-Log $_ 'WARN' } }
    Write-Log "Restored $Id to $($m.OriginalPath)." 'OK'
}
 
# ----------------------------------------------------------------------------
# PER-FILE WORKFLOW
# ----------------------------------------------------------------------------
# ---- Interactive target selection (via Get-ThreatPath.bat) ------------------
function Select-File {
    param([System.IO.FileInfo[]]$Files)
    $max  = 40
    $show = @($Files | Select-Object -First $max)
    Write-Host ""
    Write-Host "Multiple candidates - pick the file to act on:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $show.Count; $i++) {
        $f = $show[$i]
        $sig = '?'
        try { $sig = [string](Get-AuthenticodeSignature -LiteralPath $f.FullName).Status } catch {}
        Write-Host ('{0,3}  {1,-40} {2,10:N0} B  {3:yyyy-MM-dd HH:mm}  {4}' -f ($i + 1), $f.Name, $f.Length, $f.LastWriteTime, $sig)
    }
    if ($Files.Count -gt $max) { Write-Host "  (showing newest $max of $($Files.Count))" -ForegroundColor Yellow }
    while ($true) {
        $r = Read-Host "Number (1-$($show.Count)) or C to cancel"
        if ($r -and $r.Trim().ToUpper() -eq 'C') { return $null }
        $n = 0
        if ([int]::TryParse($r, [ref]$n) -and $n -ge 1 -and $n -le $show.Count) { return $show[$n - 1].FullName }
        Write-Host '  Invalid choice.' -ForegroundColor Yellow
    }
}
 
function Get-TargetFromLauncher {
    $bat = Join-Path $PSScriptRoot 'Get-ThreatPath.bat'
    $raw = $null
    if (Test-Path -LiteralPath $bat) {
        $tmp = Join-Path $QuarantineDir ('target_{0}.tmp' -f [guid]::NewGuid().ToString('N'))
        try {
            $proc = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
                -ArgumentList "/d /c `"`"$bat`" `"$tmp`"`"" -NoNewWindow -Wait -PassThru
            if ($proc.ExitCode -eq 0 -and (Test-Path -LiteralPath $tmp)) {
                $raw = Get-Content -LiteralPath $tmp -Raw -Encoding OEM
            }
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    } else {
        Write-Log "Launcher not found ($bat); using console prompt instead." 'WARN'
        $raw = Read-Host 'Full path to the file (or the folder it is in)'
    }
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
 
    try {
        $p = [Environment]::ExpandEnvironmentVariables($raw.Trim().Trim('"').Trim())
 
        # 1) Exact file
        if (Test-Path -LiteralPath $p -PathType Leaf) { return (Get-Item -LiteralPath $p -Force).FullName }
 
        # 2) Folder only -> list exe/dll-type files and let the user pick
        if (Test-Path -LiteralPath $p -PathType Container) {
            $dir  = (Get-Item -LiteralPath $p -Force).FullName
            $exts = '.exe', '.dll', '.sys', '.scr', '.ocx', '.cpl', '.com'
            $files = @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $exts -contains $_.Extension.ToLower() } | Sort-Object LastWriteTime -Descending)
            if ($files.Count -eq 0) { Write-Log "No EXE/DLL-type files in $dir - cancelled." 'WARN'; return $null }
            return Select-File -Files $files
        }
 
        # 3) Full path typed without an extension
        $guess = @()
        foreach ($e in '.exe', '.dll', '.sys', '.scr') {
            if (Test-Path -LiteralPath "$p$e" -PathType Leaf) { $guess += Get-Item -LiteralPath "$p$e" -Force }
        }
        if ($guess.Count -eq 1) { Write-Host "No exact match; using $($guess[0].FullName)" -ForegroundColor Yellow; return $guess[0].FullName }
        if ($guess.Count -gt 1) { return Select-File -Files $guess }
 
        # 4) Not there -> cancel
        $parent = Split-Path -Parent $p
        if ($parent -and (Test-Path -LiteralPath $parent -PathType Container)) {
            Write-Log "Folder exists but the file was not found: $p - cancelled." 'WARN'
        } else {
            Write-Log "Path not found: $p - cancelled." 'WARN'
        }
    } catch {
        Write-Log "Could not evaluate path '$raw': $($_.Exception.Message)" 'ERROR'
    }
    return $null
}
 
function Invoke-ThreatRemoval {
    param([string]$Full)
 
    Write-Host ""
    Write-Host ('=' * 70)
    $rep = Get-FileReport -Full $Full
    $rep | Format-List | Out-String | Write-Host
 
    $why = Test-Protected -Full $Full -Report $rep
    if ($why -and -not $Force) {
        Write-Log "REFUSED $Full - $why. Use -Force only if you are certain." 'WARN'
        return
    }
    if ($why) { Write-Log "Protected target overridden with -Force: $why" 'WARN' }
 
    $procs = @(Get-RelatedProcesses -Full $Full)
    if ($procs.Count) {
        Write-Host "Processes using this file:" -ForegroundColor Cyan
        $procs | Select-Object Id, Name, Why, Critical,
            @{ n = 'Services'; e = { (@($_.Services) | ForEach-Object Name) -join ',' } },
            @{ n = 'ListenPorts'; e = { @($_.Ports) -join ',' } } |
            Format-Table -AutoSize | Out-String | Write-Host
    } else {
        Write-Host 'No running process or loaded module references this file.' -ForegroundColor Green
    }
 
    $refs = @(Get-PersistenceRefs -Full $Full)
    if ($refs.Count) {
        Write-Host 'Persistence referencing this file (NOT removed by this tool):' -ForegroundColor Yellow
        $refs | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    }
 
    $choice = $Action
    if ($choice -eq 'Prompt') {
        Write-Host ""
        Write-Host "  FILE   : $Full" -ForegroundColor White
        Write-Host "  SHA256 : $($rep.SHA256)" -ForegroundColor White
        Write-Host "  SIGNED : $($rep.Signature) $($rep.Signer)" -ForegroundColor White
        Write-Host ""
        Write-Host "  [1] Yes - Quarantine  (move to quarantine; reversible)"
        Write-Host "  [2] Yes - Delete      (permanent)"
        Write-Host "  [3] Yes - Both        (hash-verified evidence copy in quarantine, then delete original)"
        Write-Host "  [C] Cancel"
        $c = Read-Choice 'Choice (1 / 2 / 3 / C, default C)' @('1', '2', '3', 'C') 'C'
        $choice = switch ($c) { '1' { 'Quarantine' } '2' { 'Delete' } '3' { 'Both' } 'C' { 'Cancel' } }
    }
    if ($choice -eq 'Cancel') { Write-Log "Cancelled by operator: $Full (SHA256 $($rep.SHA256))"; return }
 
    $id = [guid]::NewGuid().ToString('N')
    $aclName = "$id.acl"
 
    # --- 1. Ownership via ICACLS --------------------------------------------
    if ($DryRun) {
        Write-Log "[DRYRUN] Would save ACL, run icacls /setowner $AdminSid and grant Administrators full control on $Full"
    } else {
        try {
            Invoke-Icacls @($Full, '/save', (Join-Path $QuarantineDir $aclName), '/c')
            Invoke-Icacls @($Full, '/setowner', $AdminSid, '/c', '/l')
            Invoke-Icacls @($Full, '/grant:r', "${AdminSid}:(F)", '/c', '/l')
            try { [IO.File]::SetAttributes($Full, [IO.FileAttributes]::Normal) } catch {}
            Write-Log "Took ownership of $Full (original ACL saved as $aclName)." 'OK'
        } catch {
            Write-Log "Ownership step failed for ${Full}: $($_.Exception.Message)" 'ERROR'
            return
        }
    }
 
    # --- 2. Stop processes --------------------------------------------------
    if ($DryRun) {
        if ($procs.Count) { Write-Log "[DRYRUN] Would offer to stop $($procs.Count) process(es)." }
    } else {
        Stop-RelatedProcesses -Procs $procs -Full $Full -Mode $StopProcesses
    }
 
    # --- 3. Quarantine or delete -------------------------------------------
    $act = $choice
 
    if ($DryRun) { Write-Log "[DRYRUN] Would $act $Full  (SHA256 $($rep.SHA256))"; return }
 
    try {
        if ($act -in 'Quarantine', 'Both') {
            $dest = Join-Path $QuarantineDir "$id.quar"
            if ($act -eq 'Quarantine') {
                Move-Item -LiteralPath $Full -Destination $dest -Force -ErrorAction Stop
            } else {
                # Copy works even if the file is locked by a running process; verify before deleting anything
                Copy-Item -LiteralPath $Full -Destination $dest -Force -ErrorAction Stop
                if ($rep.SHA256 -ne 'unavailable') {
                    $h2 = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
                    if ($h2 -ne $rep.SHA256) {
                        Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
                        throw 'Evidence copy hash mismatch - original NOT deleted.'
                    }
                }
            }
            Invoke-Icacls @($dest, '/inheritance:r', '/grant:r', "${SystemSid}:(F)", "${AdminSid}:(F)")
            [ordered]@{
                Id            = $id
                OriginalPath  = $Full
                SHA256        = $rep.SHA256
                Size          = $rep.Size
                Signature     = $rep.Signature
                Signer        = $rep.Signer
                OriginalOwner = $rep.Owner
                AclFile       = $aclName
                Disposition   = $act
                QuarantinedAt = (Get-Date).ToString('o')
                QuarantinedBy = "$env:USERDOMAIN\$env:USERNAME"
                PersistenceRefs = $refs
            } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $QuarantineDir "$id.json") -Encoding UTF8
            Write-Log "QUARANTINED ($act) $Full -> $id  (SHA256 $($rep.SHA256))" 'OK'
        }
        if ($act -in 'Delete', 'Both') {
            Remove-Item -LiteralPath $Full -Force -ErrorAction Stop
            Write-Log "DELETED $Full  (SHA256 $($rep.SHA256), signature $($rep.Signature))" 'OK'
        }
        if (Test-Path -LiteralPath $Full) { Write-Log "File still present after $act - check for a locking process." 'ERROR' }
    } catch {
        Write-Log "$act failed for ${Full}: $($_.Exception.Message)  (file may be locked by a process still running)" 'ERROR'
    }
 
    if ($refs.Count) { Write-Log "Reminder: $($refs.Count) persistence entry(ies) still reference $Full - remove them or it will respawn." 'WARN' }
}
 
# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------
Initialize-Store
 
Write-Host "Host: $env:COMPUTERNAME   Running as: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan
try {
    $self = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    Write-Host "Script SHA256: $self  (compare with your known-good copy)" -ForegroundColor Cyan
} catch {}
if ($DryRun) { Write-Host '*** DRY RUN - no changes will be made ***' -ForegroundColor Magenta }
 
if ($ListQuarantine) {
    Get-QuarantineItems | Select-Object Id, OriginalPath, SHA256, QuarantinedAt, QuarantinedBy | Format-Table -AutoSize
    return
}
if ($Restore) { Restore-Quarantined -Id $Restore; return }
 
if (-not $Path -or $Path.Count -eq 0) {
    $target = Get-TargetFromLauncher
    if (-not $target) { Write-Log 'Cancelled - no valid target selected.' 'WARN'; return }
    $Path = @($target)
}
 
foreach ($p in $Path) {
    $resolved = @()
    if (Test-Path -LiteralPath $p) { $resolved = @(Get-Item -LiteralPath $p -Force) }
    else { $resolved = @(Get-ChildItem -Path $p -Force -ErrorAction SilentlyContinue) }
 
    if ($resolved.Count -eq 0) { Write-Log "Not found: $p" 'WARN'; continue }
    foreach ($item in $resolved) {
        if ($item.PSIsContainer) { Write-Log "Skipping directory (files only): $($item.FullName)" 'WARN'; continue }
        try { Invoke-ThreatRemoval -Full $item.FullName }
        catch { Write-Log "Unhandled error on $($item.FullName): $($_.Exception.Message)" 'ERROR' }
    }
}
 
Write-Host ""
Write-Host "Log: $LogFile" -ForegroundColor Cyan
