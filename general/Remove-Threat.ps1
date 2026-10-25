#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Blue-team threat removal tool (GUI): take ownership (ICACLS) -> stop related
    processes -> quarantine or delete a malicious file.
    Merged version: Get-ThreatPath.bat is no longer needed.

.DESCRIPTION
    Run locally on each host (Windows Server 2019, PowerShell 5.1, Desktop Experience).
    Flow per file (Windows Forms dialogs):
      1. Path box          : type/paste the exact full path (with file name) or Browse
      2. Details box       : hash, signature, owner, size, processes using it,
                             persistence references + [Quarantine] [Delete] [Both] [Cancel]
      3. Ownership         : icacls (original ACL is saved first)
      4. Process confirm   : Yes/No, plus typed YES for services / listening processes
      5. Quarantine/delete : reversible quarantine, permanent delete, or evidence copy + delete
      6. Result box        : SUCCESS / PARTIAL / FAILED, steps taken, log location

    It never touches firewall, network, RDP, accounts, or reboots the host.
    It guards against stopping processes that host services or listen on ports
    (likely scored) without an explicit typed YES.

.PARAMETER Path
    One or more file paths (wildcards allowed). If omitted, the path box is shown.
.PARAMETER Action
    Prompt (default) | Quarantine | Delete | Both
    Both = keep an evidence copy in quarantine, then delete the original.
    Any value other than Prompt skips the action buttons.
.PARAMETER StopProcesses
    Prompt (default) | Yes | No
.PARAMETER DryRun
    Show what would happen; change nothing.
.PARAMETER Force
    Skip the protected-file refusal and the typed-YES gate. Use sparingly.
.PARAMETER Restore
    Restore a quarantined file by its ID (a confirmation box is shown).
.PARAMETER ListQuarantine
    Open the quarantine manager window (list + Restore button).

.EXAMPLE
    .\Remove-Threat.ps1
.EXAMPLE
    .\Remove-Threat.ps1 -Path C:\Users\Public\update.exe -DryRun
.EXAMPLE
    .\Remove-Threat.ps1 -ListQuarantine
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

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ----------------------------------------------------------------------------
# CONFIG - edit for your environment
# ----------------------------------------------------------------------------
$QuarantineDir = Join-Path $env:ProgramData 'BT_Quarantine'
$LogFile       = Join-Path $QuarantineDir 'threat-removal.log'
$FallbackLog   = Join-Path $env:TEMP 'threat-removal.fallback.log'   # used if the main log can't be written
$AdminSid      = '*S-1-5-32-544'   # BUILTIN\Administrators (locale-safe)
$SystemSid     = '*S-1-5-18'       # NT AUTHORITY\SYSTEM

# Processes this tool will never stop
$CriticalProcs = @('System', 'Idle', 'Registry', 'Memory Compression', 'smss', 'csrss',
                   'wininit', 'winlogon', 'services', 'lsass', 'lsaiso', 'dwm', 'fontdrvhost')

# Paths refused unless -Force (add your scored-service directories here)
$ProtectedPathPatterns = @(
    "$env:SystemRoot\NTDS*",
    "$env:SystemRoot\SYSVOL*",
    "$env:SystemRoot\System32\dns*",                    # DNS server role (added for AD/DNS box)
    "$env:SystemRoot\WinSxS*",
    "$env:SystemRoot\servicing*",
    "$env:ProgramFiles\Cloudbase Solutions*",           # OpenStack cloudbase-init
    "${env:ProgramFiles(x86)}\Cloudbase Solutions*",
    "$QuarantineDir*"
    # 'C:\inetpub\wwwroot\*'   # example: scored web content
)

# ----------------------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------------------
$script:LogFailed = $false
$script:Trail     = New-Object System.Collections.ArrayList   # log lines for the current file (shown in result box)

function Initialize-Store {
    if (-not (Test-Path -LiteralPath $QuarantineDir)) {
        New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
        & icacls.exe $QuarantineDir /inheritance:r /grant:r "${SystemSid}:(OI)(CI)F" "${AdminSid}:(OI)(CI)F" 2>&1 | Out-Null
    }
}

function Write-Log {
    param([string]$Msg, [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO')
    $line = '{0:u} [{1}] [{2}\{3}] {4}' -f (Get-Date), $Level, $env:USERDOMAIN, $env:USERNAME, $Msg
    try { Add-Content -LiteralPath $LogFile -Value $line -ErrorAction Stop }
    catch {
        $script:LogFailed = $true
        try { Add-Content -LiteralPath $FallbackLog -Value $line -ErrorAction Stop } catch {}
    }
    [void]$script:Trail.Add("[$Level] $Msg")
    $color = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'OK' { 'Green' } default { 'Gray' } }
    Write-Host "[$Level] $Msg" -ForegroundColor $color
}

function Notify([string]$Text, [string]$Title = 'Threat Remover', $Icon = 'Information') {
    [void][System.Windows.Forms.MessageBox]::Show($Text, $Title, 'OK', $Icon)
}

function Ask-Yes([string]$Text, [string]$Title = 'Threat Remover', $Icon = 'Warning') {
    # Default button is No.
    ([System.Windows.Forms.MessageBox]::Show($Text, $Title, 'YesNo', $Icon, 'Button2') -eq 'Yes')
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

# ----------------------------------------------------------------------------
# DIALOGS
# ----------------------------------------------------------------------------

# Replaces Get-ThreatPath.bat. Same rules: exact FULL path incl. file name,
# quotes tolerated, must start with X:\ or \\, must not end in a backslash.
function Resolve-TargetInput {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @{ Path = $null; Error = 'Enter a path first (or press Cancel).' } }
    $p = [Environment]::ExpandEnvironmentVariables($Raw.Trim().Trim('"').Trim())
    if ($p -notmatch '^([A-Za-z]:\\|\\\\)') { return @{ Path = $null; Error = "Not a full path - it must start with a drive letter like C:\ and include the file name.`n`n$p" } }
    if ($p.EndsWith('\'))                    { return @{ Path = $null; Error = "That ends in a backslash (a folder). Include the file name.`n`n$p" } }
    try {
        if (Test-Path -LiteralPath $p -PathType Leaf)      { return @{ Path = (Get-Item -LiteralPath $p -Force).FullName; Error = $null } }
        if (Test-Path -LiteralPath $p -PathType Container) { return @{ Path = $null; Error = "'$p' is a folder. Type the exact path INCLUDING the file name." } }
        $parent = Split-Path -Parent $p
        if ($parent -and (Test-Path -LiteralPath $parent -PathType Container)) {
            return @{ Path = $null; Error = "The folder exists but the file was not found:`n$p" }
        }
        return @{ Path = $null; Error = "File not found:`n$p" }
    } catch {
        return @{ Path = $null; Error = "Could not evaluate path:`n$($_.Exception.Message)" }
    }
}

function Read-TargetPath {
    $f = New-Object System.Windows.Forms.Form
    $f.Text = 'Threat Removal - Target File'; $f.Size = New-Object System.Drawing.Size(660, 215)
    $f.StartPosition = 'CenterScreen'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.TopMost = $true

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "Type the EXACT full path INCLUDING the file name, e.g.`r`nC:\Windows\System32\getridofme.txt   (pasting with quotes is fine)"
    $lbl.Location = New-Object System.Drawing.Point(12, 12); $lbl.Size = New-Object System.Drawing.Size(620, 40)

    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = New-Object System.Drawing.Point(12, 62); $tb.Size = New-Object System.Drawing.Size(520, 24)

    $br = New-Object System.Windows.Forms.Button
    $br.Text = 'Browse...'; $br.Location = New-Object System.Drawing.Point(540, 60); $br.Size = New-Object System.Drawing.Size(95, 27)
    $br.Add_Click({
        $d = New-Object System.Windows.Forms.OpenFileDialog
        $d.Title = 'Select threat file'; $d.Filter = 'All files (*.*)|*.*'
        $d.CheckFileExists = $true; $d.DereferenceLinks = $false
        if ($d.ShowDialog() -eq 'OK') { $tb.Text = $d.FileName }
    })

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'Next'; $ok.Location = New-Object System.Drawing.Point(430, 115); $ok.Size = New-Object System.Drawing.Size(95, 32); $ok.DialogResult = 'OK'
    $cn = New-Object System.Windows.Forms.Button
    $cn.Text = 'Cancel'; $cn.Location = New-Object System.Drawing.Point(540, 115); $cn.Size = New-Object System.Drawing.Size(95, 32); $cn.DialogResult = 'Cancel'
    $f.AcceptButton = $ok; $f.CancelButton = $cn
    $f.Controls.AddRange(@($lbl, $tb, $br, $ok, $cn))

    while ($true) {
        if ($f.ShowDialog() -ne 'OK') { return $null }
        $res = Resolve-TargetInput -Raw $tb.Text
        if ($res.Path) { return $res.Path }
        Notify $res.Error 'Threat Removal - Target File' 'Warning'
    }
}

function Get-InfoText {
    param($Rep, $Procs, $Refs, [string]$Full)
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add('FILE')
    $L.Add("  Path      : $Full")
    $L.Add("  Size      : $('{0:N0}' -f $Rep.Size) bytes")
    $L.Add("  Owner     : $($Rep.Owner)")
    $L.Add('')
    $L.Add('SIGNATURE')
    $L.Add("  Status    : $($Rep.Signature)")
    $L.Add("  Signer    : $(if ($Rep.Signer) { $Rep.Signer } else { '(none)' })")
    $L.Add('')
    $L.Add('SHA256')
    $L.Add("  $($Rep.SHA256)")
    $L.Add('')
    $L.Add('PROCESSES USING THIS FILE')
    if (@($Procs).Count -eq 0) { $L.Add('  (none)') }
    foreach ($p in @($Procs)) {
        $svc = (@($p.Services) | ForEach-Object { $_.Name }) -join ','
        $prt = @($p.Ports) -join ','
        $flag = if ($p.Critical) { '  [CRITICAL - will not be stopped]' } else { '' }
        $L.Add("  PID $($p.Id)  $($p.Name)  ($($p.Why))  services: $(if ($svc) { $svc } else { '-' })  listening: $(if ($prt) { $prt } else { '-' })$flag")
    }
    $L.Add('')
    $L.Add('PERSISTENCE REFERENCING THIS FILE (NOT removed by this tool)')
    if (@($Refs).Count -eq 0) { $L.Add('  (none found)') }
    foreach ($r in @($Refs)) { $L.Add("  - $r") }
    $L.Add('')
    $L.Add('ACTIONS')
    $L.Add('  Quarantine : move to quarantine (reversible)')
    $L.Add('  Delete     : permanent')
    $L.Add('  Both       : evidence copy in quarantine, then delete original')
    $L.Add('  Cancel     : do nothing')
    ($L -join "`r`n")
}

function Read-Action {
    param([string]$InfoText, [string]$Suffix = '')
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Threat Removal - Confirm Target and Choose Action$Suffix"
    $f.Size = New-Object System.Drawing.Size(820, 600); $f.StartPosition = 'CenterScreen'
    $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.TopMost = $true; $f.Tag = 'Cancel'

    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Multiline = $true; $tb.ReadOnly = $true; $tb.ScrollBars = 'Both'; $tb.WordWrap = $false
    $tb.Font = New-Object System.Drawing.Font('Consolas', 9.5)
    $tb.Location = New-Object System.Drawing.Point(12, 12); $tb.Size = New-Object System.Drawing.Size(780, 480); $tb.Text = $InfoText
    $f.Controls.Add($tb)

    $defs = @(
        @{ T = 'Quarantine (reversible)';  A = 'Quarantine'; X = 12;  W = 190; C = 'LightGoldenrodYellow' },
        @{ T = 'Delete (permanent)';       A = 'Delete';     X = 212; W = 190; C = 'MistyRose' },
        @{ T = 'Both (copy + delete)';     A = 'Both';       X = 412; W = 190; C = 'LightSalmon' },
        @{ T = 'Cancel';                   A = 'Cancel';     X = 612; W = 180; C = 'Gainsboro' }
    )
    foreach ($d in $defs) {
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $d.T; $b.Tag = $d.A
        $b.Location = New-Object System.Drawing.Point($d.X, 505); $b.Size = New-Object System.Drawing.Size($d.W, 44)
        $b.BackColor = [System.Drawing.Color]::FromName($d.C)
        $b.Add_Click({ param($s, $e) $f.Tag = $s.Tag; $f.Close() })
        $f.Controls.Add($b)
    }
    [void]$f.ShowDialog()
    return [string]$f.Tag
}

function Read-TypedYes {
    param([string]$Text)
    $f = New-Object System.Windows.Forms.Form
    $f.Text = 'Scored-service guard'; $f.Size = New-Object System.Drawing.Size(560, 280)
    $f.StartPosition = 'CenterScreen'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.TopMost = $true
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $Text + "`r`n`r`nType YES (capitals) to stop it, anything else to skip:"
    $lbl.Location = New-Object System.Drawing.Point(12, 12); $lbl.Size = New-Object System.Drawing.Size(520, 130)
    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Location = New-Object System.Drawing.Point(12, 150); $tb.Size = New-Object System.Drawing.Size(520, 24)
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'OK'; $ok.Location = New-Object System.Drawing.Point(330, 190); $ok.Size = New-Object System.Drawing.Size(95, 32); $ok.DialogResult = 'OK'
    $cn = New-Object System.Windows.Forms.Button
    $cn.Text = 'Skip'; $cn.Location = New-Object System.Drawing.Point(437, 190); $cn.Size = New-Object System.Drawing.Size(95, 32); $cn.DialogResult = 'Cancel'
    $f.AcceptButton = $ok; $f.CancelButton = $cn
    $f.Controls.AddRange(@($lbl, $tb, $ok, $cn))
    if ($f.ShowDialog() -ne 'OK') { return $false }
    return ($tb.Text -ceq 'YES')
}

# ----------------------------------------------------------------------------
# PROCESSES
# ----------------------------------------------------------------------------
function Stop-RelatedProcesses {
    param($Procs, [string]$Full, [string]$Mode)

    if (-not $Procs -or @($Procs).Count -eq 0) { return }
    if ($Mode -eq 'Prompt') {
        $lines = foreach ($p in $Procs) {
            $svc = (@($p.Services) | ForEach-Object { $_.Name }) -join ','
            $prt = @($p.Ports) -join ','
            "  PID $($p.Id)  $($p.Name)  services: $(if ($svc) { $svc } else { '-' })  listening: $(if ($prt) { $prt } else { '-' })"
        }
        $Mode = if (Ask-Yes ("These processes are using the file:`n`n" + ($lines -join "`n") + "`n`nStop them now?") 'Threat Removal - Processes') { 'Yes' } else { 'No' }
    }
    if ($Mode -ne 'Yes') { Write-Log 'Process stop skipped by operator.'; return }

    foreach ($p in $Procs) {
        if ($p.Critical -or $p.Id -eq $PID) {
            Write-Log "Refusing to stop critical process $($p.Name) ($($p.Id)). Handle manually." 'WARN'
            continue
        }
        $risky = (@($p.Services).Count -gt 0) -or (@($p.Ports).Count -gt 0)
        if ($risky -and -not $Force) {
            $txt = "$($p.Name) ($($p.Id)) may be tied to a scored service:"
            if (@($p.Services).Count) { $txt += "`r`n    Services : $((@($p.Services) | ForEach-Object { $_.Name }) -join ', ')" }
            if (@($p.Ports).Count)    { $txt += "`r`n    Listening: $(@($p.Ports) -join ', ')" }
            if (-not (Read-TypedYes -Text $txt)) { Write-Log "Skipped stopping $($p.Name) ($($p.Id))." 'WARN'; continue }
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

# ----------------------------------------------------------------------------
# QUARANTINE STORE / RESTORE
# ----------------------------------------------------------------------------
function Get-QuarantineItems {
    Get-ChildItem -LiteralPath $QuarantineDir -Filter '*.json' -ErrorAction SilentlyContinue |
        ForEach-Object { try { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } catch {} }
}

function Restore-Quarantined {
    # Returns $true if restored.
    param([string]$Id)
    $metaFile = Join-Path $QuarantineDir "$Id.json"
    if (-not (Test-Path -LiteralPath $metaFile)) { Write-Log "No quarantine record for ID $Id." 'ERROR'; Notify "No quarantine record for ID $Id." 'Restore' 'Error'; return $false }
    $m = Get-Content -LiteralPath $metaFile -Raw | ConvertFrom-Json
    $src = Join-Path $QuarantineDir "$Id.quar"
    if (-not (Test-Path -LiteralPath $src)) { Write-Log "Quarantined file missing for ID $Id." 'ERROR'; Notify "Quarantined file missing for ID $Id." 'Restore' 'Error'; return $false }
    if (Test-Path -LiteralPath $m.OriginalPath) { Write-Log "Original path already exists: $($m.OriginalPath)" 'ERROR'; Notify "Original path already exists:`n$($m.OriginalPath)" 'Restore' 'Error'; return $false }
    $parent = Split-Path -Parent $m.OriginalPath
    if (-not (Test-Path -LiteralPath $parent)) { Write-Log "Original folder missing: $parent" 'ERROR'; Notify "Original folder missing:`n$parent" 'Restore' 'Error'; return $false }

    if (-not (Ask-Yes "Restoring puts a suspected-malicious file back. Continue?`n`n$($m.OriginalPath)`nSHA256 $($m.SHA256)" 'Restore')) { return $false }
    try {
        Move-Item -LiteralPath $src -Destination $m.OriginalPath -Force -ErrorAction Stop
    } catch {
        Write-Log "Restore of $Id failed: $($_.Exception.Message)" 'ERROR'; Notify "Restore failed:`n$($_.Exception.Message)" 'Restore' 'Error'; return $false
    }
    $aclFile = Join-Path $QuarantineDir $m.AclFile
    if (Test-Path -LiteralPath $aclFile) { try { Invoke-Icacls @($parent, '/restore', $aclFile, '/c') } catch { Write-Log "$_" 'WARN' } }
    Write-Log "Restored $Id to $($m.OriginalPath)." 'OK'
    Notify "Restored:`n$($m.OriginalPath)" 'Restore' 'Information'
    return $true
}

function Show-QuarantineManager {
    $items = @(Get-QuarantineItems | Where-Object { $_ -and (Test-Path -LiteralPath (Join-Path $QuarantineDir "$($_.Id).quar")) })
    if ($items.Count -eq 0) { Notify 'Quarantine is empty.' 'Quarantine Manager' 'Information'; return }

    $f = New-Object System.Windows.Forms.Form
    $f.Text = 'Quarantine Manager'; $f.Size = New-Object System.Drawing.Size(1000, 480)
    $f.StartPosition = 'CenterScreen'; $f.TopMost = $true

    $lv = New-Object System.Windows.Forms.ListView
    $lv.View = 'Details'; $lv.FullRowSelect = $true; $lv.MultiSelect = $false; $lv.GridLines = $true
    $lv.Location = New-Object System.Drawing.Point(12, 12); $lv.Size = New-Object System.Drawing.Size(960, 380)
    $lv.Anchor = 'Top,Bottom,Left,Right'
    [void]$lv.Columns.Add('ID', 230); [void]$lv.Columns.Add('Original path', 360); [void]$lv.Columns.Add('Quarantined at', 150)
    [void]$lv.Columns.Add('By', 130); [void]$lv.Columns.Add('Mode', 70)
    foreach ($it in $items) {
        $li = New-Object System.Windows.Forms.ListViewItem([string]$it.Id)
        [void]$li.SubItems.Add([string]$it.OriginalPath)
        [void]$li.SubItems.Add([string]$it.QuarantinedAt)
        [void]$li.SubItems.Add([string]$it.QuarantinedBy)
        [void]$li.SubItems.Add([string]$it.Disposition)
        $li.Tag = $it.Id
        [void]$lv.Items.Add($li)
    }

    $rb = New-Object System.Windows.Forms.Button
    $rb.Text = 'Restore selected'; $rb.Location = New-Object System.Drawing.Point(12, 402); $rb.Size = New-Object System.Drawing.Size(160, 34); $rb.Anchor = 'Bottom,Left'
    $rb.Add_Click({
        if ($lv.SelectedItems.Count -eq 0) { return }
        $sel = $lv.SelectedItems[0]
        if (Restore-Quarantined -Id ([string]$sel.Tag)) { $lv.Items.Remove($sel) }
    })
    $cb = New-Object System.Windows.Forms.Button
    $cb.Text = 'Close'; $cb.Location = New-Object System.Drawing.Point(812, 402); $cb.Size = New-Object System.Drawing.Size(160, 34); $cb.Anchor = 'Bottom,Right'
    $cb.DialogResult = 'Cancel'
    $f.CancelButton = $cb
    $f.Controls.AddRange(@($lv, $rb, $cb))
    [void]$f.ShowDialog()
}

# ----------------------------------------------------------------------------
# PER-FILE WORKFLOW
# ----------------------------------------------------------------------------
function Show-Result {
    param([string]$Outcome, [string]$Full)
    $text = "Result : $Outcome`r`nFile   : $Full`r`n`r`n" + (($script:Trail | ForEach-Object { $_ }) -join "`r`n") + "`r`n`r`nLog: $LogFile"
    if ($script:LogFailed) { $text += "`r`n`r`nWARNING: writing to the main log FAILED. Fallback log: $FallbackLog" }
    $icon = switch ($Outcome) { 'SUCCESS' { 'Information' } 'DRY RUN' { 'Information' } 'CANCELLED' { 'Information' } 'REFUSED' { 'Warning' } 'PARTIAL' { 'Warning' } default { 'Error' } }
    Notify $text "Threat Removal - $Outcome" $icon
}

function Invoke-ThreatRemoval {
    param([string]$Full)
    $script:Trail.Clear()

    $rep = Get-FileReport -Full $Full

    $why = Test-Protected -Full $Full -Report $rep
    if ($why -and -not $Force) {
        Write-Log "REFUSED $Full - $why. Use -Force only if you are certain." 'WARN'
        Show-Result 'REFUSED' $Full
        return
    }
    if ($why) { Write-Log "Protected target overridden with -Force: $why" 'WARN' }

    $procs = @(Get-RelatedProcesses -Full $Full)
    $refs  = @(Get-PersistenceRefs -Full $Full)

    $choice = $Action
    if ($choice -eq 'Prompt') {
        $suffix = if ($DryRun) { '  [DRY RUN]' } else { '' }
        $choice = Read-Action -InfoText (Get-InfoText -Rep $rep -Procs $procs -Refs $refs -Full $Full) -Suffix $suffix
    }
    if ($choice -eq 'Cancel') {
        Write-Log "Cancelled by operator: $Full (SHA256 $($rep.SHA256))"
        Show-Result 'CANCELLED' $Full
        return
    }
    Write-Log "Operator chose $choice for $Full (SHA256 $($rep.SHA256))"

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
            Show-Result 'FAILED' $Full
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
    if ($DryRun) {
        Write-Log "[DRYRUN] Would $act $Full  (SHA256 $($rep.SHA256))"
        Show-Result 'DRY RUN' $Full
        return
    }

    $stored = $false
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
                } else {
                    Write-Log 'Original hash unavailable - evidence copy is NOT hash-verified; deleting anyway.' 'WARN'
                }
            }
            $stored = $true
            Invoke-Icacls @($dest, '/inheritance:r', '/grant:r', "${SystemSid}:(F)", "${AdminSid}:(F)")
            [ordered]@{
                Id              = $id
                OriginalPath    = $Full
                SHA256          = $rep.SHA256
                Size            = $rep.Size
                Signature       = $rep.Signature
                Signer          = $rep.Signer
                OriginalOwner   = $rep.Owner
                AclFile         = $aclName
                Disposition     = $act
                QuarantinedAt   = (Get-Date).ToString('o')
                QuarantinedBy   = "$env:USERDOMAIN\$env:USERNAME"
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

    $gone   = -not (Test-Path -LiteralPath $Full)
    $hadErr = @($script:Trail | Where-Object { $_.StartsWith('[ERROR]') }).Count -gt 0
    $outcome = if ($gone -and -not $hadErr) { 'SUCCESS' }
               elseif ($gone -or $stored)   { 'PARTIAL' }
               else                         { 'FAILED' }
    Show-Result $outcome $Full
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

if ($ListQuarantine) { Show-QuarantineManager; return }
if ($Restore) { [void](Restore-Quarantined -Id $Restore); return }

if (-not $Path -or $Path.Count -eq 0) {
    $target = Read-TargetPath
    if (-not $target) { Write-Log 'Cancelled - no valid target selected.' 'WARN'; return }
    $Path = @($target)
}

foreach ($p in $Path) {
    $resolved = @()
    if (Test-Path -LiteralPath $p) { $resolved = @(Get-Item -LiteralPath $p -Force) }
    else { $resolved = @(Get-ChildItem -Path $p -Force -ErrorAction SilentlyContinue) }

    if ($resolved.Count -eq 0) { Write-Log "Not found: $p" 'WARN'; Notify "Not found:`n$p" 'Threat Removal' 'Warning'; continue }
    foreach ($item in $resolved) {
        if ($item.PSIsContainer) { Write-Log "Skipping directory (files only): $($item.FullName)" 'WARN'; continue }
        try { Invoke-ThreatRemoval -Full $item.FullName }
        catch {
            Write-Log "Unhandled error on $($item.FullName): $($_.Exception.Message)" 'ERROR'
            Show-Result 'FAILED' $item.FullName
        }
    }
}

Write-Host ""
Write-Host "Log: $LogFile" -ForegroundColor Cyan
