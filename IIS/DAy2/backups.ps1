#Requires -RunAsAdministrator
<#
.SYNOPSIS
  backups.ps1 - copies gitat's emergency copy of the IIS files to 3 other hidden places.

.DESCRIPTION
  Run in an elevated PowerShell, no arguments:
      .\backups.ps1

  Source: the emergency copy gitat keeps (C:\Users\Public\Pictures\.<GUID>). The exact
  path is read from C:\ProgramData\IISCache\settings.json (EmergencyPath).

  Destinations: 3 hidden folders with random names, made the first time you run it
  and reused after that. The exact paths are saved in C:\BlueLogs\backups-locations.json.
  Every run adds a NEW timestamped snapshot folder in each place and keeps the newest 5,
  so a bad copy never overwrites a good one.

  Each snapshot is checked after copying (same files, same sizes, nothing different).
  If the source changed while copying, it retries once. Run it again after any gitat
  Rebaseline so the backups pick up the new approved files.

  These are on this same server. A local administrator can still delete them.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$SettingsFile = 'C:\ProgramData\IISCache\settings.json'
$LogDir       = 'C:\BlueLogs'
$StateFile    = Join-Path $LogDir 'backups-locations.json'
$LogFile      = Join-Path $LogDir 'backups.log'
$KeepSnapshots = 5
$Parents = @(
    'C:\Users\Public\Documents',
    'C:\ProgramData\Microsoft\Windows\Templates',
    'C:\Windows\Help'
)
$PrivateSddl = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'

function Log([string]$text, [string]$color = '') {
    if ($color) { Write-Host $text -ForegroundColor $color } else { Write-Host $text }
    try { Add-Content -LiteralPath $LogFile -Value ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $text) } catch {}
}

function Test-NoReparse([string]$Path) {
    $p = [IO.Path]::GetFullPath($Path)
    while ($p) {
        if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
        $p = [IO.Path]::GetDirectoryName($p)
    }
    return $true
}

function Get-Stats([string]$Path) {
    $files = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction Stop)
    $bytes = [long]0
    foreach ($f in $files) { $bytes += $f.Length }
    return [pscustomobject]@{ Files = $files.Count; Bytes = $bytes }
}

function Set-Private([string]$Path) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm($PrivateSddl)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

# ---------------- make sure the log folder exists ----------------
try {
    if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
} catch {
    Write-Host "ERROR: cannot create $LogDir : $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ---------------- find the source ----------------
if (-not (Test-Path -LiteralPath $SettingsFile)) {
    Log "ERROR: $SettingsFile not found. Run gitat.ps1 first so it makes its baseline." 'Red'
    exit 1
}
try {
    $settings = Get-Content -LiteralPath $SettingsFile -Raw | ConvertFrom-Json
} catch {
    Log "ERROR: could not read settings.json: $($_.Exception.Message)" 'Red'
    exit 1
}
$source = [string]$settings.EmergencyPath
if (-not $source) {
    Log 'ERROR: settings.json has no EmergencyPath. Run gitat.ps1 setup first.' 'Red'
    exit 1
}
$source = [IO.Path]::GetFullPath($source)
if (-not (Test-Path -LiteralPath $source -PathType Container)) {
    Log "ERROR: the emergency copy folder is missing: $source" 'Red'
    exit 1
}
if (-not (Test-Path -LiteralPath (Join-Path $source 'manifest.json'))) {
    Log "ERROR: $source has no manifest.json, so it does not look like a complete gitat emergency copy. Nothing was backed up." 'Red'
    exit 1
}
if (-not (Test-NoReparse $source)) {
    Log "ERROR: $source is or sits inside a link/junction. Refusing." 'Red'
    exit 1
}
try { $srcStats = Get-Stats $source }
catch { Log "ERROR: could not read the source: $($_.Exception.Message)" 'Red'; exit 1 }
if ($srcStats.Files -lt 2) {
    Log "ERROR: the emergency copy has only $($srcStats.Files) file(s). Not backing up something that looks empty." 'Red'
    exit 1
}
Log "Source: $source ($($srcStats.Files) files, $([math]::Round($srcStats.Bytes / 1MB, 1)) MB)"

# ---------------- destinations (made once, then reused) ----------------
$destinations = @()
if (Test-Path -LiteralPath $StateFile) {
    try { $destinations = @((Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json).Destinations | ForEach-Object { [string]$_ }) } catch { $destinations = @() }
}
$stateOk = ($destinations.Count -eq 3) -and (@($destinations | Where-Object { $_ -match '^[A-Za-z]:\\.+\\\.[a-f0-9]{32}$' }).Count -eq 3)
if (-not $stateOk) {
    $destinations = @($Parents | ForEach-Object { Join-Path $_ ('.' + [guid]::NewGuid().ToString('N')) })
    try {
        @{ Destinations = $destinations; Created = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $StateFile -Encoding ASCII
    } catch {
        Log "ERROR: could not save $StateFile : $($_.Exception.Message)" 'Red'
        exit 1
    }
    Log "Made 3 new backup locations. Saved in $StateFile"
}

# never back up into the source or into a protected IIS folder
$protected = @('C:\inetpub')
foreach ($t in @($settings.Targets)) { if ($t.Root) { $protected += [string]$t.Root } }
foreach ($d in $destinations) {
    $full = [IO.Path]::GetFullPath($d).TrimEnd('\')
    $bad = ($full -ieq $source.TrimEnd('\')) -or $full.StartsWith($source.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)
    foreach ($r in $protected) {
        $rr = [IO.Path]::GetFullPath($r).TrimEnd('\')
        if (($full -ieq $rr) -or $full.StartsWith($rr + '\', [StringComparison]::OrdinalIgnoreCase)) { $bad = $true }
    }
    if ($bad) {
        Log "ERROR: backup location $d overlaps the source or a protected IIS folder. Delete $StateFile and run again." 'Red'
        exit 1
    }
}

# ---------------- back up to each place ----------------
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$results = @()
foreach ($dest in $destinations) {
    $row = [pscustomobject]@{ Place = $dest; Result = 'FAILED'; Detail = '' }
    try {
        if (-not (Test-Path -LiteralPath $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
        if (-not (Test-NoReparse $dest)) { throw 'the backup folder is or sits inside a link/junction' }
        Set-Private $dest
        $item = Get-Item -LiteralPath $dest -Force
        $item.Attributes = $item.Attributes -bor [IO.FileAttributes]::Hidden

        $snap = Join-Path $dest $stamp
        $verified = $false
        for ($try = 1; ($try -le 2) -and (-not $verified); $try++) {
            if (Test-Path -LiteralPath $snap) { Remove-Item -LiteralPath $snap -Recurse -Force }
            $null = & robocopy.exe $source $snap /E /COPY:DAT /DCOPY:DAT /R:1 /W:1 /XJ /NFL /NDL /NJH /NJS /NP
            if ($LASTEXITCODE -ge 8) { throw "robocopy failed (exit code $LASTEXITCODE)" }

            # verify: same file count and bytes, and robocopy sees nothing different
            $now = Get-Stats $source
            $got = Get-Stats $snap
            $diff = @(& robocopy.exe $source $snap /E /L /COPY:DAT /XJ /NJH /NJS /NP /NDL | Where-Object { ([string]$_).Trim() })
            if (($got.Files -eq $now.Files) -and ($got.Bytes -eq $now.Bytes) -and (-not $diff.Count)) {
                $verified = $true
                $row.Detail = "$($got.Files) files, $([math]::Round($got.Bytes / 1MB, 1)) MB"
            }
        }
        if (-not $verified) { throw 'the copy did not match the source (the source may have been changing). Run it again.' }

        # keep only the newest snapshots
        $old = @(Get-ChildItem -LiteralPath $dest -Directory -Force | Where-Object { $_.Name -match '^\d{8}-\d{6}$' } | Sort-Object Name -Descending | Select-Object -Skip $KeepSnapshots)
        foreach ($o in $old) {
            try { Remove-Item -LiteralPath $o.FullName -Recurse -Force -ErrorAction Stop } catch { Log "Note: could not remove old snapshot $($o.FullName): $($_.Exception.Message)" 'Yellow' }
        }
        $row.Result = 'OK'
        Log "OK     $snap  ($($row.Detail))" 'Green'
    } catch {
        $row.Detail = $_.Exception.Message
        Log "FAILED $dest : $($row.Detail)" 'Red'
    }
    $results += $row
}

# ---------------- summary ----------------
$ok = @($results | Where-Object { $_.Result -eq 'OK' }).Count
Write-Host ''
if ($ok -eq 3) {
    Log 'DONE: all 3 backups made and verified.' 'Green'
    Write-Host 'Restore one (puts the files back into gitat''s emergency copy):'
    Write-Host "  robocopy `"$($destinations[0])\$stamp`" `"$source`" /MIR /COPY:DAT /DCOPY:DAT"
    exit 0
}
Log "PROBLEM: only $ok of 3 backups succeeded. Fix the red lines above and run it again." 'Red'
exit 1
