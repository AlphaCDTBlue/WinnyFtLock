#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Remove-Folder.ps1 - force-deletes a folder (or a single file) no matter who
  owns it or what its permissions say.

.DESCRIPTION
  Run in an elevated PowerShell:
      .\Remove-Folder.ps1 "C:\Program Files\PostgreSQL"
      .\Remove-Folder.ps1 "C:\Program Files\PostgreSQL" -Yes      (skips the y/N question)
  With no path, nothing happens.

  What it does, in order:
    1. Refuses protected paths (drive roots, Windows, Program Files, ProgramData,
       Users, inetpub, C:\BlueLogs) and UNC paths and wildcards.
    2. Stops and deletes Windows services whose program lives inside the folder.
    3. Kills processes that are running from inside the folder.
    4. Takes ownership, resets the permissions, gives Administrators full control,
       and clears read-only / hidden / system flags.
    5. Deletes it. Junctions and symlinks inside are removed, never followed.
    6. If anything is left (a file held open), retries and lists what remains.

  PERMANENT. There is no recycle bin. Copy the folder somewhere first if you
  need it as evidence. If the folder is a scored service's, you lose that service.
  Not touched: scheduled tasks, Run keys and firewall rules that point into the
  folder. Check those yourself afterwards.

  Log: C:\BlueLogs\remove-folder.log
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Path,
    [switch]$Yes
)

$ErrorActionPreference = 'Continue'

if (-not $Path) {
    Write-Host 'Nothing done. Give a path:  .\Remove-Folder.ps1 "C:\Program Files\PostgreSQL"'
    exit 0
}

$LogDir  = 'C:\BlueLogs'
$LogFile = Join-Path $LogDir 'remove-folder.log'

function Log([string]$m, [string]$color = 'Gray') {
    Write-Host $m -ForegroundColor $color
    try {
        $null = New-Item -ItemType Directory -Path $LogDir -Force
        Add-Content -Path $LogFile -Value ('{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8
    } catch {}
}

function Trim-Slash([string]$p) {
    if ($p.Length -gt 3) { return $p.TrimEnd('\') }
    return $p
}

# ---- resolve and sanity-check the path ----
$full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path.Trim().Trim('"'))
$full = Trim-Slash $full

if ($full -match '[*?]') { Log "Refusing: wildcards are not allowed in the path ($full)." Red; exit 1 }
if ($full.StartsWith('\\')) { Log "Refusing: network/UNC paths are not supported ($full)." Red; exit 1 }
if ($full -match '^[A-Za-z]:\\?$') { Log "Refusing: $full is a whole drive." Red; exit 1 }

$drive = $env:SystemDrive
$protected = @(
    ($drive + '\'),
    $env:SystemRoot,
    (Join-Path $env:SystemRoot 'System32'),
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:ProgramData,
    (Join-Path $drive 'Users'),
    (Join-Path $drive 'inetpub'),
    $LogDir
)
foreach ($p in $protected) {
    if (-not $p) { continue }
    $p = Trim-Slash $p
    # refuse the protected folder itself, or any folder that contains it
    if (($full -ieq $p) -or ($p.StartsWith($full + '\', [StringComparison]::OrdinalIgnoreCase))) {
        Log "Refusing: $full is protected ($p)." Red
        exit 1
    }
}

function Test-Exists {
    return ((Test-Path -LiteralPath $full) -or [IO.Directory]::Exists($full) -or [IO.File]::Exists($full))
}

if (-not (Test-Exists)) { Log "Not found: $full" Red; exit 1 }

$isDir = [IO.Directory]::Exists($full)
$isLink = $false
try { $isLink = (([IO.File]::GetAttributes($full) -band [IO.FileAttributes]::ReparsePoint) -ne 0) } catch {}
$inWindows = $full.StartsWith($env:SystemRoot + '\', [StringComparison]::OrdinalIgnoreCase)

$kind = 'file'
if ($isDir) { $kind = 'folder' }
if ($isLink) { $kind = 'link (junction/symlink)' }

Write-Host ''
Write-Host "About to PERMANENTLY delete $kind :" -ForegroundColor Yellow
Write-Host "  $full" -ForegroundColor Yellow
if ($inWindows) { Write-Host '  WARNING: this is inside the Windows folder.' -ForegroundColor Red }
if ((-not $Yes) -or $inWindows) {
    if ((Read-Host 'Continue? (y/N)') -ne 'y') { Write-Host 'Nothing changed.'; exit 0 }
}
Log "START delete $kind $full (by $env:USERDOMAIN\$env:USERNAME)"

# ---- a link at the top level: remove just the link, never its target ----
if ($isLink) {
    if ($isDir) { & cmd.exe /c rmdir "$full" 2>&1 | Out-Null }
    else { & cmd.exe /c del /f /q "$full" 2>&1 | Out-Null }
    if (Test-Exists) { Log "FAILED to remove the link $full" Red; exit 1 }
    Log "Removed the link $full (its target was not touched)." Green
    exit 0
}

# ---- 1. services whose program is inside the folder ----
$rx = '(?i)' + [regex]::Escape($full) + '(\\|"|\s|$)'
$svcs = @(Get-CimInstance Win32_Service | Where-Object { $_.PathName -match $rx })
foreach ($s in $svcs) {
    Log "service: $($s.Name) [$($s.State)] runs $($s.PathName)" Yellow
    $svcPid = [int]$s.ProcessId
    & sc.exe stop $s.Name 2>&1 | Out-Null
    Start-Sleep -Milliseconds 800
    if (($svcPid -gt 0) -and (Get-Process -Id $svcPid -ErrorAction SilentlyContinue)) {
        & taskkill.exe /F /T /PID $svcPid 2>&1 | Out-Null
    }
    & sc.exe delete $s.Name 2>&1 | Out-Null
    Log "  stopped and deleted service $($s.Name)"
}

# ---- 2. processes running from inside the folder ----
$procs = @(Get-CimInstance Win32_Process | Where-Object { ($_.ProcessId -ne $PID) -and ($_.ExecutablePath -match $rx) })
foreach ($p in $procs) {
    Log "killing process $($p.Name) (pid $($p.ProcessId)) $($p.ExecutablePath)" Yellow
    & taskkill.exe /F /T /PID $p.ProcessId 2>&1 | Out-Null
}
if ($svcs.Count -or $procs.Count) { Start-Sleep -Seconds 1 }

# ---- 3. ownership, permissions, attributes ----
$admins = '*S-1-5-32-544'    # built-in Administrators group
if ($isDir) {
    & takeown.exe /F $full /R /D Y /SKIPSL 2>&1 | Out-Null
    & icacls.exe $full /reset /T /C /L /Q 2>&1 | Out-Null
    & icacls.exe $full /grant "${admins}:(OI)(CI)F" /T /C /L /Q 2>&1 | Out-Null
    & attrib.exe -R -S -H "$full\*" /S /D /L 2>&1 | Out-Null
    & attrib.exe -R -S -H $full /L 2>&1 | Out-Null
} else {
    & takeown.exe /F $full 2>&1 | Out-Null
    & icacls.exe $full /reset /C /L /Q 2>&1 | Out-Null
    & icacls.exe $full /grant "${admins}:F" /C /L /Q 2>&1 | Out-Null
    & attrib.exe -R -S -H $full /L 2>&1 | Out-Null
}

# ---- 4. delete ----
$long = '\\?\' + $full      # lets cmd handle paths longer than 260 characters
if ($isDir) { & cmd.exe /c rd /s /q "$long" 2>&1 | Out-Null }
else { & cmd.exe /c del /f /q "$long" 2>&1 | Out-Null }

# ---- 5. still there? retry with the robocopy empty-folder trick ----
if ((Test-Exists) -and $isDir) {
    Start-Sleep -Seconds 2
    $empty = Join-Path $env:TEMP ('empty-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $empty -Force
    & robocopy.exe $empty $full /MIR /B /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS /NP 2>&1 | Out-Null
    Remove-Item -LiteralPath $empty -Force -ErrorAction SilentlyContinue
    & cmd.exe /c rd /s /q "$long" 2>&1 | Out-Null
}

# ---- result ----
if (-not (Test-Exists)) {
    Log "DELETED $full" Green
    exit 0
}

Log "NOT fully deleted: $full" Red
if ($isDir) {
    Write-Host 'Still left (first 20):' -ForegroundColor Yellow
    & cmd.exe /c dir /a /b /s "$full" 2>$null | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" }
}
Write-Host ''
Write-Host 'Something is probably holding it open (a program, or a DLL loaded by another process).' -ForegroundColor Yellow
Write-Host 'Find it with Sysinternals:  handle64.exe -nobanner "<folder>"   or Process Explorer > Find > Handle.' -ForegroundColor Yellow
Write-Host 'Stop that program, then run this script again.' -ForegroundColor Yellow
exit 1
