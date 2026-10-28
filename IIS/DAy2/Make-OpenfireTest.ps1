#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Make-OpenfireTest.ps1 - makes a fake test folder (OpenfireTest) in Program
  Files that users and administrators cannot delete, so you can try
  Remove-Folder.ps1 on it.

.DESCRIPTION
  Run in an elevated PowerShell:
      .\Make-OpenfireTest.ps1
      .\Make-OpenfireTest.ps1 -Name SomethingElse     (your own folder name)

  It makes C:\Program Files\OpenfireTest with a few fake files inside (no real
  Openfire, nothing runs). If that name is taken it uses OpenfireTest2,
  OpenfireTest3, and so on. Permissions:
    - owner: SYSTEM
    - SYSTEM: full control
    - Administrators and Users: read and execute only
    - Administrators and Users: explicit DENY for delete and delete-subfolders-and-files
    - inheritance from Program Files switched off
  One file is Read-only + Hidden + System, to test that the deleter clears those.

  Then it proves it: it tries to delete the folder as the current administrator
  and reports whether that was blocked.

  Remove-Folder.ps1 still gets rid of it, because an elevated administrator can
  take ownership, reset the permissions, and then delete.

  It never touches a folder that already exists, so it cannot damage a real
  Openfire install.
#>
[CmdletBinding()]
param([string]$Name = 'OpenfireTest')

$ErrorActionPreference = 'Stop'

if ($Name -notmatch '^[A-Za-z0-9 _-]+$') {
    Write-Host "Bad name '$Name'. Use letters, numbers, space, - or _ only." -ForegroundColor Red
    exit 1
}
$path = Join-Path $env:ProgramFiles $Name

# default name: if it is taken, use OpenfireTest2, OpenfireTest3, ...
if ((-not $PSBoundParameters.ContainsKey('Name')) -and (Test-Path -LiteralPath $path)) {
    $n = 2
    while (Test-Path -LiteralPath (Join-Path $env:ProgramFiles ($Name + $n))) { $n++ }
    $Name = $Name + $n
    $path = Join-Path $env:ProgramFiles $Name
}
if (Test-Path -LiteralPath $path) {
    Write-Host "$path already exists. Not touching it (it may be a real install)." -ForegroundColor Red
    Write-Host 'Use a different name:  .\Make-OpenfireTest.ps1 -Name SomethingElse'
    exit 1
}

function Run-Icacls {
    $out = & icacls.exe @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls failed: $($out -join ' ')" }
}

# ---- 1. fake contents ----
$null = New-Item -ItemType Directory -Path $path -Force
foreach ($d in @('conf', 'lib', 'logs', 'plugins', 'resources\a\b\c')) {
    $null = New-Item -ItemType Directory -Path (Join-Path $path $d) -Force
}
$files = @{
    'README.txt'               = 'TEST FOLDER made by Make-OpenfireTest.ps1. Remove it with Remove-Folder.ps1.'
    'conf\openfire.xml'        = '<jive><!-- test file --></jive>'
    'lib\test.jar'             = 'not a real jar'
    'logs\openfire.log'        = 'test log line'
    'plugins\readme.txt'       = 'test'
    'resources\a\b\c\deep.txt' = 'test'
}
foreach ($k in $files.Keys) {
    Set-Content -LiteralPath (Join-Path $path $k) -Value $files[$k]
}
# one Read-only + Hidden + System file, to test attribute clearing
(Get-Item -LiteralPath (Join-Path $path 'conf\openfire.xml') -Force).Attributes = 'ReadOnly,Hidden,System'

# ---- 2. permissions ----
$SYS = '*S-1-5-18'        # SYSTEM
$ADM = '*S-1-5-32-544'    # Administrators
$USR = '*S-1-5-32-545'    # Users

Run-Icacls $path '/inheritance:r'
Run-Icacls $path '/grant:r' "${SYS}:(OI)(CI)F" "${ADM}:(OI)(CI)RX" "${USR}:(OI)(CI)RX"
Run-Icacls $path '/deny' "${ADM}:(OI)(CI)(D,DC)" "${USR}:(OI)(CI)(D,DC)"
Run-Icacls "$path\*" '/reset' '/T' '/C' '/Q'      # everything inside inherits from the folder
try {
    Run-Icacls $path '/setowner' $SYS '/T' '/C' '/Q'
} catch {
    Write-Host "Warning: could not make SYSTEM the owner ($($_.Exception.Message)). Owner left as Administrators." -ForegroundColor Yellow
}

# ---- 3. show the result ----
Write-Host ''
Write-Host "Created $path" -ForegroundColor Green
try { Write-Host ("Owner: " + (Get-Acl -LiteralPath $path).Owner) } catch {}
& icacls.exe $path
Write-Host ''

# ---- 4. prove an administrator cannot delete it ----
$deleted = $false
try {
    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
    $deleted = $true
} catch {}
$readmeLeft = Test-Path -LiteralPath (Join-Path $path 'README.txt')
if ((-not $deleted) -and $readmeLeft) {
    Write-Host 'Delete test as this administrator: BLOCKED (good).' -ForegroundColor Green
} else {
    Write-Host 'WARNING: an administrator could delete it, so the permissions are not as intended.' -ForegroundColor Red
    if (Test-Path -LiteralPath $path) { Write-Host "Some of it may be left in $path." -ForegroundColor Yellow }
    exit 1
}

Write-Host ''
Write-Host 'Now test the deleter:' -ForegroundColor Yellow
Write-Host "  .\Remove-Folder.ps1 `"$path`""
