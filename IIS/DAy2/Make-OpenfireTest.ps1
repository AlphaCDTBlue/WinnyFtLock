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
    $ErrorActionPreference = 'Continue'     # icacls text on stderr must not abort the script
    $out = & icacls.exe @args 2>&1
    if ($LASTEXITCODE -ne 0) {
        $msg = ($out | ForEach-Object { [string]$_ }) -join ' '
        throw "icacls failed: $msg"
    }
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

# The same permissions are written onto every file and folder directly (no
# inheritance tricks). BA = Administrators, BU = Users, SY = SYSTEM.
#   deny: delete (SD) and delete-child (DC) for Administrators and Users
#   allow: SYSTEM full control, Administrators and Users read + execute
$dirSddl  = 'D:P(D;OICI;SDDC;;;BA)(D;OICI;SDDC;;;BU)(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BA)(A;OICI;FRFX;;;BU)'
$fileSddl = 'D:P(D;;SDDC;;;BA)(D;;SDDC;;;BU)(A;;FA;;;SY)(A;;FRFX;;;BA)(A;;FRFX;;;BU)'

function Set-Dacl([string]$p, [bool]$isDir) {
    if ($isDir) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $sddl = $dirSddl
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $sddl = $fileSddl
    }
    $acl.SetSecurityDescriptorSddlForm($sddl, [System.Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $p -AclObject $acl
}

try {
    # list everything first, while we still have full access
    $allDirs  = @(Get-ChildItem -LiteralPath $path -Recurse -Force -Directory | Sort-Object { $_.FullName.Length } -Descending | ForEach-Object { $_.FullName })
    $allFiles = @(Get-ChildItem -LiteralPath $path -Recurse -Force -File | ForEach-Object { $_.FullName })

    foreach ($f in $allFiles) { Set-Dacl $f $false }    # files first
    foreach ($d in $allDirs)  { Set-Dacl $d $true }     # then folders, deepest first
    Set-Dacl $path $true                                 # the top folder last
} catch {
    Write-Host "ERROR setting permissions: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "$path was left half set up. Remove it with:  .\Remove-Folder.ps1 `"$path`"" -ForegroundColor Red
    exit 1
}

# owner = SYSTEM (icacls does this because it needs a privilege). Not fatal if it fails.
$ownerFailed = $false
foreach ($p in (@($allFiles) + @($allDirs) + @($path))) {
    try { Run-Icacls $p '/setowner' $SYS '/C' '/Q' } catch { $ownerFailed = $true }
}
if ($ownerFailed) {
    Write-Host 'Warning: could not make SYSTEM the owner of everything. Owner left as Administrators.' -ForegroundColor Yellow
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
