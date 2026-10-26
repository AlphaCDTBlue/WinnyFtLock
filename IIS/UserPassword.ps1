# UserPassword.ps1 - run as Administrator.
#   No arguments : sets every non-grey packet user to the hard-coded password
#   -Ask         : prompts you for the new password instead
param([switch]$Ask)

# ===== EDIT THESE TWO LISTS (same lists as UserChecker) =====
$PacketUsers = @(
    'mrkrabs',
    'spongebob',
    'squidward',
    'patrick',
    'sandy',
    'gary',
    'puff',
    'larry',
    'mermaidman',
    'barnacleboy',
    'jellyfish'
)
$GreyTeamUsers = @(
    'kingneptune',
    'paintythepirate',
    'greyteamadmin'
)
# ============================================================
$DefaultPassword = 'Wardontstop1!'

$ErrorActionPreference = 'Continue'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this as Administrator.' -ForegroundColor Red; exit 1 }
if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2) {
    Write-Host 'This is a domain controller - local accounts do not exist here. Aborting.' -ForegroundColor Red; exit 1
}
if (($PacketUsers + $GreyTeamUsers) -match '^REPLACE') {
    Write-Host 'Fill in the user lists at the top first. Aborting.' -ForegroundColor Red; exit 1
}

function ConvertTo-Plain([System.Security.SecureString]$s) {
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

if ($Ask) {
    while ($true) {
        $p1 = Read-Host 'New password' -AsSecureString
        $p2 = Read-Host 'Confirm new password' -AsSecureString
        $a = ConvertTo-Plain $p1
        $b = ConvertTo-Plain $p2
        if ($a.Length -eq 0) { Write-Host 'Password cannot be empty.' -ForegroundColor Yellow; continue }
        if ($a -ceq $b) { $secure = $p1; break }
        Write-Host 'Passwords did not match, try again.' -ForegroundColor Yellow
    }
} else {
    $secure = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force
}

$grey = @{}
foreach ($g in $GreyTeamUsers) { if ($g) { $grey[$g.Trim()] = $true } }

$ok = 0; $bad = 0
foreach ($name in $PacketUsers) {
    if (-not $name -or -not $name.Trim()) { continue }
    $name = $name.Trim()
    if ($grey.ContainsKey($name)) { Write-Host "SKIP  $name (grey team)" -ForegroundColor Yellow; continue }
    $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if (-not $u) { Write-Host "MISS  $name not found on this box" -ForegroundColor Yellow; continue }
    try {
        Set-LocalUser -Name $name -Password $secure -ErrorAction Stop
        Write-Host "OK    $name" -ForegroundColor Green
        $ok++
    } catch {
        Write-Host "FAIL  $name : $($_.Exception.Message)" -ForegroundColor Red
        $bad++
    }
}

Write-Host ''
Write-Host "Changed: $ok   Failed: $bad" -ForegroundColor Cyan
Write-Host 'Active sessions (look for anything you do not recognise):' -ForegroundColor Cyan
& quser 2>$null
