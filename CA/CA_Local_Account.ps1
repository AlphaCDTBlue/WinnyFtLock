# Windows Server 2019 CA: local account audit and approved password rotation
# Run in elevated Windows PowerShell 5.1.
# Usage: .\CA_Local_Account_Audit.ps1 [-RotateApprovedPasswords]
[CmdletBinding()]
param([switch]$RotateApprovedPasswords)
$ErrorActionPreference = 'Stop'
$logDir = 'C:\BlueTeam\Logs'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir ('CA_Local_Account_Audit_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
function Write-Audit([string]$Message) {
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -LiteralPath $log -Value $line
    Write-Host $line
}
# Snapshot names from supplied original screenshot plus the expected domain Blue Team list.
$originalLocal = @('Admin','Administrator','cloudbase-init','DefaultAccount','greyteamadmin','Guest','jellyfish','WDAGUtilityAccount')
$expectedBlue = @('Mrkrabs','Spongebob','Squidward','Patrick','Sandy','gary','puff','larry','mermaidman','barnacleboy','jellyfish')
$protectedGrey = @('kingneptune','paintythepirate','greyteamadmin')
$expected = @($originalLocal + $expectedBlue + $protectedGrey) | Select-Object -Unique
Write-Audit "Started local account audit on $env:COMPUTERNAME. RotationRequested=$RotateApprovedPasswords"
$users = @()
$usersAvailable = $false
try {
    $users = @(Get-LocalUser)
    $usersAvailable = $true
    Write-Audit ('Local account count: {0}' -f $users.Count)
    foreach ($user in $users) {
        if ($user.Name -notin $expected) {
            Write-Audit "UNEXPECTED LOCAL USER: $($user.Name) (enabled=$($user.Enabled))"
        }
    }
} catch {
    Write-Audit "ERROR during local user inventory; continuing with remaining checks: $($_.Exception.Message)"
}
Write-Audit 'Grey Team accounts and groups will not be modified.'
try {
    $adminGroup = Get-LocalGroup -ErrorAction Stop |
        Where-Object { $_.SID.Value -eq 'S-1-5-32-544' } |
        Select-Object -First 1
    if (-not $adminGroup) {
        Write-Audit 'Administrators group not found; skipping group-member check.'
    } else {
        $members = @(Get-LocalGroupMember -Group $adminGroup.Name -ErrorAction Stop)
        foreach ($member in $members) {
            Write-Audit "ADMIN GROUP MEMBER: $($member.Name)"
        }
    }
} catch {
    Write-Audit "ERROR during Administrators group check; continuing: $($_.Exception.Message)"
}
if ($RotateApprovedPasswords -and -not $usersAvailable) {
    Write-Audit 'SKIPPED password rotation because local user inventory failed.'
} elseif ($RotateApprovedPasswords) {
    # Only explicit, authorized local account allowlist. Never domain accounts.
    $rotationTargets = @('Administrator','Admin','jellyfish')
    $oldPassword = Read-Host 'Enter old password to verify for each eligible account' -AsSecureString
    $newPassword = Read-Host 'Enter replacement password' -AsSecureString
    try {
        $oldBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($oldPassword)
        try { $oldPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($oldBstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($oldBstr) }
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $env:COMPUTERNAME)
        try {
            foreach ($name in $rotationTargets) {
                if ($name -in $protectedGrey) { continue }
                $user = $users | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
                if (-not $user) { Write-Audit "SKIPPED missing local account: $name"; continue }
                if (-not $user.Enabled) { Write-Audit "SKIPPED disabled local account: $name"; continue }
                try {
                    if (-not $ctx.ValidateCredentials($name, $oldPlain)) {
                        Write-Audit "SKIPPED old password did not match for local account: $name"
                        continue
                    }
                    Set-LocalUser -Name $name -Password $newPassword -ErrorAction Stop
                    Write-Audit "PASSWORD CHANGED successfully for local account: $name"
                } catch {
                    Write-Audit "ERROR changing local password for ${name}: $($_.Exception.Message)"
                }
            }
        } finally { $ctx.Dispose() }
    } finally {
        $oldPlain = $null
        $oldPassword.Dispose()
        $newPassword.Dispose()
    }
}
Write-Audit 'Account audit completed.'
Write-Host "Log saved: $log"
