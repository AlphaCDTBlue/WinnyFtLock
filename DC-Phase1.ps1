#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$Check, [switch]$RevokeOnly)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess) { throw 'Use elevated 64-bit Windows PowerShell 5.1.' }
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { throw 'This launcher is for the DC only.' }
Import-Module ActiveDirectory
$domain = Get-ADDomain -Server $env:COMPUTERNAME
$repo = $PSScriptRoot
$store = Join-Path $env:ProgramData 'CDT-DC-Start'
$stateFile = Join-Path $store 'phase1.xml'
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
function RepoFile([string]$Relative) {
    $path = Join-Path $repo $Relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing $path. Put BOTH launchers at the extracted repo root." }
    return $path
}
function Run([string]$Relative, [string]$Arguments = '') {
    $path = RepoFile $Relative
    Write-Host "`nRUNNING: $Relative. Waiting for this script to exit." -ForegroundColor Cyan
    # Separate process prevents child 'exit', types and variables from breaking the launcher.
    $quoted = "'" + $path.Replace("'", "''") + "'"
    $command = "`$ErrorActionPreference='Stop'; try { & $quoted $Arguments } catch { Write-Host (`$_ | Out-String) -ForegroundColor Red; Read-Host 'Failed - press Enter to return to launcher'; exit 1 }"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $child = Start-Process -FilePath $ps -ArgumentList "-NoLogo -NoProfile -STA -ExecutionPolicy Bypass -EncodedCommand $encoded" -WorkingDirectory $repo -Wait -PassThru
    if ($child.ExitCode -ne 0) { throw "$Relative exited with code $($child.ExitCode). Stopped; review its output." }
    Write-Host "RETURNED: $Relative (exit 0; verify any tool-reported errors)." -ForegroundColor Cyan
}
function Read-State {
    if (-not (Test-Path $stateFile)) { throw 'Run DC-Phase1.ps1 first.' }
    $s = Import-Clixml $stateFile
    if ($s.Computer -ine $env:COMPUTERNAME -or $s.DomainSID -ne $domain.DomainSID.Value) { throw 'Phase state belongs to another host/domain.' }
    return $s
}
function Check-Baselines {
    $ad = Join-Path $env:ProgramData 'AD-DisabledWatch\baseline.xml'
    $dns = Join-Path $env:ProgramData 'DNS-Guard\active.xml'
    if (-not (Test-Path $ad) -or -not (Test-Path $dns)) { throw 'Both accepted baselines are required; a cancelled dialog does not count.' }
    $a=Import-Clixml $ad; $d=Import-Clixml $dns
    if ($a.DomainSID -ne $domain.DomainSID.Value -or $a.DC -ine $env:COMPUTERNAME -or $d.Server -ine $env:COMPUTERNAME) { throw 'Baseline identity mismatch.' }
    if (-not (Test-Path (Join-Path $d.Folder 'snapshot.xml'))) { throw 'DNS inventory snapshot is missing.' }
}
$required = @('AD_DNS\rotate.ps1','AD_DNS\AD-Guard.ps1','AD_DNS\DNS-Guard.ps1','general\upkeep\Deploy-BlueOps.ps1','general\sessionrevokewin.ps1')
foreach ($relative in $required) {
    $path=RepoFile $relative
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw "Syntax error in ${relative}: $($errors[0].Message)" }
}
if ($Check) { Write-Host 'DC identity, required paths and PowerShell syntax checked. No changes made.'; return }

if (-not $RevokeOnly -and -not (Test-Path $stateFile)) {
    New-Item -ItemType Directory -Path $store -Force | Out-Null
    & icacls.exe $store /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE) { throw 'Could not secure launcher backup directory.' }
    $backup=Join-Path $store ('before-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    New-Item -ItemType Directory -Path $backup | Out-Null
    $services=@('NTDS','DNS','openfire','inetd','W3SVC','CertSvc')
    foreach ($name in $services) {
        $svc=Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $lines=@(& sc.exe sdshow $name 2>&1)
        if ($LASTEXITCODE) { throw "Cannot back up service ACL: $name" }
        $sddl=($lines | Where-Object { [string]$_ -match '^[OGDS]:' }) -join ''
        if (-not $sddl) { throw "No SDDL returned for $name" }
        Set-Content -LiteralPath (Join-Path $backup "$name.sddl.txt") -Value $sddl -Encoding ASCII
        & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Services\$name" (Join-Path $backup "$name.reg") /y | Out-Null
        if ($LASTEXITCODE) { throw "Cannot back up service registry: $name" }
        $svc | Select-Object Name,Status,StartType | Export-Clixml (Join-Path $backup "$name.state.xml")
    }
    Write-Host "Service configuration backup: $backup"
    Write-Host 'AD guard: review/accept baseline. Once Watching appears, press Q in ITS console. Existing valid baseline is reused; B updates it deliberately.' -ForegroundColor Yellow
    Run 'AD_DNS\AD-Guard.ps1'
    if (-not (Test-Path "$env:ProgramData\AD-DisabledWatch\baseline.xml")) { throw 'AD baseline was not accepted.' }
    Write-Host 'DNS guard: review/accept baseline, then Q in ITS console after the watcher starts.' -ForegroundColor Yellow
    Run 'AD_DNS\DNS-Guard.ps1'
    Check-Baselines
    # This folder hosts a SYSTEM worker: do not leave it writable by ordinary users.
    if ((Test-Path 'C:\BlueOps') -and ((Get-Item 'C:\BlueOps' -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'C:\BlueOps is a reparse point.' }
    New-Item -ItemType Directory -Path 'C:\BlueOps' -Force | Out-Null
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath 'C:\BlueOps' -AclObject $acl
    Run 'general\upkeep\Deploy-BlueOps.ps1'
    foreach ($name in $services) {
        if (-not (Get-Service $name -ErrorAction SilentlyContinue)) { continue }
        $sddl=(& sc.exe sdshow $name) -join ''
        if ($LASTEXITCODE -or -not $sddl.Contains('(D;;DCWPDTSD;;;AU)')) { throw "BlueOps service ACL did not verify: $name. Backup: $backup" }
        $props=Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        if (-not $props.FailureActions -or $props.FailureActionsOnNonCrashFailures -ne 1) { throw "Recovery settings absent for $name; inspect sc.exe qfailure $name." }
        & sc.exe qfailure $name | Out-Host
    }
    foreach ($name in @('NTDS','DNS')) {
        if ((Get-Service $name).Status -ne 'Running') { throw "$name is not running. Stop and investigate." }
    }
    [pscustomobject]@{Computer=$env:COMPUTERNAME;DomainSID=$domain.DomainSID.Value;Backup=$backup;Completed=Get-Date;PasswordsConfirmed=$false} | Export-Clixml $stateFile
}
$state=Read-State
if (-not $RevokeOnly -and -not $state.PasswordsConfirmed) {
    Write-Host 'Starting the password reset tool. Choose accounts, enter passwords, and read its result summary.' -ForegroundColor Cyan
    Write-Host 'rotate.ps1 must have the correct domain/DC/account list for this competition.' -ForegroundColor Yellow
    Run 'AD_DNS\rotate.ps1'
    # The repo rotator can return normally after cancellation or partial failure.
    # Exit zero alone therefore cannot prove that all requested passwords changed.
    if ((Read-Host 'If ALL intended resets succeeded, type DONE; otherwise Enter to stop') -cne 'DONE') {
        Write-Host 'Stopped. Review reset results before rerunning Phase 1; setup backups are retained.'
        return
    }
    $state.PasswordsConfirmed=$true
    $state | Export-Clixml $stateFile
}
if (-not $state.PasswordsConfirmed) { throw 'Complete password rotation through DC-Phase1.ps1 before revoking sessions.' }
Write-Host 'Phase 1 setup and password-reset handoff complete. Test a fresh login with the new password.' -ForegroundColor Cyan
Write-Host 'REVOKE signs out ALL local interactive sessions, including you and Grey/team sessions, and attempts SSH termination.' -ForegroundColor Yellow
$answer=Read-Host 'Type REVOKE when ready to sign out; Enter to stop here'
if ($answer -cne 'REVOKE') { Write-Host 'Later: .\DC-Phase1.ps1 -RevokeOnly. After relogin: .\DC-Phase2.ps1'; return }
Write-Host 'Log back in, then run DC-Phase2.ps1.'
Run 'general\sessionrevokewin.ps1'
