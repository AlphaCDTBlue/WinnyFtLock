#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([string]$SiteName='', [string]$HealthUrl='', [switch]$RetryPasswordReset)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 as Administrator.'}
$repo=$PSScriptRoot
if(-not(Test-Path (Join-Path $repo 'IIS')) -or -not(Test-Path (Join-Path $repo 'general'))){throw 'Put phase_1.ps1 and phase_2.ps1 at the cloned repository root.'}
$plan=Join-Path $env:ProgramData 'CDT-IIS-Plan';$statePath=Join-Path $plan 'state.json'
function Plain([string]$Path){$p=[IO.Path]::GetFullPath($Path);while($p){if((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "Reparse point refused: $p"};$p=[IO.Path]::GetDirectoryName($p)}}
Plain $plan;New-Item -ItemType Directory $plan -Force|Out-Null
& "$env:SystemRoot\System32\icacls.exe" $plan /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null
if($LASTEXITCODE){throw 'Cannot secure phase state directory.'}
function RepoFile([string]$Relative){$p=Join-Path $repo $Relative;Plain $p;if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw "Missing repo file: $Relative"};return $p}
function IisFile([string]$Name){
    $canonical=Join-Path $repo "IIS\$Name.ps1"
    if(Test-Path -LiteralPath $canonical){Plain $canonical;return $canonical}
    $candidates=@(Get-ChildItem -LiteralPath (Join-Path $repo 'IIS') -File|Where-Object {$_.Name -match ('^'+[regex]::Escape($Name)+'(?: \(\d+\))?\.ps1$')})
    if($candidates.Count -ne 1){throw "Expected one IIS/$Name.ps1 (or one numbered downloaded copy)."}
    Plain $candidates[0].FullName;return $candidates[0].FullName
}
function SaveState {
    Plain "$statePath.tmp"
    $state|ConvertTo-Json -Depth 8|Set-Content -LiteralPath "$statePath.tmp" -Encoding UTF8
    Move-Item -LiteralPath "$statePath.tmp" -Destination $statePath -Force
}
function CallScript([string]$Path,[hashtable]$Arguments=@{}){
    $global:LASTEXITCODE=0
    $result=@(& $Path @Arguments)
    if($LASTEXITCODE){throw "$Path failed (native exit $LASTEXITCODE)."}
    return $result
}
function LogonKey {
    if(-not ('CDTPhaseLogon' -as [type])){
        Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using System.Security.Principal;
public static class CDTPhaseLogon {
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr t,int c,IntPtr p,int n,out int required);
 public static string Key(){using(var id=WindowsIdentity.GetCurrent()){IntPtr p=Marshal.AllocHGlobal(128);try{int needed;if(!GetTokenInformation(id.Token,10,p,128,out needed))throw new System.ComponentModel.Win32Exception();return id.User.Value+":"+Marshal.ReadInt64(p,8).ToString("X");}finally{Marshal.FreeHGlobal(p);}}}
}
'@
    }
    ([CDTPhaseLogon]::Key())+':'+((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString())
}
function ReadState {
    if(-not(Test-Path $statePath)){return $null}
    Plain $statePath;$s=Get-Content $statePath -Raw|ConvertFrom-Json
    if($s.Computer -ine $env:COMPUTERNAME -or $s.Repo -ine $repo){throw 'Phase state belongs to another host/repo; do not overwrite it.'}
    return $s
}
Get-ChildItem -LiteralPath $repo -Recurse -File|Unblock-File

$watch=IisFile 'watchdogsgit';$blue=RepoFile 'general\upkeep\Deploy-BlueOps.ps1';$control=RepoFile 'general\upkeep\Svcwithme.ps1'
$reset=RepoFile 'general\Reset-Passwords.ps1';$revoke=RepoFile 'general\sessionrevokewin.ps1'
if(-not(Get-Command $watch).Parameters.ContainsKey('ServiceController')){throw 'Install the standalone watchdog version that supports Setup and ServiceController.'}
if(-not(Get-Command $reset).Parameters.ContainsKey('PassThru')){throw 'Copy the corrected general/Reset-Passwords.ps1 from the walkthrough package before running Phase 1.'}
if(-not(Get-Command $revoke).Parameters.ContainsKey('GreyAccounts')){throw 'Copy the Grey-aware general/sessionrevokewin.ps1 from the walkthrough package before running Phase 1.'}
if((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4){throw 'These are IIS launchers, not domain-controller launchers.'}
$state=ReadState
if(-not $state){$state=[pscustomobject]@{Phase1Logon=(LogonKey);Version=1;Computer=$env:COMPUTERNAME;Repo=$repo;Phase1Complete=$false;PasswordResetStarted=$false;ResetAccounts=@();ToolsDone=$false;RebootPending=$false;ToolsBoot='';Phase2Complete=$false}}
if($state.Phase1Complete){Write-Host 'Phase 1 is complete. Run general/sessionrevokewin.ps1 if you have not signed out, then log back in and run phase_2.ps1.';return}
if($state.PasswordResetStarted -and -not $RetryPasswordReset){throw 'A previous password reset was interrupted/uncertain. Verify the changed credentials, then explicitly use -RetryPasswordReset if rotation must be repeated.'}
$siteArgs=@{};if($SiteName){$siteArgs.SiteName=$SiteName};if($HealthUrl){$siteArgs.HealthUrl=$HealthUrl}
Write-Host 'Enabling repo PowerShell transcript policy.'
if(Test-Path (Join-Path $repo 'terminal_sessions\logging.ps1')){CallScript (RepoFile 'terminal_sessions\logging.ps1')|Out-Host}
elseif(Test-Path (Join-Path $repo 'tt')){$logging=RepoFile 'tt';& ([scriptblock]::Create((Get-Content -LiteralPath $logging -Raw)))}
else{throw 'Transcription script missing: expected terminal_sessions/logging.ps1.'}
Write-Host '1. Checking IIS and creating/preserving the approved baseline.'
$pre=((CallScript $watch (@{Action='Preflight'}+$siteArgs))-join "`n")|ConvertFrom-Json
if(-not $pre.Ready){throw ($pre.Problems -join '; ')}
$existing=Join-Path $env:ProgramData 'watchdogs\settings.json'
if(-not(Test-Path $existing)){CallScript $watch (@{Action='Baseline'}+$siteArgs)|Out-Host}
Write-Host '2. Installing BlueOps, then starting and verifying the IIS watchdog.'
CallScript $blue|Out-Host
$acl=(& "$env:SystemRoot\System32\sc.exe" sdshow W3SVC) -join ' '
if($LASTEXITCODE -or -not $acl.Contains('(D;;DCWPDTSD;;;AU)')){throw 'BlueOps IIS lock did not verify; passwords were not changed.'}
CallScript $watch (@{Action='Setup';ServiceController=$control}+$siteArgs)|Out-Host
$health=((CallScript $watch @{Action='Status'})-join "`n")|ConvertFrom-Json
if(-not $health.Healthy -or -not $health.RecoveryActive){throw 'Watchdog did not report healthy automatic recovery. Passwords were not changed.'}
if((Get-CimInstance Win32_ComputerSystem).PartOfDomain){
    if((Read-Host 'Wait for the AD/DNS operator to finish domain password rotation, then type READY') -cne 'READY'){throw 'Stopped before local rotation and sign-out; domain-password handoff was not confirmed.'}
}
$state.PasswordResetStarted=$true;SaveState
Write-Host '3. Rotating existing enabled non-Grey LOCAL users. AD rotation is done once by the AD/DNS operator.'
$result=@(CallScript $reset @{PassThru=$true}|Where-Object {$_.PSObject.Properties['Success']})
if($result.Count -ne 1 -or -not $result[0].Success){throw 'Password rotation did not return a successful result. Sessions were not revoked.'}
$state.ResetAccounts=@($result[0].ResetAccounts);$state.Phase1Complete=$true;SaveState
Write-Host '4. Phase 1 complete. Keep the new password available; signing out non-Grey sessions now.'
CallScript $revoke @{GreyAccounts=@('kingneptune','paintythepirate','greyteamadmin')}|Out-Host
Write-Host 'Log back in and run .\phase_2.ps1.'
