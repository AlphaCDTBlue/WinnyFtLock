# Phase launcher fix 2026-10-26: bundled compatible routines; repo tools remain external.
#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([string]$SiteName='', [string]$HealthUrl='', [switch]$RetryPasswordReset, [switch]$Check)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 as Administrator.'}
$repo=$PSScriptRoot
if((Split-Path $repo -Leaf) -eq 'IIS' -and (Test-Path (Join-Path (Split-Path $repo -Parent) 'general'))){$repo=Split-Path $repo -Parent}
if(-not(Test-Path (Join-Path $repo 'IIS')) -or -not(Test-Path (Join-Path $repo 'general'))){throw 'Put phase_1_fixed.ps1 and phase_2_fixed.ps1 at the cloned repository root.'}
$plan=Join-Path $env:ProgramData 'CDT-IIS-Plan';$statePath=Join-Path $plan 'state.json'
function Plain([string]$Path){$p=[IO.Path]::GetFullPath($Path);while($p){if((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "Reparse point refused: $p"};$p=[IO.Path]::GetDirectoryName($p)}}
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



function Invoke-PhaseLocalPasswordReset {
[CmdletBinding()]
param([Security.SecureString]$NewPassword,[switch]$PassThru)
$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4){throw 'Local password rotation is for member/workgroup hosts; use AD_DNS/rotate.ps1 on the DC.'}
$grey=@('kingneptune','paintythepirate','greyteamadmin')
$targets=@(Get-LocalUser | Where-Object {$_.Enabled -and $_.Name -notin $grey -and $_.SID.Value -notmatch '-(501|503|504)$'})
if(-not $targets.Count){throw 'No enabled non-Grey local accounts found.'}
$services=@(Get-CimInstance Win32_Service)
$tasks=@(Get-ScheduledTask)
$pools=@();$dll="$env:SystemRoot\System32\inetsrv\Microsoft.Web.Administration.dll"
if(Test-Path $dll){
    [void][Reflection.Assembly]::LoadFrom($dll);$manager=New-Object Microsoft.Web.Administration.ServerManager
    try{$pools=@($manager.ApplicationPools|Where-Object {[string]$_.ProcessModel.IdentityType -eq 'SpecificUser'}|ForEach-Object {$_.ProcessModel.UserName})}finally{$manager.Dispose()}
}
foreach($u in $targets){
    $names=@("$env:COMPUTERNAME\$($u.Name)",".\$($u.Name)")
    if(@($pools|Where-Object {$_ -in $names}).Count -or @($tasks|Where-Object {$_.Principal.LogonType -eq 'Password' -and $_.Principal.UserId -in @($names + $u.SID.Value)}).Count){throw "Account $($u.Name) has a stored task/app-pool credential; update that dependency before rotation. No passwords changed."}
    if(@($services | Where-Object StartName -in $names).Count){throw "Account $($u.Name) runs a service; review its dependent credentials before rotation. No passwords changed."}
}
$current=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$targets=@($targets|Sort-Object {$_.SID.Value -eq $current},Name)
Write-Host ('Local accounts to rotate (current operator last): '+(($targets|ForEach-Object Name)-join ', '))
Write-Host 'Grey accounts, account membership, and AD passwords are retained. No accounts are created or deleted.'
if(-not $NewPassword){
    $NewPassword=Read-Host 'New LOCAL Windows password' -AsSecureString
    $confirm=Read-Host 'Confirm new LOCAL Windows password' -AsSecureString
    try{
        $a=[pscredential]::new('x',$NewPassword).GetNetworkCredential().Password
        $b=[pscredential]::new('x',$confirm).GetNetworkCredential().Password
        if(-not $a -or $a -cne $b){throw 'Passwords were blank or did not match. Nothing changed.'}
    }finally{$a=$null;$b=$null;$confirm.Dispose()}
}
$done=@()
try{
    foreach($u in $targets){Set-LocalUser -SID $u.SID -Password $NewPassword -ErrorAction Stop;$done+=$u.Name;Write-Host "Rotated: $($u.Name)"}
}catch{throw "Local rotation stopped: $($_.Exception.Message). Already reset: $($done -join ', '). Verify credentials before retrying."}
if($PassThru){[pscustomobject]@{Success=$true;Scope='Local';ResetAccounts=$done;GreyExcluded=$grey;CurrentAccountChanged=(@($targets|Where-Object {$_.SID.Value -eq $current}).Count -gt 0)}}
}

function Invoke-PhaseSessionSignout {
[CmdletBinding()]
param([string[]]$GreyAccounts=@('kingneptune','paintythepirate','greyteamadmin'))
$ErrorActionPreference='Stop'
if(-not ('CDTSessionRevoke' -as [type])){
Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Runtime.InteropServices;using System.Security.Principal;
public static class CDTSessionRevoke {
 [StructLayout(LayoutKind.Sequential)] struct Info{public int Id;public IntPtr Name;public int State;}
 [DllImport("wtsapi32.dll",EntryPoint="WTSEnumerateSessionsW",SetLastError=true)]static extern bool Enum(IntPtr h,int r,int v,out IntPtr p,out int n);
 [DllImport("wtsapi32.dll",EntryPoint="WTSQuerySessionInformationW",SetLastError=true)]static extern bool Query(IntPtr h,int id,int c,out IntPtr p,out int n);
 [DllImport("wtsapi32.dll")]static extern void WTSFreeMemory(IntPtr p);
 [DllImport("wtsapi32.dll",SetLastError=true)]public static extern bool WTSLogoffSession(IntPtr h,int id,bool wait);
 public sealed class Session{public int Id;public string Account,Name,Sid;}
 static string Text(int id,int cls){IntPtr p;int n;if(!Query(IntPtr.Zero,id,cls,out p,out n))throw new System.ComponentModel.Win32Exception();try{return Marshal.PtrToStringUni(p)??"";}finally{WTSFreeMemory(p);}}
 public static Session[] Sessions(){IntPtr p;int n;if(!Enum(IntPtr.Zero,0,1,out p,out n))throw new System.ComponentModel.Win32Exception();var result=new List<Session>();try{int size=Marshal.SizeOf(typeof(Info));for(int i=0;i<n;i++){var row=(Info)Marshal.PtrToStructure(IntPtr.Add(p,i*size),typeof(Info));if(row.Id==0)continue;string user=Text(row.Id,5),domain=Text(row.Id,7);if(user.Length==0)continue;string sid=((SecurityIdentifier)new NTAccount(domain,user).Translate(typeof(SecurityIdentifier))).Value;result.Add(new Session{Id=row.Id,Name=user,Account=domain+"\\"+user,Sid=sid});}}finally{WTSFreeMemory(p);}return result.ToArray();}
}
'@
}
$current=(Get-Process -Id $PID).SessionId
# Query every session identity before terminating anything; errors stop the sweep.
$all=@([CDTSessionRevoke]::Sessions());$selected=@($all|Where-Object {$_.Name -notin $GreyAccounts}|Sort-Object {$_.Id -eq $current},Id)
Write-Host ('Preserved Grey sessions: '+(($all|Where-Object {$_.Name -in $GreyAccounts}|ForEach-Object Account)-join ', '))
# Close user-owned sshd children, retaining the SYSTEM listener and Grey transports.
$ssh=Get-CimInstance Win32_Service -Filter "Name='sshd'"
if($ssh -and $ssh.State -eq 'Running'){
    foreach($p in Get-CimInstance Win32_Process -Filter "Name='sshd.exe'"){
        if($p.ProcessId -eq $ssh.ProcessId){continue}
        $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwner
        if($owner.ReturnValue -ne 0){throw 'An SSH process owner could not be verified; session revocation stopped.'}
        if($owner.User -in @('SYSTEM','LOCAL SERVICE','NETWORK SERVICE') -or $owner.User -in $GreyAccounts){continue}
        $fresh=Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ProcessId)"
        if(-not $fresh -or $fresh.CreationDate -ne $p.CreationDate){continue}
        Stop-Process -Id $p.ProcessId -Force
    }
}
foreach($s in $selected){
    $fresh=@([CDTSessionRevoke]::Sessions()|Where-Object {$_.Id -eq $s.Id -and $_.Sid -eq $s.Sid})
    if(-not $fresh.Count){continue}
    Write-Host "Signing out $($s.Account) (session $($s.Id)); your own session is last."
    if(-not [CDTSessionRevoke]::WTSLogoffSession([IntPtr]::Zero,$s.Id,$false)){throw "Session $($s.Id) logoff failed."}
}
}

function Test-PhaseDependencies {
    $watchFile=IisFile 'watchdogsgit';$sessionFile=IisFile 'new_session'
    $required=@($watchFile,$sessionFile,(RepoFile 'general\upkeep\Deploy-BlueOps.ps1'),(RepoFile 'general\upkeep\Svcwithme.ps1'),(RepoFile 'general\checker\Watch-Baseline.ps1'),(RepoFile 'terminal_sessions\logging.ps1'))
    foreach($path in $required){
        $tokens=$null;$errors=$null
        $null=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
        if($errors.Count){throw "PowerShell syntax error in $path : $($errors[0].Message)"}
    }
    foreach($p in @('Action','ServiceController')){if(-not(Get-Command $watchFile).Parameters.ContainsKey($p)){throw "IIS watchdog lacks required parameter $p."}}
    foreach($p in @('Action','GreyAccounts','Services')){if(-not(Get-Command $sessionFile).Parameters.ContainsKey($p)){throw "IIS session guard lacks required parameter $p."}}
    foreach($name in @('baseline-processes.csv','baseline-services.csv')){[void](RepoFile ('general\checker\'+$name))}
}
Test-PhaseDependencies
if($Check){Write-Host 'Phase dependency check passed. No configuration, credentials or sessions were changed.';return}
Plain $plan;New-Item -ItemType Directory $plan -Force|Out-Null
& "$env:SystemRoot\System32\icacls.exe" $plan /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null
if($LASTEXITCODE){throw 'Cannot secure phase state directory.'}
Get-ChildItem -LiteralPath $repo -Recurse -File|Unblock-File

$watch=IisFile 'watchdogsgit';$blue=RepoFile 'general\upkeep\Deploy-BlueOps.ps1';$control=RepoFile 'general\upkeep\Svcwithme.ps1'
if(-not(Get-Command $watch).Parameters.ContainsKey('ServiceController')){throw 'Install the standalone watchdog version that supports Setup and ServiceController.'}
if((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4){throw 'These are IIS launchers, not domain-controller launchers.'}
$state=ReadState
if(-not $state){$state=[pscustomobject]@{Phase1Logon=(LogonKey);Version=1;Computer=$env:COMPUTERNAME;Repo=$repo;Phase1Complete=$false;PasswordResetStarted=$false;ResetAccounts=@();ToolsDone=$false;RebootPending=$false;ToolsBoot='';Phase2Complete=$false}}
if($state.Phase1Complete){Write-Host 'Phase 1 is complete. Sign out of Windows if you have not already done so, then log back in and run phase_2_fixed.ps1.';return}
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
$result=@(Invoke-PhaseLocalPasswordReset -PassThru|Where-Object {$_.PSObject.Properties['Success']})
if($result.Count -ne 1 -or -not $result[0].Success){throw 'Password rotation did not return a successful result. Sessions were not revoked.'}
$state.ResetAccounts=@($result[0].ResetAccounts);$state.Phase1Complete=$true;SaveState
Write-Host '4. Phase 1 complete. Keep the new password available; signing out non-Grey sessions now.'
Invoke-PhaseSessionSignout -GreyAccounts @('kingneptune','paintythepirate','greyteamadmin')|Out-Host
Write-Host 'Log back in and run .\phase_2_fixed.ps1.'
