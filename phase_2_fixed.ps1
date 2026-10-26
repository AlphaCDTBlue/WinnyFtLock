# Phase launcher fix 2026-10-26: bundled compatible routines; repo tools remain external.
#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$SkipToolkit, [ValidateSet('Rdp','Ssh','WinRm')][string[]]$SessionServices=@('Rdp','Ssh','WinRm'), [switch]$Check)
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



function Invoke-PhaseToolkit {
[CmdletBinding()]
param([string]$ToolsDir='C:\Tools',[switch]$PassThru)
$ErrorActionPreference='Stop'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
function PendingReboot {
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
    [bool]@((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations | Where-Object {$_})
}
function Finish([bool]$Complete,[bool]$Reboot) {
    if($PassThru){[pscustomobject]@{Success=$true;Completed=$Complete;RebootRequired=$Reboot;ToolsDir=$ToolsDir}}
    else{Write-Host "Toolkit complete=$Complete reboot required=$Reboot"}
}
function Download([string]$Url,[string]$Path){Invoke-WebRequest $Url -UseBasicParsing -OutFile $Path}
function Installer([string]$Path,[string]$Arguments=''){
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    if($signature.Status -ne 'Valid'){throw "Installer signature is not Valid: $Path"}
    $args=@{FilePath=$Path;Wait=$true;PassThru=$true};if($Arguments){$args.ArgumentList=$Arguments}
    $p=Start-Process @args
    if($p.ExitCode -notin @(0,3010,350)){throw "Installer failed/cancelled: $Path (exit $($p.ExitCode))"}
    return $p.ExitCode
}
New-Item -ItemType Directory -Path $ToolsDir -Force|Out-Null
$downloads=Join-Path $env:ProgramData 'CDT-IIS-Plan\downloads'
New-Item -ItemType Directory -Path $downloads -Force|Out-Null
if(-not(Get-Service npcap -ErrorAction SilentlyContinue)){
    $file=Join-Path $downloads 'npcap.exe';Download 'https://npcap.com/dist/npcap-1.90.exe' $file
    Write-Host 'Complete the free Npcap wizard. Silent /S installation requires Npcap OEM.'
    $exit=Installer $file
    if($exit -in @(3010,350)){Finish $false $true;return}
    if(-not(Get-Service npcap -ErrorAction SilentlyContinue)){throw 'Npcap service not found after installer success.'}
}
if(-not(Test-Path 'C:\Program Files\Wireshark\Wireshark.exe')){
    $file=Join-Path $downloads 'wireshark.exe';Download 'https://www.wireshark.org/download/win64/Wireshark-latest-x64.exe' $file
    $exit=Installer $file '/S'
    if($exit -ne 0){Finish $false $true;return}
    if(-not(Test-Path 'C:\Program Files\Wireshark\Wireshark.exe')){throw 'Wireshark executable missing after installation.'}
}
$sys=Join-Path $ToolsDir 'Sysinternals'
if(-not(Test-Path (Join-Path $sys 'Autoruns64.exe'))){
    $zip=Join-Path $downloads 'sysinternals.zip';Download 'https://download.sysinternals.com/files/SysinternalsSuite.zip' $zip
    Expand-Archive -LiteralPath $zip -DestinationPath $sys -Force
}
if(-not(Test-Path (Join-Path $sys 'Autoruns64.exe'))){throw 'Sysinternals extraction did not produce Autoruns64.exe.'}
foreach($exe in Get-ChildItem -LiteralPath $sys -Filter *.exe){
    if((Get-AuthenticodeSignature -LiteralPath $exe.FullName).Status -ne 'Valid'){throw "Sysinternals signature is not Valid: $($exe.Name)"}
    $key="HKCU:\Software\Sysinternals\$($exe.BaseName)";New-Item $key -Force|Out-Null;Set-ItemProperty $key -Name EulaAccepted -Value 1 -Type DWord
}
Finish $true (PendingReboot)
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

$state=ReadState
if(-not $state -or -not $state.Phase1Complete){throw 'Complete phase_1_fixed.ps1 and log back in before Phase 2.'}
if(-not $state.PSObject.Properties['Phase1Logon'] -or $state.Phase1Logon -eq (LogonKey)){throw 'Log off and log back in with the new Windows credentials before Phase 2.'}
$watch=IisFile 'watchdogsgit';$session=IisFile 'new_session';$checker=RepoFile 'general\checker\Watch-Baseline.ps1'
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
if($state.RebootPending){
    if($state.ToolsBoot -eq $boot){Write-Host 'Toolkit requested a reboot. Restart Windows, log back in, then rerun .\phase_2_fixed.ps1.';return}
    $state.RebootPending=$false;SaveState
}
if(-not $state.ToolsDone -and -not $SkipToolkit){
    Write-Host '1. Installing toolkit in the foreground. The free Npcap installer needs its normal wizard.'
    $result=@(Invoke-PhaseToolkit -PassThru|Where-Object {$_.PSObject.Properties['Success']})
    if($result.Count -ne 1 -or -not $result[0].Success){throw 'Toolkit installation was not verified.'}
    $state.ToolsDone=[bool]$result[0].Completed;$state.RebootPending=[bool]$result[0].RebootRequired;$state.ToolsBoot=$boot;SaveState
    if($state.RebootPending){Write-Host 'Reboot required. Restart Windows, log back in, then rerun .\phase_2_fixed.ps1. NewSession has not been installed yet.';return}
}
Write-Host '2. Installing/checking separate-password verification for new sessions.'
$task=Get-ScheduledTask -TaskName 'NewSession-Guard' -TaskPath '\' -ErrorAction SilentlyContinue
if(-not $task){CallScript $session @{Action='Install';GreyAccounts=@('kingneptune','paintythepirate','greyteamadmin');Services=$SessionServices}|Out-Host}
$sessionState=@(CallScript $session @{Action='Status'}|Where-Object {$_.PSObject.Properties['Healthy']})
if($sessionState.Count -ne 1 -or -not $sessionState[0].Healthy){throw 'NewSession is not healthy. Keep console access and inspect its Status.'}
foreach($grey in @('kingneptune','paintythepirate','greyteamadmin')){
    if(-not @($sessionState[0].GreyAccounts|Where-Object {(($_ -split '\\')[-1]) -ieq $grey}).Count){throw "Existing NewSession configuration lacks V4 Grey exemption $grey. Remove that guard from the console and rerun Phase 2."}
}
$actual=@($sessionState[0].Services)
foreach($wanted in $SessionServices){if($wanted -notin $actual){Write-Warning "$wanted is not protected (its service may have been stopped/missing)."}}
Write-Host '3. Verifying IIS and starting the baseline checker in a separate window.'
$health=((CallScript $watch @{Action='Status'})-join "`n")|ConvertFrom-Json
if(-not $health.Healthy -or -not $health.RecoveryActive){throw 'IIS recovery is not healthy; inspect watchdog Status.'}
# One foreground monitoring window, not a job that gets killed on launcher exit.
$checkerRunning=@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'"|Where-Object {$_.CommandLine -like ('*'+$checker+'*')})
if(-not $checkerRunning.Count){
    CallScript $checker @{Once=$true}|Out-Host
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -WorkingDirectory (Split-Path $checker -Parent) -ArgumentList ('-NoProfile -NoExit -ExecutionPolicy Bypass -File "{0}"' -f $checker)|Out-Null
}
$format=Join-Path $repo 'terminal_sessions\formatting.ps1'
if(Test-Path $format){CallScript $format|Out-Host}
$state.Phase2Complete=$true;SaveState
Write-Host 'Phase 2 complete. Test a NEW RDP/SSH/PowerShell WinRM connection and test the website from the scoring/client network.'
Write-Host 'The baseline checker uses the repo CSVs; inspect its window for baseline/permission errors.'
