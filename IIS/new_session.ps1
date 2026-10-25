# new_session.ps1 - independent post-login verification. Windows PowerShell 5.1.
[CmdletBinding()]
param(
    [ValidateSet('Install','Status','Uninstall','Connect','Watch','Prompt','SshGate','WinRmGate')]
    [string]$Action = 'Status',
    [string[]]$GreyAccounts = @('kingneptune','paintythepirate'),
    [Security.SecureString]$VerificationCode,
    [ValidateRange(1,300)][int]$GraceSeconds = 15,
    [ValidateRange(5,300)][int]$ResponseSeconds = 30,
    [ValidateSet('Rdp','Ssh','WinRm')][string[]]$Services = @('Rdp','Ssh','WinRm'),
    [string]$ComputerName = '',
    [pscredential]$Credential,
    [switch]$UseSSL
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramData 'NewSession'
$installed = Join-Path $root 'new_session.ps1'
$publicPath = Join-Path $root 'public.json'
$privatePath = Join-Path $root 'private.json'
$manifestPath = Join-Path $root 'rollback.json'
$taskName = 'NewSession-Guard'
$powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function Write-Json($Path,$Value) {
    $Value | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$Path.tmp" -Encoding UTF8
    Move-Item -LiteralPath "$Path.tmp" -Destination $Path -Force
}
function Plain([string]$Path) {
    $p=[IO.Path]::GetFullPath($Path)
    while($p) {
        if((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "Refusing a reparse point: $p"}
        $p=[IO.Path]::GetDirectoryName($p)
    }
}
function Secure-Path([string]$Path,[switch]$Readable) {
    Plain $Path
    $directory=(Get-Item -LiteralPath $Path).PSIsContainer
    $acl=if($directory){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
    $sddl=if($directory){'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'}else{'O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'}
    # Directory traversal only; public files get their own read rule. Secrets remain private.
    if($Readable){$sddl+=if($directory){'(A;;GRGX;;;AU)'}else{'(A;;GRGX;;;AU)'}}
    $acl.SetSecurityDescriptorSddlForm($sddl)
    # Leave ownership unchanged for admin installation; DACL protection is sufficient.
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Unwrap([Security.SecureString]$Secret) {
    $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    try{[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)}
}
function Get-ExemptNames([string[]]$Names,[string]$Machine,[string]$Domain) {
    foreach($name in $Names){
        if([string]::IsNullOrWhiteSpace($name)){throw 'Grey account names cannot be empty.'}
        if($name.StartsWith('.\')){"$Machine\$($name.Substring(2))"}
        elseif($name.Contains('\')){$name}
        elseif($name.Contains('@')){throw 'Use DOMAIN\user instead of a UPN for Grey accounts.'}
        else {"$Machine\$name";if($Domain){"$Domain\$name"}}
    }
}
function Ssh-Pattern([string]$Name,[string]$Machine) {
    if($Name -notmatch '^[A-Za-z0-9_.-]+\\[A-Za-z0-9_.-]+$'){throw "Unsupported SSH exemption name: $Name. Use exact DOMAIN\user names."}
    $n=$Name.ToLowerInvariant()
    if($n.StartsWith($Machine.ToLowerInvariant()+'\')){return ($n -split '\\',2)[1]}
    return $n
}
function Audit([string]$Message) {Add-Content -LiteralPath (Join-Path $root 'audit.log') -Value "$(Get-Date -Format o) $Message"}
function Load-Native { if(-not ('NSNative' -as [type])){Add-Type -Path (Join-Path $root 'Native.cs')} }
function Exempt-Current($Config) {
    [NSNative]::Exempt([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,[string[]]$Config.GreyAccounts)
}
function Read-Code([int]$Seconds) {
    if([Console]::IsInputRedirected){throw 'Use an interactive SSH terminal (ssh -t).'}
    $secret=New-Object Security.SecureString
    $deadline=(Get-Date).AddSeconds($Seconds)
    Write-Host 'Verification password: ' -NoNewline
    while((Get-Date) -lt $deadline){
        if([Console]::KeyAvailable){
            $key=[Console]::ReadKey($true)
            if($key.Key -eq 'Enter'){Write-Host '';return ,$secret}
            if($key.Key -eq 'Escape'){break}
            if($key.Key -eq 'Backspace'){if($secret.Length){$secret.RemoveAt($secret.Length-1);Write-Host "`b `b" -NoNewline}}
            elseif(-not [char]::IsControl($key.KeyChar) -and $secret.Length -lt 256){$secret.AppendChar($key.KeyChar);Write-Host '*' -NoNewline}
        }else{Start-Sleep -Milliseconds 50}
    }
    $secret.Dispose();throw 'Verification timed out or was cancelled.'
}
function End-Guard {
    New-Item -ItemType File -Path (Join-Path $root 'stop.flag') -Force | Out-Null
    $deadline=(Get-Date).AddSeconds(8)
    do{
        $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
        if(-not $task -or $task.State -ne 'Running'){break}
        Start-Sleep -Milliseconds 250
    }while((Get-Date) -lt $deadline)
    if($task){if($task.State -eq 'Running'){Stop-ScheduledTask -TaskName $taskName};Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
}
function Assert-NoRemoteSessions($Ssh,$WinRm) {
    # No service reload may terminate a pre-existing remote session.
    if($Ssh){
        $svc=Get-CimInstance Win32_Service -Filter "Name='sshd'"
        $ports=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object OwningProcess -eq $svc.ProcessId | Select-Object -ExpandProperty LocalPort -Unique)
        if(@(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {$_.LocalPort -in $ports}).Count){throw 'SSH sessions are open. Close them and run this from the console/RDP; nothing should reload while they are active.'}
        # Also catch connection workers not yet visible in the established-port query.
        if(@(Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" | Where-Object ProcessId -ne $svc.ProcessId).Count){throw 'An SSH connection process is present. Close SSH connections before setup/removal.'}
    }
    if($WinRm -and @(Get-CimInstance Win32_Process -Filter "Name='wsmprovhost.exe' OR Name='winrshost.exe'").Count){throw 'WinRM sessions are open. Close them and run this from the console/RDP before setup/removal.'}
}
function Get-Startup($Endpoint) {
    $p=$Endpoint.PSObject.Properties['StartupScript'];if($p){return [string]$p.Value};return ''
}
function Restore-Settings($Manifest) {
    # Check all conflicts before changing anything; never overwrite another administrator's edits.
    if($Manifest.Ssh){
        $h=(Get-FileHash -LiteralPath $Manifest.Ssh.Path -Algorithm SHA256).Hash
        if($h -notin @($Manifest.Ssh.BeforeHash,$Manifest.Ssh.AfterHash)){throw 'sshd_config changed after installation. Restore/reconcile it manually; rollback data was retained.'}
    }
    foreach($ep in $Manifest.Endpoints){
        $current=Get-Startup (Get-PSSessionConfiguration -Name $ep.Name)
        if($current -notin @($ep.Before,$ep.Hook)){throw "StartupScript for $($ep.Name) changed after installation. Reconcile it before removal."}
    }
    Assert-NoRemoteSessions ([bool]$Manifest.Ssh) ([bool]@($Manifest.Endpoints).Count)
    if($Manifest.Ssh){
        [IO.File]::WriteAllBytes($Manifest.Ssh.Path,[Convert]::FromBase64String($Manifest.Ssh.BeforeBytes))
        & $Manifest.Ssh.Exe -t -f $Manifest.Ssh.Path
        if($LASTEXITCODE){throw 'Restored SSH config did not validate; guard retained.'}
        Restart-Service sshd -ErrorAction Stop
    }
    foreach($ep in $Manifest.Endpoints){Set-PSSessionConfiguration -Name $ep.Name -StartupScript $ep.Before -NoServiceRestart -Force | Out-Null}
    if(@($Manifest.Endpoints).Count){Restart-Service WinRM -ErrorAction Stop}
}

if($Action -eq 'Connect'){
    if(-not $ComputerName){throw 'Supply -ComputerName for a PowerShell WinRM connection.'}
    if(-not $Credential){$Credential=Get-Credential -Message 'Normal Windows login credentials'}
    if(-not $VerificationCode){$VerificationCode=Read-Host 'Separate verification password' -AsSecureString}
    $plain=Unwrap $VerificationCode
    try{
        $option=New-PSSessionOption -ApplicationArguments @{NewSessionCode=$plain}
        New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $option -UseSSL:$UseSSL
    }finally{$plain=$null;$option=$null}
    return
}
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [version]'5.1'){throw 'Use Windows PowerShell 5.1.'}

# User-side gates do not need administrator rights. No Windows passwords are changed.
if($Action -in @('Prompt','SshGate','WinRmGate')){
    Load-Native
    $cfg=Get-Content -LiteralPath $publicPath -Raw | ConvertFrom-Json
    $exempt=Exempt-Current $cfg
    if($Action -eq 'WinRmGate'){
        # Identity is obtained from the authenticated remoting context, never from ApplicationArguments.
        if(-not $PSSenderInfo){throw 'This gate must run as a PowerShell remoting startup script.'}
        $sender=(New-Object Security.Principal.NTAccount($PSSenderInfo.UserInfo.Identity.Name)).Translate([Security.Principal.SecurityIdentifier]).Value
        $actual=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if($sender -ne $actual){throw 'RunAs/virtual-account endpoints are not supported by NewSession.'}
        if($exempt){return}
        $code=[string]$PSSenderInfo.ApplicationArguments['NewSessionCode']
        try{if(-not [NSNative]::Verify('WinRm',$code)){throw 'Separate verification password missing or incorrect. Use new_session.ps1 -Action Connect.'}}
        finally{$code=$null}
        return
    }
    if($Action -eq 'SshGate'){
        if(-not $exempt){
            Write-Host "Windows login succeeded. Separate verification begins in $($cfg.GraceSeconds) seconds."
            Start-Sleep -Seconds $cfg.GraceSeconds
            $secret=Read-Code $cfg.ResponseSeconds
            $code=Unwrap $secret
            try{if(-not [NSNative]::Verify('Ssh',$code)){throw 'Verification failed.'}}finally{$code=$null;$secret.Dispose()}
        }
        # The original shell remains in charge of command interpretation.
        $shell=[string]$cfg.SshShell;$option=[string]$cfg.SshShellOption
        if($env:SSH_ORIGINAL_COMMAND){& $shell $option $env:SSH_ORIGINAL_COMMAND}else{& $shell}
        exit $LASTEXITCODE
    }
    if($exempt){return}
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form=New-Object Windows.Forms.Form
    $form.Text='New session verification';$form.Size=New-Object Drawing.Size(510,210);$form.StartPosition='CenterScreen';$form.TopMost=$true
    $label=New-Object Windows.Forms.Label;$label.Location=New-Object Drawing.Point(20,20);$label.Size=New-Object Drawing.Size(460,45)
    $label.Text='Windows login succeeded. Enter the separate verification password.';$form.Controls.Add($label)
    $box=New-Object Windows.Forms.TextBox;$box.Location=New-Object Drawing.Point(20,75);$box.Width=330;$box.UseSystemPasswordChar=$true;$box.MaxLength=256;$form.Controls.Add($box)
    $button=New-Object Windows.Forms.Button;$button.Text='Verify';$button.Location=New-Object Drawing.Point(365,72);$form.Controls.Add($button);$form.AcceptButton=$button
    $script:submitted=$false
    $button.Add_Click({
        $script:submitted=$true
        try{[void][NSNative]::Verify('Rdp',$box.Text)}catch{[Windows.Forms.MessageBox]::Show('Verification service unavailable. Contact your teammate.','NewSession')|Out-Null}
        finally{$box.Clear();$form.Close()}
    })
    $timer=New-Object Windows.Forms.Timer;$timer.Interval=$ResponseSeconds*1000
    $timer.Add_Tick({$timer.Stop();$form.Close()})
    $form.Add_Shown({$box.Focus()|Out-Null;$timer.Start()})
    $form.Add_FormClosed({if(-not $script:submitted){try{[void][NSNative]::Verify('Rdp','')}catch{}}})
    try{[void]$form.ShowDialog()}finally{$timer.Stop();$timer.Dispose();$form.Dispose()}
    return
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run Windows PowerShell as Administrator.'}
if(-not [Environment]::Is64BitProcess){throw 'Run the 64-bit Windows PowerShell for administration.'}

if($Action -eq 'Watch'){
    if($identity.User.Value -ne 'S-1-5-18'){throw 'Watch is for the installed SYSTEM task only.'}
    Load-Native
    $cfg=Get-Content $publicPath -Raw|ConvertFrom-Json;$secret=Get-Content $privatePath -Raw|ConvertFrom-Json
    $gate=$null;$mutex=New-Object Threading.Mutex($false,'Global\NewSession-Guard');$held=$false
    try{
        try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held){throw 'Another NewSession watcher is running.'}
        $baselinePath=Join-Path $root 'existing-sessions.json'
        $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
        if(-not (Test-Path $baselinePath)){Write-Json $baselinePath @{Boot=$boot;Keys=@([NSNative]::Sessions()|ForEach-Object Key)}}
        $baseline=Get-Content $baselinePath -Raw|ConvertFrom-Json
        $existing=if($baseline.Boot -eq $boot){@($baseline.Keys)}else{@()}
        $verifiedPath=Join-Path $root 'verified-sessions.json'
        $verified=@();if(Test-Path $verifiedPath){$saved=Get-Content $verifiedPath -Raw|ConvertFrom-Json;if($saved.Boot -eq $boot){$verified=@($saved.Keys)}}
        $gate=New-Object NSNative+Verifier($secret.Salt,$secret.Hash,$secret.Iterations,[string[]]$cfg.GreyAccounts)
        $state=@{}
        while(-not (Test-Path (Join-Path $root 'stop.flag'))){
            $errors=@();$now=Get-Date
            try{
                if(-not $gate.Alive){throw "Verification listener unavailable: $($gate.Error)"}
                if($cfg.Services -contains 'Rdp' -and (Get-Content $manifestPath -Raw|ConvertFrom-Json).State -eq 'Active'){
                    $sessions=@([NSNative]::Sessions());$live=@($sessions|ForEach-Object Key)
                    foreach($s in $sessions){
                        if($s.Key -in $existing -or $s.Key -in $verified -or [NSNative]::Exempt($s.Sid,[string[]]$cfg.GreyAccounts)){continue}
                        if($s.State -ne 0){continue}
                        if(-not $state.ContainsKey($s.Key)){$state[$s.Key]=@{First=$now;Prompted=$false;Deadline=$null}}
                        $entry=$state[$s.Key]
                        if(-not $entry.Prompted -and ($now-$entry.First).TotalSeconds -ge $cfg.GraceSeconds){
                            [NSNative]::Prompt($s.Id,$installed,$cfg.ResponseSeconds)
                            $entry.Prompted=$true;$entry.Deadline=$now.AddSeconds($cfg.ResponseSeconds+8)
                            Audit "CHALLENGE Rdp session=$($s.Id) user=$($s.Account)"
                        }
                        $passed=$false;$has=$gate.RdpResults.TryGetValue($s.Key,[ref]$passed)
                        if($has -and $passed){$verified+= $s.Key;Write-Json $verifiedPath @{Boot=$boot;Keys=$verified};Audit "VERIFIED Rdp session=$($s.Id)"}
                        elseif(($has -and -not $passed) -or ($entry.Prompted -and $now -gt $entry.Deadline)){
                            # Re-enumerate before acting: never log off a reused session ID.
                            $still=@([NSNative]::Sessions()|Where-Object Key -eq $s.Key)
                            if($still.Count){[NSNative]::Logoff($s.Id);Audit "DENIED Rdp session=$($s.Id)"}
                        }
                    }
                    foreach($key in @($state.Keys)){if($key -notin $live){$state.Remove($key);$value=$false;[void]$gate.RdpResults.TryRemove($key,[ref]$value)}}
                    # Keep successful logons across reconnects within this boot. A new logon has a new authentication ID.
                }
            }catch{$errors+= $_.Exception.Message}
            Write-Json (Join-Path $root 'status.json') @{Time=(Get-Date).ToUniversalTime().ToString('o');Healthy=($errors.Count -eq 0);Errors=$errors;Services=$cfg.Services;ExistingSessionsIgnored=$existing.Count}
            Start-Sleep -Seconds 1
        }
    }finally{if($gate){$gate.Dispose()};if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
    return
}
if($Action -eq 'Status'){
    $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    if(-not $task){'NewSession is not installed.';return}
    $cfg=Get-Content $publicPath -Raw|ConvertFrom-Json
    $last=$null;$age=$null
    if(Test-Path (Join-Path $root 'status.json')){$last=Get-Content (Join-Path $root 'status.json') -Raw|ConvertFrom-Json;$age=((Get-Date).ToUniversalTime()-([datetimeoffset]$last.Time).UtcDateTime).TotalSeconds}
    [pscustomobject]@{Task=$taskName;State=[string]$task.State;Healthy=[bool]($task.State -eq 'Running' -and $null -ne $age -and $age -ge 0 -and $age -lt 15 -and $last.Healthy);HeartbeatAgeSeconds=$age;Services=$cfg.Services;GreyAccounts=$cfg.GreyAccounts;Errors=$last.Errors;Directory=$root}
    return
}
if($Action -eq 'Uninstall'){
    Plain $root
    if(-not(Test-Path $manifestPath)){throw 'No rollback record found. Nothing was removed.'}
    $manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json
    if($manifest.State -eq 'Removed'){'Already removed.';return}
    Restore-Settings $manifest
    End-Guard
    $manifest.State='Removed';Write-Json $manifestPath $manifest
    'NewSession removed; original SSH and PowerShell endpoint settings restored. Files retained for review.'
    return
}

# INSTALL: validate everything before changing services. Existing SSH/WinRM sessions must be absent for the one-time reload.
Plain $root
Plain $manifestPath
if(Test-Path $root){
    foreach($item in Get-ChildItem -LiteralPath $root -Force -Recurse){Plain $item.FullName}
    if(-not(Test-Path $manifestPath) -and @(Get-ChildItem -LiteralPath $root -Force).Count){throw 'An unrecognized nonempty NewSession directory exists. Inspect it before installing.'}
}
if(Test-Path $manifestPath){$old=Get-Content $manifestPath -Raw|ConvertFrom-Json;if($old.State -ne 'Removed'){throw 'NewSession is already installed or partly installed. Use Status/Uninstall before installing again.'}}
if(Get-ScheduledTask -TaskName 'CDT-RdpGuard-Watch' -ErrorAction SilentlyContinue){throw 'The older RdpGuard is still installed. Remove it and restore its SSH/WinRM settings before installing NewSession.'}
if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'An existing NewSession task must be reviewed/removed first.'}
if(-not $VerificationCode){$VerificationCode=Read-Host 'Set a separate verification password (12+ characters)' -AsSecureString}
$text=Unwrap $VerificationCode
try{
    if($text.Length -lt 12 -or $text.Length -gt 256){throw 'Use a unique verification password between 12 and 256 characters.'}
    $salt=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create();try{$rng.GetBytes($salt)}finally{$rng.Dispose()}
    $kdf=New-Object Security.Cryptography.Rfc2898DeriveBytes($text,$salt,150000)
    try{$hash=[Convert]::ToBase64String($kdf.GetBytes(32))}finally{$kdf.Dispose()}
}finally{$text=$null}
$computer=Get-CimInstance Win32_ComputerSystem
$domain=if($computer.PartOfDomain){$computer.Domain}else{''}
$names=@(Get-ExemptNames $GreyAccounts $env:COMPUTERNAME $domain|Select-Object -Unique)
$pinned=@();$canonical=@()
foreach($name in $names){try{
    $sid=(New-Object Security.Principal.NTAccount($name)).Translate([Security.Principal.SecurityIdentifier])
    $pinned+=$sid.Value;$canonical+=$sid.Translate([Security.Principal.NTAccount]).Value
}catch{Write-Host "Grey account not present/resolvable here (kept as an exemption): $name"}}
$names=@(@($names)+@($canonical)|Select-Object -Unique)
$exemptAccounts=@(@($names)+@($pinned)|Select-Object -Unique)
$effective=@();if($Services -contains 'Rdp'){$effective+='Rdp'}
$manifest=[pscustomobject]@{Version=1;State='Installing';Ssh=$null;Endpoints=@()}
$sshShell="$env:SystemRoot\System32\cmd.exe";$sshShellOption='/c'
$sshSvc=Get-Service sshd -ErrorAction SilentlyContinue
$winSvc=Get-Service WinRM -ErrorAction SilentlyContinue
$enableSsh=$Services -contains 'Ssh' -and $sshSvc -and $sshSvc.Status -eq 'Running'
$enableWin=$Services -contains 'WinRm' -and $winSvc -and $winSvc.Status -eq 'Running'
Assert-NoRemoteSessions $enableSsh $enableWin
$sshNew=$null
if($enableSsh){
    $sshPath=Join-Path $env:ProgramData 'ssh\sshd_config';Plain $sshPath
    $svc=Get-CimInstance Win32_Service -Filter "Name='sshd'"
    if($svc.PathName -match '^"([^"]+)"\s*$'){$sshExe=$Matches[1]}elseif($svc.PathName -match '^([^" ]+\.exe)\s*$'){$sshExe=$Matches[1]}else{throw 'Custom sshd service arguments are not supported. No configuration was changed.'}
    Plain $sshExe
    $before=Get-Content -LiteralPath $sshPath -Raw
    if($before -match '(?im)^\s*(ForceCommand|Include)\s' -or $before -match 'tyrdp2|NewSession managed'){throw 'Existing SSH ForceCommand/Include/old guard requires manual review before NewSession installation.'}
    $negations=@($names|ForEach-Object {'!'+(Ssh-Pattern $_ $env:COMPUTERNAME)}) -join ','
    $pattern=if($negations){"*,$negations"}else{'*'}
    $sshNew=$before.TrimEnd()+"`r`n`r`n# NewSession managed`r`nMatch User $pattern`r`n    ForceCommand $powerShell -NoProfile -ExecutionPolicy Bypass -File $installed -Action SshGate`r`n    DisableForwarding yes`r`n# End NewSession managed`r`n"
    $reg=Get-ItemProperty 'HKLM:\SOFTWARE\OpenSSH' -ErrorAction SilentlyContinue
    if($reg -and $reg.PSObject.Properties['DefaultShell']){$sshShell=[string]$reg.DefaultShell;$sshShellOption=if($sshShell -match '(powershell|pwsh)\.exe$'){'-Command'}elseif($sshShell -match 'cmd\.exe$'){'/c'}else{'-c'}}
    if($reg -and $reg.PSObject.Properties['DefaultShellCommandOption']){$sshShellOption=[string]$reg.DefaultShellCommandOption}
    $manifest.Ssh=[pscustomobject]@{Path=$sshPath;Exe=$sshExe;BeforeBytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes($sshPath));BeforeHash=(Get-FileHash $sshPath).Hash;AfterHash=''}
    $effective+='Ssh'
}elseif($Services -contains 'Ssh'){Write-Warning 'SSH is not running; it will not be enabled or protected by this installation.'}
if($enableWin){
    foreach($ep in @(Get-PSSessionConfiguration | Where-Object Name -in @('Microsoft.PowerShell','Microsoft.PowerShell32'))){
        if($ep.PSObject.Properties['RunAsUser'] -and $ep.RunAsUser){throw "RunAs endpoint unsupported: $($ep.Name)"}
        $oldStartup=Get-Startup $ep
        if($oldStartup){Plain $oldStartup;if(-not(Test-Path $oldStartup -PathType Leaf)){throw "Missing existing startup script: $oldStartup"}}
        $manifest.Endpoints+= [pscustomobject]@{Name=$ep.Name;Before=$oldStartup;Hook=(Join-Path $root ($ep.Name+'.ps1'))}
    }
    if(-not @($manifest.Endpoints).Count){throw 'WinRM is running but no supported PowerShell endpoint was found.'}
    $effective+='WinRm'
}elseif($Services -contains 'WinRm'){Write-Warning 'WinRM is not running; it will not be enabled or protected by this installation.'}
if(-not $effective.Count){throw 'No selected supported service is available.'}
New-Item -ItemType Directory -Path $root -Force | Out-Null;Secure-Path $root -Readable
if($manifest.Ssh){
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$manifest.Ssh.AfterHash=([BitConverter]::ToString($sha.ComputeHash((New-Object Text.UTF8Encoding($false)).GetBytes($sshNew)))).Replace('-','')}finally{$sha.Dispose()}
}
Write-Json $manifestPath $manifest;Secure-Path $manifestPath
$changed=$false
try{
if([IO.Path]::GetFullPath($PSCommandPath) -ne $installed){Copy-Item -LiteralPath $PSCommandPath -Destination $installed -Force}
Secure-Path $installed -Readable
$nativeSource = @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Security.Cryptography;
public static class NSNative {
 [StructLayout(LayoutKind.Sequential)] struct WTS { public int Id; public IntPtr Name; public int State; }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct SI {public int cb; public string reserved, desktop, title; public int x,y,xs,ys,xc,yc,fill,flags; public short show,res2; public IntPtr reserved2,input,output,error;}
 [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr process,thread; public int pid,tid; }
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSEnumerateSessions(IntPtr h,int r,int v,out IntPtr p,out int n);
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQuerySessionInformation(IntPtr h,int id,int cls,out IntPtr p,out int n);
 [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQueryUserToken(int id,out IntPtr token);
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSLogoffSession(IntPtr h,int id,bool wait);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int c,IntPtr p,int n,out int needed);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint access,out IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint id);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeServerProcessId(IntPtr h,out uint id);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeClientProcessId(IntPtr h,out uint id);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ProcessIdToSessionId(uint pid,out uint session);
 [DllImport("userenv.dll",SetLastError=true)] static extern bool CreateEnvironmentBlock(out IntPtr env,IntPtr token,bool inherit);
 [DllImport("userenv.dll")] static extern bool DestroyEnvironmentBlock(IntPtr env);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr token,string app,StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref SI si,out PI pi);
 public sealed class Session {public int Id; public int State; public string Sid,Account,Key;}
 static string TokenKey(IntPtr token,int session) {
  IntPtr p=Marshal.AllocHGlobal(128); try {int needed;if(!GetTokenInformation(token,10,p,128,out needed))throw new Win32Exception();
   using(var id=new WindowsIdentity(token))return session+":"+Marshal.ReadInt64(p,8).ToString("X")+":"+id.User.Value;
  } finally {Marshal.FreeHGlobal(p);}
 }
 public static Session[] Sessions() {
  IntPtr p;int n;if(!WTSEnumerateSessions(IntPtr.Zero,0,1,out p,out n))throw new Win32Exception();var list=new List<Session>();
  try {int size=Marshal.SizeOf(typeof(WTS));for(int i=0;i<n;i++) {
   var s=(WTS)Marshal.PtrToStructure(IntPtr.Add(p,i*size),typeof(WTS));IntPtr protocol;int length;
   if(!WTSQuerySessionInformation(IntPtr.Zero,s.Id,16,out protocol,out length))continue;
   short kind;try {kind=Marshal.ReadInt16(protocol);}finally {WTSFreeMemory(protocol);} if(kind!=2)continue; // RDP only: never console/RustDesk.
   IntPtr token;if(!WTSQueryUserToken(s.Id,out token)) {if(s.State==0)throw new Win32Exception();continue;}
   try {using(var id=new WindowsIdentity(token))list.Add(new Session{Id=s.Id,State=s.State,Sid=id.User.Value,Account=id.Name,Key=TokenKey(token,s.Id)});}finally{CloseHandle(token);}
  }} finally {WTSFreeMemory(p);} return list.ToArray();
 }
 public static void Logoff(int id) {if(!WTSLogoffSession(IntPtr.Zero,id,false))throw new Win32Exception();}
 public static void Prompt(int session,string script,int seconds) {
  IntPtr token;if(!WTSQueryUserToken(session,out token))throw new Win32Exception();IntPtr env=IntPtr.Zero;
  try {if(!CreateEnvironmentBlock(out env,token,false))throw new Win32Exception();
   string exe=Environment.GetFolderPath(Environment.SpecialFolder.System)+@"\WindowsPowerShell\v1.0\powershell.exe";
   var si=new SI{cb=Marshal.SizeOf(typeof(SI)),desktop=@"winsta0\default"};PI pi;
   var cmd=new StringBuilder("\""+exe+"\" -NoProfile -ExecutionPolicy Bypass -STA -File \""+script+"\" -Action Prompt -ResponseSeconds "+seconds);
   if(!CreateProcessAsUser(token,exe,cmd,IntPtr.Zero,IntPtr.Zero,false,0x400,env,Path.GetDirectoryName(script),ref si,out pi))throw new Win32Exception();
   CloseHandle(pi.process);CloseHandle(pi.thread);
  } finally {if(env!=IntPtr.Zero)DestroyEnvironmentBlock(env);CloseHandle(token);}
 }
 public static bool Exempt(string sid,string[] accounts) {
  foreach(string name in accounts) {if(name.StartsWith("S-1-",StringComparison.OrdinalIgnoreCase)){if(name==sid)return true;continue;}try {if(((SecurityIdentifier)new NTAccount(name).Translate(typeof(SecurityIdentifier))).Value==sid)return true;}catch(IdentityNotMappedException){}} return false;
 }
 public static bool MatchCode(string code,string salt,string hash,int iterations) {
  if(String.IsNullOrEmpty(code)||code.Length>256)return false;
  using(var k=new Rfc2898DeriveBytes(code,Convert.FromBase64String(salt),iterations)) {byte[] a=k.GetBytes(32),b=Convert.FromBase64String(hash);int d=a.Length^b.Length;for(int i=0;i<Math.Min(a.Length,b.Length);i++)d|=a[i]^b[i];return d==0;}
 }
 static string ProcessIdentity(uint pid,out string key) {
  IntPtr process=OpenProcess(0x1000,false,pid);if(process==IntPtr.Zero)throw new Win32Exception();IntPtr token=IntPtr.Zero;
  try {if(!OpenProcessToken(process,8,out token))throw new Win32Exception();uint session;if(!ProcessIdToSessionId(pid,out session))throw new Win32Exception();key=TokenKey(token,(int)session);using(var id=new WindowsIdentity(token))return id.User.Value;
  } finally {if(token!=IntPtr.Zero)CloseHandle(token);CloseHandle(process);}
 }
 static string ReadLine(Stream stream,int timeout) {
  var bytes=new List<byte>();var end=DateTime.UtcNow.AddMilliseconds(timeout);
  while(bytes.Count<2048) {byte[] b=new byte[1];var ar=stream.BeginRead(b,0,1,null,null);int left=(int)(end-DateTime.UtcNow).TotalMilliseconds;
   if(left<=0||!ar.AsyncWaitHandle.WaitOne(left))throw new TimeoutException();int n;try{n=stream.EndRead(ar);}finally{ar.AsyncWaitHandle.Close();}if(n==0)throw new EndOfStreamException();if(b[0]==10)return Encoding.UTF8.GetString(bytes.ToArray());bytes.Add(b[0]);}
  throw new InvalidDataException();
 }
 public static bool Verify(string kind,string code) {
  using(var pipe=new NamedPipeClientStream(".","NewSession-Verify-v1",PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification)) {
   pipe.Connect(4000);
   if(((SecurityIdentifier)pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier))).Value!="S-1-5-18")throw new InvalidOperationException("Verification pipe is not owned by SYSTEM.");
   byte[] data=Encoding.UTF8.GetBytes(kind+":"+Convert.ToBase64String(Encoding.UTF8.GetBytes(code??""))+"\n");pipe.Write(data,0,data.Length);pipe.Flush();return ReadLine(pipe,5000)=="OK";
  }
 }
 public sealed class Verifier : IDisposable {
  readonly string salt,hash;readonly int iterations;readonly string[] accounts;Thread thread;volatile bool stop;public volatile bool Alive;public string Error="";
  public ConcurrentDictionary<string,bool> RdpResults=new ConcurrentDictionary<string,bool>();
  public Verifier(string s,string h,int i,string[] a){salt=s;hash=h;iterations=i;accounts=a;thread=new Thread(Loop);thread.IsBackground=true;thread.Start();}
  void Loop() {try {while(!stop) {
   var acl=new PipeSecurity();acl.SetOwner(new SecurityIdentifier("S-1-5-18"));acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-5-18"),PipeAccessRights.FullControl,AccessControlType.Allow));acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-5-32-544"),PipeAccessRights.FullControl,AccessControlType.Allow));acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-5-11"),PipeAccessRights.ReadWrite,AccessControlType.Allow));
   using(var pipe=new NamedPipeServerStream("NewSession-Verify-v1",PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,4096,acl)) {
    Alive=true;pipe.WaitForConnection();if(stop)break;
    try {uint client;if(!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(),out client))throw new Win32Exception();string key;string sid=ProcessIdentity(client,out key);
     string line=ReadLine(pipe,2000);int split=line.IndexOf(':');if(split<0)throw new InvalidDataException();string kind=line.Substring(0,split);if(kind!="Rdp"&&kind!="Ssh"&&kind!="WinRm")throw new InvalidDataException();
     string code=Encoding.UTF8.GetString(Convert.FromBase64String(line.Substring(split+1)));bool pass=Exempt(sid,accounts)||MatchCode(code,salt,hash,iterations);code=null;
     if(kind=="Rdp")RdpResults[key]=pass;
     byte[] data=Encoding.ASCII.GetBytes(pass?"OK\n":"NO\n");pipe.Write(data,0,data.Length);pipe.Flush();
    }catch(Exception){ /* A failed/malformed request grants nothing. Never log secret data. */ }
   }
  }}catch(Exception e){Error=e.GetType().Name+": "+e.Message;}finally{Alive=false;}}
  public void Dispose(){stop=true;try{using(var p=new NamedPipeClientStream(".","NewSession-Verify-v1",PipeDirection.InOut)){p.Connect(1000);}}catch{}thread.Join(3000);}
 }
}
'@
$nativeSource | Set-Content -LiteralPath (Join-Path $root 'Native.cs') -Encoding UTF8
Secure-Path (Join-Path $root 'Native.cs') -Readable
Write-Json $publicPath @{Version=1;Services=$effective;GreyAccounts=$exemptAccounts;GraceSeconds=$GraceSeconds;ResponseSeconds=$ResponseSeconds;SshShell=$sshShell;SshShellOption=$sshShellOption}
Secure-Path $publicPath -Readable
Write-Json $privatePath @{Salt=[Convert]::ToBase64String($salt);Hash=$hash;Iterations=150000};Secure-Path $privatePath
foreach($name in @('stop.flag','existing-sessions.json','verified-sessions.json','status.json')){Remove-Item -LiteralPath (Join-Path $root $name) -Force -ErrorAction SilentlyContinue}
foreach($ep in $manifest.Endpoints){
    $hook="& '$($installed.Replace("'","''"))' -Action WinRmGate`r`n"
    if($ep.Before){$hook+=". '$($ep.Before.Replace("'","''"))'`r`n"}
    $hook|Set-Content -LiteralPath $ep.Hook -Encoding UTF8;Secure-Path $ep.Hook -Readable
}
if($manifest.Ssh){
    $candidate=Join-Path $root 'sshd_config.candidate'
    [IO.File]::WriteAllText($candidate,$sshNew,(New-Object Text.UTF8Encoding($false)))
    & $manifest.Ssh.Exe -t -f $candidate
    if($LASTEXITCODE){throw 'Proposed sshd_config failed validation. Live SSH configuration was not changed.'}
    $manifest.Ssh.AfterHash=(Get-FileHash $candidate).Hash
}
Write-Json $manifestPath $manifest;Secure-Path $manifestPath
    $taskAction=New-ScheduledTaskAction -Execute $powerShell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$installed`" -Action Watch"
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $taskAction -Trigger (New-ScheduledTaskTrigger -AtStartup) -User SYSTEM -RunLevel Highest -Settings $settings | Out-Null
    Start-ScheduledTask $taskName
    $deadline=(Get-Date).AddSeconds(30);$ready=$false
    do{
        Start-Sleep -Seconds 1
        if(Test-Path (Join-Path $root 'status.json')){$s=Get-Content (Join-Path $root 'status.json') -Raw|ConvertFrom-Json;if($s.Healthy){$ready=$true;break}}
    }while((Get-Date) -lt $deadline)
    if(-not $ready){throw 'No healthy watcher heartbeat. Service settings were not changed.'}
    Assert-NoRemoteSessions $enableSsh $enableWin
    $changed=$true
    if($manifest.Ssh){Copy-Item -LiteralPath $candidate -Destination $manifest.Ssh.Path -Force;Restart-Service sshd -ErrorAction Stop}
    foreach($ep in $manifest.Endpoints){Set-PSSessionConfiguration -Name $ep.Name -StartupScript $ep.Hook -NoServiceRestart -Force | Out-Null}
    if(@($manifest.Endpoints).Count){Restart-Service WinRM -ErrorAction Stop}
    $manifest.State='Active';Write-Json $manifestPath $manifest
    'NewSession installed. Existing RDP logons and all console sessions are untouched. New sessions require separate verification; Grey users are exempt.'
    & $installed -Action Status
}catch{
    $failure=$_.Exception.Message
    if($changed){try{Restore-Settings $manifest}catch{throw "Installation incomplete: $failure. Rollback blocked: $($_.Exception.Message). Keep the guard running and inspect $manifestPath."}}
    End-Guard;$manifest.State='Removed';Write-Json $manifestPath $manifest
    throw "Installation failed; settings rolled back: $failure"
}
