<#
session.ps1 - Run in 64-bit Windows PowerShell 5.1 as Administrator, from console/RDP.
.\session.ps1 installs/repairs. -Ask chooses a separate verification password.
.\session.ps1 -Remove removes this guard and restores its owned SSH/WinRM settings.
The default password is the UserPassword constant below; change it or prefer -Ask.
This does NOT reset Windows passwords or change accounts/groups. Listed Grey users bypass all gates by authenticated account SID.
RDP: new login/reconnect -> ~15 seconds -> popup -> 15 seconds to answer.
Wrong password, closed popup or timeout logs off that RDP session. Existing connections
at first installation are not kicked mid-setup. Console/RustDesk sessions are untouched.
SSH stays enabled if OpenSSH Server is installed: normal authentication -> 15 seconds
-> terminal password prompt (15-second deadline) -> original shell on success.
Use an interactive client (ssh -t). SCP/SFTP, forwarding and noninteractive commands
cannot supply this terminal prompt and are blocked. Do file transfers BEFORE installation.
WinRM is stopped/disabled. If that fails, only the original supported PowerShell
endpoints get a startup verification hook. WinRS/custom endpoints are NOT covered:
a warning and WinRmMode=Fallback mean WinRM is NOT fully secured/disabled.
A post-login popup is NOT MFA or a security boundary against a full local administrator.
The hardcoded password exists in THIS source, but only a salted PBKDF2 hash is installed.

PATHS / STATE (all beneath ProgramData unless stated otherwise):
Session\session-engine.ps1 - installed runtime; scheduled task Session-Guard runs as SYSTEM.
Session\Native.cs - WTS/popup and named-pipe verification helper, readable by users.
Session\public.json - timing, supported services and resolved Grey account SIDs/names, readable by users.
Session\private.json - private salted hash, never a Windows-account password.
Session\rollback.json - original SSH configuration/service modes and owned change hashes.
Session\sshd_config.candidate - syntax-checked copy of the SSH gate configuration.
Session\Microsoft.PowerShell*.ps1 - WinRM fallback startup hooks, if needed.
Session\repair\* - private verified copies of the installed public files/hooks.
Session\existing-sessions.json / verified-sessions.json - current-boot RDP identity records.
Repairs preserve original rollback state; if a script/policy update occurs, the watcher restarts.
Session\status.json / audit.log - heartbeat/errors and RDP decisions (no typed passwords).
Session\stop.flag - cooperative watcher shutdown marker; *.tmp are atomic JSON writes.
Session-Setup\session-engine.ps1 - private installer staging file.
%ProgramData%\ssh\sshd_config - read, validated, gated; original bytes restored by -Remove.
HKLM:\SOFTWARE\OpenSSH - read original shell settings; not changed.
HKLM:\SYSTEM\CurrentControlSet\Services\{WinRM,sshd} - original service mode captured/restored.
WSMan PowerShell endpoint StartupScript - changed only when WinRM disable fails, then restored.
Removal keeps private rollback/diagnostic files. It refuses to overwrite unrelated SSH edits.
Install/remove while no SSH/WinRM sessions are connected; close those sessions first.
#>
# session.ps1 - Windows PowerShell 5.1, run as Administrator from console/RDP.
# Public commands: .\session.ps1 | .\session.ps1 -Ask | .\session.ps1 -Remove
[CmdletBinding(DefaultParameterSetName='Install')]
param([Parameter(ParameterSetName='Remove')][switch]$Remove,
      [Parameter(ParameterSetName='Install')][switch]$Ask)
# EDIT this separate verification password, or use -Ask. It is NOT a Windows password.
# A hardcoded secret is visible to anyone who can read THIS source file.
$UserPassword = 'BlueTeam-Session-2026!'
# Grey Team accounts (including the local administrator account, greyteamadmin).
$GreyTeamUsers = @('kingneptune', 'paintythepirate', 'greyteamadmin', 'Administrator', 'Admin')
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 as Administrator.'}
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not(New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Open Windows PowerShell as Administrator.'}
function Protect-Setup([string]$Path){
    $p=[IO.Path]::GetFullPath($Path)
    while($p){if((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "Reparse point refused: $p"};$p=[IO.Path]::GetDirectoryName($p)}
    New-Item -ItemType Directory -Path $Path -Force|Out-Null
    $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)');Set-Acl -LiteralPath $Path -AclObject $acl
}
function Get-SessionEngineSource {
$engine={
# session-engine.ps1 - independent post-login verification. Windows PowerShell 5.1.
[CmdletBinding()]
param(
    [ValidateSet('Install','Status','Uninstall','Connect','Watch','Prompt','SshGate','WinRmGate')]
    [string]$Action = 'Status',
    [Security.SecureString]$VerificationCode,
    [ValidateRange(1,300)][int]$GraceSeconds = 15,
    [ValidateRange(5,300)][int]$ResponseSeconds = 15,
    [ValidateSet('Rdp','Ssh','WinRm')][string[]]$Services = @('Rdp','Ssh','WinRm'),
    [string[]]$GreyAccounts = @(),
    [string]$ComputerName = '',
    [pscredential]$Credential,
    [switch]$UseSSL
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramData 'Session'
$installed = Join-Path $root 'session-engine.ps1'
$publicPath = Join-Path $root 'public.json'
$privatePath = Join-Path $root 'private.json'
$manifestPath = Join-Path $root 'rollback.json'
$taskName = 'Session-Guard'
$powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function Write-Json($Path,$Value) {
    Plain $Path;Plain "$Path.tmp"
    $acl=if(Test-Path -LiteralPath $Path){Get-Acl -LiteralPath $Path}else{$null}
    $Value | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$Path.tmp" -Encoding UTF8
    if($acl){Set-Acl -LiteralPath "$Path.tmp" -AclObject $acl}
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
function Audit([string]$Message) {Add-Content -LiteralPath (Join-Path $root 'audit.log') -Value "$(Get-Date -Format o) $Message"}
function Load-Native { if(-not ('SessionNative' -as [type])){Add-Type -Path (Join-Path $root 'Native.cs')} }
function Read-Code([int]$Seconds) {
    if([Console]::IsInputRedirected){throw 'Use an interactive SSH terminal (ssh -t).'}
    $secret=New-Object Security.SecureString
    $deadline=(Get-Date).AddSeconds($Seconds)
    Write-Host 'Verification password: ' -NoNewline
    while((Get-Date) -lt $deadline){
        if([Console]::KeyAvailable){
            $key=[Console]::ReadKey($true)
            if($key.Key -eq 'Enter'){Write-Host '';return ,$secret}
            if($key.Key -eq 'Escape' -or ($key.Key -eq 'C' -and ($key.Modifiers -band [ConsoleModifiers]::Control))){break}
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
    if($Manifest.WinRmService -and $Manifest.WinRmService.Changed){
        $current=Get-CimInstance Win32_Service -Filter "Name='WinRM'"
        if($current.StartMode -notin @($Manifest.WinRmService.ExpectedMode,$Manifest.WinRmService.StartMode)){throw 'WinRM start mode was changed by someone else; reconcile it before removal.'}
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
    Restore-ServiceState $Manifest.WinRmService
    Restore-ServiceState $Manifest.SshService
}

function Resolve-GreyIdentities([string[]]$Names) {
    # Resolve once as administrator: user gates read a SID list from public.json (read-only to non-administrators).
    # Account/display-name text alone is never enough to grant an exemption.
    $computer=Get-CimInstance Win32_ComputerSystem
    $hostName=[string]$computer.Name
    $domainName=if($computer.PartOfDomain){[string]$computer.Domain}else{''}
    $found=@()
    foreach($name in @($Names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        $candidates=if($name -match '[\\@]'){@($name)}else{
            $choices=@("$hostName\$name")
            if($domainName){$choices+=("$domainName\$name")}
            $choices
        }
        $resolved=$null
        foreach($candidate in $candidates){
            try {
                $accountObject=New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $candidate
                $sid=$accountObject.Translate([Security.Principal.SecurityIdentifier])
                $account=$sid.Translate([Security.Principal.NTAccount]).Value
                $resolved=[pscustomobject]@{Sid=$sid.Value;Account=$account}
                break
            }catch [Security.Principal.IdentityNotMappedException] { continue }
        }
        if($resolved){if($resolved.Sid -notin @($found | ForEach-Object Sid)){$found+=$resolved}}
        else{Write-Warning "Grey account '$name' was not found. It will NOT be exempt; rerun after the account is available."}
    }
    return $found
}
function Test-GreySid([string]$Sid,$Config) {
    # Never match user-controlled display names: compare the authenticated Windows token SID.
    return ([bool]$Sid -and $Sid -in @($Config.GreySids))
}
function Update-ManagedCopy([string]$Path,$Manifest) {
    # Keep repair copy/hash in sync when the trusted installer itself updates an owned file.
    $entry=@($Manifest.ManagedFiles | Where-Object { $_.Path -ieq $Path })
    if($entry.Count -ne 1){throw "Missing or ambiguous owned-file rollback record: $Path"}
    Plain $entry[0].Backup
    Copy-Item -LiteralPath $Path -Destination $entry[0].Backup -Force
    Secure-Path $entry[0].Backup
    $entry[0].Hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Save-ServiceState([string]$Name) {
    $svc=Get-CimInstance Win32_Service -Filter "Name='$Name'"
    if(-not $svc){return $null}
    $reg=Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -ErrorAction Stop
    [pscustomobject]@{Name=$Name;StartMode=$svc.StartMode;WasRunning=($svc.State -eq 'Running');DelayedAutoStart=[bool]$reg.DelayedAutoStart;ExpectedMode=$svc.StartMode;Changed=$false}
}
function Set-SessionCode([Security.SecureString]$Code) {
    $text=Unwrap $Code
    try{
        if($text.Length -lt 12 -or $text.Length -gt 256){throw 'Verification password must contain 12-256 characters.'}
        $salt=New-Object byte[] 32;$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try{$rng.GetBytes($salt)}finally{$rng.Dispose()}
        $kdf=New-Object Security.Cryptography.Rfc2898DeriveBytes($text,$salt,150000)
        try{$hash=[Convert]::ToBase64String($kdf.GetBytes(32))}finally{$kdf.Dispose()}
        Write-Json $privatePath @{Salt=[Convert]::ToBase64String($salt);Hash=$hash;Iterations=150000};Secure-Path $privatePath
    }finally{$text=$null}
}
function Restore-ServiceState($Saved) {
    if(-not $Saved -or -not $Saved.Changed){return}
    $kind=switch($Saved.StartMode){'Auto'{'Automatic'}'Manual'{'Manual'}'Disabled'{'Disabled'}default{throw "Unsupported saved service mode: $($Saved.StartMode)"}}
    Set-Service -Name $Saved.Name -StartupType $kind -ErrorAction Stop
    if($Saved.StartMode -eq 'Auto'){Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($Saved.Name)" -Name DelayedAutoStart -Type DWord -Value ([int]$Saved.DelayedAutoStart)}
    if($Saved.WasRunning){Start-Service -Name $Saved.Name -ErrorAction Stop}
    else{Stop-Service -Name $Saved.Name -ErrorAction Stop}
}
function Stop-WinRm($Manifest,[switch]$NoFallback) {
    if(-not $Manifest.WinRmService){$Manifest.WinRmMode='NotInstalled';Write-Json $manifestPath $Manifest;return $true}
    # Already stopped/disabled: succeed without touching the service or its saved original state.
    $current=Get-CimInstance Win32_Service -Filter "Name='WinRM'"
    if($current -and $current.State -eq 'Stopped' -and $current.StartMode -eq 'Disabled'){
        $Manifest.WinRmMode='Disabled';Write-Json $manifestPath $Manifest
        return $true
    }
    $Manifest.WinRmService.Changed=$true;$Manifest.WinRmService.ExpectedMode='Disabled'
    Write-Json $manifestPath $Manifest
    try{
        Set-Service WinRM -StartupType Disabled -ErrorAction Stop
        Stop-Service WinRM -ErrorAction Stop
        $svc=Get-CimInstance Win32_Service -Filter "Name='WinRM'"
        if($svc.State -ne 'Stopped' -or $svc.StartMode -ne 'Disabled'){throw 'WinRM did not become stopped and disabled.'}
        $Manifest.WinRmMode='Disabled';Write-Json $manifestPath $Manifest
        return $true
    }catch{
        if($NoFallback){throw}
        Write-Warning 'WinRM could not be disabled. Attempting the verified PowerShell endpoint gate instead.'
        Restore-ServiceState $Manifest.WinRmService
        $Manifest.WinRmService.Changed=$false;$Manifest.WinRmService.ExpectedMode=$Manifest.WinRmService.StartMode
        $Manifest.WinRmMode='Fallback';Write-Json $manifestPath $Manifest
        return $false
    }
}
function Repair-Session {
    $manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json
    if($manifest.State -ne 'Active'){throw 'Session setup was interrupted. Run .\session.ps1 -Remove to roll it back, then run it again.'}
    # Only restore changes owned by this installer. Never replace unrelated SSH configuration.
    if($manifest.Ssh){
        $live=(Get-FileHash -LiteralPath $manifest.Ssh.Path).Hash
        if($live -ne $manifest.Ssh.AfterHash){
            if($live -ne $manifest.Ssh.BeforeHash){throw 'SSH configuration has unrelated edits. Reconcile them before repairing session.'}
            Assert-NoRemoteSessions $true $false
            $candidate=Join-Path $root 'sshd_config.candidate'
            if((Get-FileHash $candidate).Hash -ne $manifest.Ssh.AfterHash){throw 'Saved SSH gate configuration failed verification.'}
            Copy-Item -LiteralPath $candidate -Destination $manifest.Ssh.Path -Force
            Restart-Service sshd -ErrorAction Stop
        }
        $ssh=Get-CimInstance Win32_Service -Filter "Name='sshd'"
        if($ssh.StartMode -eq 'Disabled'){Set-Service sshd -StartupType Manual -ErrorAction Stop}
        if($ssh.State -ne 'Running'){Start-Service sshd -ErrorAction Stop}
    }
    if($manifest.WinRmMode -eq 'Disabled'){
        Assert-NoRemoteSessions $false $true
        if(-not (Stop-WinRm $manifest -NoFallback)){throw 'WinRM disable repair failed. Remove/reinstall from the console to configure fallback gating.'}
    }
    foreach($ep in $manifest.Endpoints){
        $actual=Get-Startup (Get-PSSessionConfiguration -Name $ep.Name)
        if($actual -ne $ep.Hook){throw "WinRM endpoint $($ep.Name) changed. Remove/reinstall after reviewing its configuration."}
    }
    foreach($file in $manifest.ManagedFiles){
        Plain $file.Path
        if(-not(Test-Path $file.Path) -or (Get-FileHash $file.Path).Hash -ne $file.Hash){
            Plain $file.Backup
            if(-not(Test-Path $file.Backup) -or (Get-FileHash $file.Backup).Hash -ne $file.Hash){throw "Both installed and repair copies failed verification: $($file.Path). The rollback record is retained."}
            Copy-Item -LiteralPath $file.Backup -Destination $file.Path -Force
            Secure-Path $file.Path -Readable
        }
    }
    # Repeated installs must preserve the original WinRmService snapshot in rollback.json.
    # Only replace files owned by Session after the repair integrity checks above.
    $policy=Get-Content -LiteralPath $publicPath -Raw | ConvertFrom-Json
    $grey=@(Resolve-GreyIdentities $GreyAccounts)
    $newSids=@($grey | ForEach-Object Sid)
    $newNames=@($grey | ForEach-Object Account)
    $oldSids=@($policy.GreySids)
    $oldNames=@($policy.GreyAccounts)
    $missingFields=($null -eq $policy.PSObject.Properties['GreySids'] -or $null -eq $policy.PSObject.Properties['GreyAccounts'])
    $policyChanged=($missingFields -or ($newSids -join '|') -cne ($oldSids -join '|') -or ($newNames -join '|') -cne ($oldNames -join '|'))
    if($policyChanged){
        $policy | Add-Member -NotePropertyName GreySids -NotePropertyValue $newSids -Force
        $policy | Add-Member -NotePropertyName GreyAccounts -NotePropertyValue $newNames -Force
        Write-Json $publicPath $policy
        Secure-Path $publicPath -Readable
        Update-ManagedCopy $publicPath $manifest
    }
    $engineChanged=((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash)
    if($engineChanged){
        Copy-Item -LiteralPath $PSCommandPath -Destination $installed -Force
        Secure-Path $installed -Readable
        Update-ManagedCopy $installed $manifest
    }
    if($policyChanged -or $engineChanged){Write-Json $manifestPath $manifest}
    # An old running watcher keeps its in-memory settings/code. Restart only after policy or code changes.
    if($policyChanged -or $engineChanged){End-Guard}
    Remove-Item -LiteralPath (Join-Path $root 'stop.flag') -Force -ErrorAction SilentlyContinue
    $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    if($task){
        if(-not @($task.Actions|Where-Object {$_.Execute -ieq $powerShell -and $_.Arguments -like ('*"'+$installed+'" -Action Watch*')}).Count){throw 'The Session-Guard task points to an unexpected command.'}
        if($task.State -eq 'Disabled'){Enable-ScheduledTask -TaskName $taskName -TaskPath '\'|Out-Null}
        if($task.State -ne 'Running'){Start-ScheduledTask -TaskName $taskName -TaskPath '\'}
    }else{Install-SessionTask}
    $deadline=(Get-Date).AddSeconds(30)
    do{Start-Sleep -Seconds 1;$health=& $installed -Action Status;if($health.Healthy){$health;return}}while((Get-Date) -lt $deadline)
    throw 'Session watcher has no healthy heartbeat; review its status.json.'
}
function Install-SessionTask {
    $taskAction=New-ScheduledTaskAction -Execute $powerShell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$installed`" -Action Watch"
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $taskAction -Trigger (New-ScheduledTaskTrigger -AtStartup) -User SYSTEM -RunLevel Highest -Settings $settings|Out-Null
    Start-ScheduledTask -TaskName $taskName -TaskPath '\'
}

if($Action -eq 'Connect'){
    if(-not $ComputerName){throw 'Supply -ComputerName for a PowerShell WinRM connection.'}
    if(-not $Credential){$Credential=Get-Credential -Message 'Normal Windows login credentials'}
    if(-not $VerificationCode){$VerificationCode=Read-Host 'Separate verification password' -AsSecureString}
    $plain=Unwrap $VerificationCode
    try{
        $option=New-PSSessionOption -ApplicationArguments @{SessionCode=$plain}
        New-PSSession -ComputerName $ComputerName -Credential $Credential -SessionOption $option -UseSSL:$UseSSL
    }finally{$plain=$null;$option=$null}
    return
}
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [version]'5.1'){throw 'Use Windows PowerShell 5.1.'}

# User-side gates do not need administrator rights. No Windows passwords are changed.
if($Action -in @('Prompt','SshGate','WinRmGate')){
    $cfg=Get-Content -LiteralPath $publicPath -Raw | ConvertFrom-Json
    # Effective identity is taken from Windows, never from a supplied account/display name.
    $exempt=Test-GreySid ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) $cfg
    if($Action -eq 'WinRmGate'){
        # Identity is obtained from the authenticated remoting context, never from ApplicationArguments.
        if(-not $PSSenderInfo){throw 'This gate must run as a PowerShell remoting startup script.'}
        $senderAccount=New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList ([string]$PSSenderInfo.UserInfo.Identity.Name)
        $sender=$senderAccount.Translate([Security.Principal.SecurityIdentifier]).Value
        $actual=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        if($sender -ne $actual){throw 'RunAs/virtual-account endpoints are not supported by Session.'}
        $exempt=Test-GreySid $actual $cfg
        if($exempt){return}
        Load-Native
        $code=[string]$PSSenderInfo.ApplicationArguments['SessionCode']
        try{if(-not [SessionNative]::Verify('WinRm',$code)){throw 'Separate verification password missing or incorrect. Use session-engine.ps1 -Action Connect.'}}
        finally{$code=$null}
        return
    }
    if($Action -eq 'SshGate'){
        try{[Console]::TreatControlCAsInput=$true}catch{}
        if(-not $exempt){
            Load-Native
            Write-Host "Windows login succeeded. Separate verification begins in $($cfg.GraceSeconds) seconds."
            Start-Sleep -Seconds $cfg.GraceSeconds
            $secret=Read-Code $cfg.ResponseSeconds
            $code=Unwrap $secret
            try{if(-not [SessionNative]::Verify('Ssh',$code)){throw 'Verification failed.'}}finally{$code=$null;$secret.Dispose()}
        }
        [Console]::TreatControlCAsInput=$false
        # The original shell remains in charge of command interpretation.
        $shell=[string]$cfg.SshShell;$option=[string]$cfg.SshShellOption
        if($env:SSH_ORIGINAL_COMMAND){& $shell $option $env:SSH_ORIGINAL_COMMAND}else{& $shell}
        exit $LASTEXITCODE
    }
    if($exempt){return}
    Load-Native
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
        try{[void][SessionNative]::Verify('Rdp',$box.Text)}catch{}
        finally{$box.Clear();$form.Close()}
    })
    $timer=New-Object Windows.Forms.Timer;$timer.Interval=$cfg.ResponseSeconds*1000
    $timer.Add_Tick({$timer.Stop();$form.Close()})
    $form.Add_Shown({$box.Focus()|Out-Null;$timer.Start();try{[void][SessionNative]::Verify('RdpReady','')}catch{$form.Close()}})
    $form.Add_FormClosed({if(-not $script:submitted){try{[void][SessionNative]::Verify('Rdp','')}catch{}}})
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
    $gate=$null;$mutex=New-Object Threading.Mutex($false,'Global\Session-Guard');$held=$false
    try{
        try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
        if(-not $held){throw 'Another Session watcher is running.'}
        $baselinePath=Join-Path $root 'existing-sessions.json'
        $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
        if(-not (Test-Path $baselinePath)){Write-Json $baselinePath @{Boot=$boot;Keys=@([SessionNative]::Sessions()|ForEach-Object Key)}}
        $baseline=Get-Content $baselinePath -Raw|ConvertFrom-Json
        $existing=if($baseline.Boot -eq $boot){@($baseline.Keys)}else{@()}
        $verifiedPath=Join-Path $root 'verified-sessions.json'
        $verified=@();if(Test-Path $verifiedPath){$saved=Get-Content $verifiedPath -Raw|ConvertFrom-Json;if($saved.Boot -eq $boot){$verified=@($saved.Keys)}}
        $gate=New-Object SessionNative+Verifier($secret.Salt,$secret.Hash,$secret.Iterations)
        $state=@{}
        while(-not (Test-Path (Join-Path $root 'stop.flag'))){
            $errors=@();$now=Get-Date
            try{
                if((Get-Content $manifestPath -Raw|ConvertFrom-Json).WinRmMode -eq 'Disabled'){
                    $winState=Get-CimInstance Win32_Service -Filter "Name='WinRM'"
                    if($winState -and ($winState.State -ne 'Stopped' -or $winState.StartMode -ne 'Disabled')){$errors+='WinRM disable setting drifted; run session.ps1 again to repair it.'}
                }
                $listenerAlive=[bool]$gate.Alive
                if(-not $listenerAlive){$errors+="Verification listener unavailable: $($gate.Error)"}
                if($cfg.Services -contains 'Rdp' -and (Get-Content $manifestPath -Raw|ConvertFrom-Json).State -eq 'Active'){
                    $sessions=@([SessionNative]::Sessions());$live=@($sessions|ForEach-Object Key)
                    foreach($s in $sessions){
                        if($s.State -ne 0){
                            if($s.Key -in $existing){$existing=@($existing|Where-Object {$_ -ne $s.Key});Write-Json $baselinePath @{Boot=$boot;Keys=$existing}}
                            if($s.Key -in $verified){$verified=@($verified|Where-Object {$_ -ne $s.Key});Write-Json $verifiedPath @{Boot=$boot;Keys=$verified}}
                            $state.Remove($s.Key);$value=$false;[void]$gate.RdpResults.TryRemove($s.Key,[ref]$value);$shown=[datetime]::MinValue;[void]$gate.RdpShown.TryRemove($s.Key,[ref]$shown);[void]$gate.RdpAnswered.TryRemove($s.Key,[ref]$shown)
                            continue
                        }
                        # WTSQueryUserToken supplies the authenticated logon SID; names are not trusted.
                        if(Test-GreySid $s.Sid $cfg){
                            if($state.ContainsKey($s.Key)){$state.Remove($s.Key)}
                            continue
                        }
                        if($s.Key -in $existing -or $s.Key -in $verified){continue}
                        if(-not $state.ContainsKey($s.Key)){$state[$s.Key]=@{First=$now;Prompted=$false;Deadline=$null;PromptPid=0;LaunchDeadline=$null}}
                        $entry=$state[$s.Key]
                        if(-not $entry.Prompted -and ($now-$entry.First).TotalSeconds -ge $cfg.GraceSeconds){
                            # Fail closed if the verifier is unavailable or a popup cannot launch.
                            # Check the full logon key before logging off: session IDs can be reused.
                            if(-not $listenerAlive){
                                $still=@([SessionNative]::Sessions() | Where-Object Key -eq $s.Key)
                                if($still.Count){[SessionNative]::Logoff($s.Id);Audit "DENIED Rdp session=$($s.Id) verifier-unavailable"}
                                continue
                            }
                            try{$entry.PromptPid=[SessionNative]::Prompt($s.Id,$installed,$cfg.ResponseSeconds)}
                            catch{
                                $errors+="RDP popup launch failed: $($_.Exception.Message)"
                                $still=@([SessionNative]::Sessions() | Where-Object Key -eq $s.Key)
                                if($still.Count){[SessionNative]::Logoff($s.Id);Audit "DENIED Rdp session=$($s.Id) popup-launch-failed"}
                                continue
                            }
                            $entry.Prompted=$true;$entry.LaunchDeadline=$now.AddSeconds(15)
                            Audit "CHALLENGE Rdp session=$($s.Id) user=$($s.Account)"
                        }
                        $passed=$false;$has=$gate.RdpResults.TryGetValue($s.Key,[ref]$passed)
                        $shown=[datetime]::MinValue
                        if($entry.Prompted -and $gate.RdpShown.TryGetValue($s.Key,[ref]$shown)){$entry.Deadline=$shown.ToLocalTime().AddSeconds($cfg.ResponseSeconds)}
                        $dead=$entry.Prompted -and -not(Get-Process -Id $entry.PromptPid -ErrorAction SilentlyContinue)
                        $expired=$entry.Prompted -and (($entry.Deadline -and $now -ge $entry.Deadline) -or (-not $entry.Deadline -and $now -ge $entry.LaunchDeadline))
                        $answered=[datetime]::MinValue;$onTime=$entry.Deadline -and $gate.RdpAnswered.TryGetValue($s.Key,[ref]$answered) -and $answered.ToLocalTime() -le $entry.Deadline
                        if($entry.Prompted -and $has -and $passed -and $onTime){$verified+= $s.Key;Write-Json $verifiedPath @{Boot=$boot;Keys=$verified};Audit "VERIFIED Rdp session=$($s.Id)"}
                        elseif(($has -and -not $passed) -or $expired -or $dead){
                            # Re-enumerate before acting: never log off a reused session ID.
                            $still=@([SessionNative]::Sessions()|Where-Object Key -eq $s.Key)
                            if($still.Count){[SessionNative]::Logoff($s.Id);Audit "DENIED Rdp session=$($s.Id)"}
                        }
                    }
                    foreach($key in @($state.Keys)){if($key -notin $live){$state.Remove($key);$value=$false;[void]$gate.RdpResults.TryRemove($key,[ref]$value);$stamp=[datetime]::MinValue;[void]$gate.RdpShown.TryRemove($key,[ref]$stamp);[void]$gate.RdpAnswered.TryRemove($key,[ref]$stamp)}}
                    # A disconnect removes the verification entry; a new login/reconnect is challenged again.
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
    if(-not $task){'Session is not installed.';return}
    $cfg=Get-Content $publicPath -Raw|ConvertFrom-Json
    $last=$null;$age=$null
    if(Test-Path (Join-Path $root 'status.json')){$last=Get-Content (Join-Path $root 'status.json') -Raw|ConvertFrom-Json;$age=((Get-Date).ToUniversalTime()-([datetimeoffset]$last.Time).UtcDateTime).TotalSeconds}
    [pscustomobject]@{Task=$taskName;State=[string]$task.State;Healthy=[bool]($task.State -eq 'Running' -and $null -ne $age -and $age -ge 0 -and $age -lt 15 -and $last.Healthy);HeartbeatAgeSeconds=$age;Services=$cfg.Services;Errors=$last.Errors;Directory=$root;WinRmMode=(Get-Content $manifestPath -Raw|ConvertFrom-Json).WinRmMode}
    return
}
if($Action -eq 'Uninstall'){
    Plain $root
    if(-not(Test-Path $manifestPath)){throw 'No rollback record found. Nothing was removed.'}
    $manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json
    if($manifest.State -eq 'Removed'){'Already removed.';return}
    Restore-Settings $manifest
    End-Guard
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe'"|Where-Object {$_.CommandLine -like ('*'+$installed+'* -Action Prompt*')}|ForEach-Object {Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
    $manifest.State='Removed';Write-Json $manifestPath $manifest
    'Session removed; popup/task removed and original SSH/WinRM settings restored. Private rollback files retained.'
    return
}

# INSTALL: validate everything before changing services. Existing SSH/WinRM sessions must be absent for the one-time reload.
Plain $root
Plain $manifestPath
if(Test-Path $root){
    foreach($item in Get-ChildItem -LiteralPath $root -Force -Recurse){Plain $item.FullName}
    if(-not(Test-Path $manifestPath) -and @(Get-ChildItem -LiteralPath $root -Force).Count){throw 'An unrecognized nonempty Session directory exists. Inspect it before installing.'}
}
if(Test-Path $manifestPath){$old=Get-Content $manifestPath -Raw|ConvertFrom-Json;if($old.State -ne 'Removed'){Repair-Session;if($VerificationCode){Set-SessionCode $VerificationCode;End-Guard;Repair-Session};return}}
if(Get-ScheduledTask -TaskName 'NewSession-Guard' -ErrorAction SilentlyContinue){throw 'Remove the old NewSession guard with its original script before installing session.'}
if(Get-ScheduledTask -TaskName 'CDT-RdpGuard-Watch' -ErrorAction SilentlyContinue){throw 'The older RdpGuard is still installed. Remove it and restore its SSH/WinRM settings before installing Session.'}
if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'An existing Session task must be reviewed/removed first.'}
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

$effective=@();if($Services -contains 'Rdp'){$effective+='Rdp'}
$manifest=[pscustomobject]@{Version=3;State='Installing';Ssh=$null;Endpoints=@();WinRmService=(Save-ServiceState 'WinRM');WinRmMode='Pending';SshService=(Save-ServiceState 'sshd');ManagedFiles=@()}
$sshShell="$env:SystemRoot\System32\cmd.exe";$sshShellOption='/c'
$sshSvc=Get-Service sshd -ErrorAction SilentlyContinue
$winSvc=Get-Service WinRM -ErrorAction SilentlyContinue
$enableSsh=$Services -contains 'Ssh' -and [bool]$sshSvc
$enableWin=$Services -contains 'WinRm' -and $winSvc -and $winSvc.Status -eq 'Running'
Assert-NoRemoteSessions $enableSsh $enableWin
$sshNew=$null
if($enableSsh){
    $sshPath=Join-Path $env:ProgramData 'ssh\sshd_config';Plain $sshPath
    $svc=Get-CimInstance Win32_Service -Filter "Name='sshd'"
    if($svc.PathName -match '^"([^"]+)"\s*$'){$sshExe=$Matches[1]}elseif($svc.PathName -match '^([^" ]+\.exe)\s*$'){$sshExe=$Matches[1]}else{throw 'Custom sshd service arguments are not supported. No configuration was changed.'}
    Plain $sshExe
    $before=Get-Content -LiteralPath $sshPath -Raw
    if($before -match '(?im)^\s*(ForceCommand|Include)\s' -or $before -match 'tyrdp2|Session managed'){throw 'Existing SSH ForceCommand/Include/old guard requires manual review before Session installation.'}
    $pattern='*'
    $sshNew=$before.TrimEnd()+"`r`n`r`n# Session managed`r`nMatch User $pattern`r`n    ForceCommand $powerShell -NoProfile -ExecutionPolicy Bypass -File $installed -Action SshGate`r`n    DisableForwarding yes`r`n# End Session managed`r`n"
    $reg=Get-ItemProperty 'HKLM:\SOFTWARE\OpenSSH' -ErrorAction SilentlyContinue
    if($reg -and $reg.PSObject.Properties['DefaultShell']){$sshShell=[string]$reg.DefaultShell;$sshShellOption=if($sshShell -match '(powershell|pwsh)\.exe$'){'-Command'}elseif($sshShell -match 'cmd\.exe$'){'/c'}else{'-c'}}
    if($reg -and $reg.PSObject.Properties['DefaultShellCommandOption']){$sshShellOption=[string]$reg.DefaultShellCommandOption}
    $manifest.Ssh=[pscustomobject]@{Path=$sshPath;Exe=$sshExe;BeforeBytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes($sshPath));BeforeHash=(Get-FileHash $sshPath).Hash;AfterHash=''}
    $effective+='Ssh'
}elseif($Services -contains 'Ssh'){Write-Warning 'OpenSSH Server is not installed. RDP protection will still be installed; no SSH listener was added.'}
if($enableWin){
    foreach($ep in @(Get-PSSessionConfiguration | Where-Object Name -in @('Microsoft.PowerShell','Microsoft.PowerShell32'))){
        if($ep.PSObject.Properties['RunAsUser'] -and $ep.RunAsUser){continue}
        $oldStartup=Get-Startup $ep
        if($oldStartup){Plain $oldStartup;if(-not(Test-Path $oldStartup -PathType Leaf)){throw "Missing existing startup script: $oldStartup"}}
        $manifest.Endpoints+= [pscustomobject]@{Name=$ep.Name;Before=$oldStartup;Hook=(Join-Path $root ($ep.Name+'.ps1'))}
    }

    $effective+='WinRm'
}elseif($Services -contains 'WinRm'){Write-Warning 'WinRM is not running; setup will still ensure its service is disabled.'}
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
# A copy of a browser-downloaded script keeps its internet-zone mark. The WinRM startup hook runs this file without
# -ExecutionPolicy Bypass, so under RemoteSigned the mark would make every remoting session fail. Clear it.
Unblock-File -LiteralPath $installed -ErrorAction SilentlyContinue
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
public static class SessionNative {
 [StructLayout(LayoutKind.Sequential)] struct WTS { public int Id; public IntPtr Name; public int State; }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct SI {public int cb; public string reserved, desktop, title; public int x,y,xs,ys,xc,yc,fill,flags; public short show,res2; public IntPtr reserved2,input,output,error;}
 [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr process,thread; public int pid,tid; }
 [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSEnumerateSessions(IntPtr h,int r,int v,out IntPtr p,out int n);
 [DllImport("wtsapi32.dll",EntryPoint="WTSQuerySessionInformationW",ExactSpelling=true,SetLastError=true)] static extern bool WTSQuerySessionInformation(IntPtr h,int id,int cls,out IntPtr p,out int n);
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
 static string ConnectionStamp(int session) {
  IntPtr p;int n;if(!WTSQuerySessionInformation(IntPtr.Zero,session,16,out p,out n))return "0";
  short protocol;try{protocol=Marshal.ReadInt16(p);}finally{WTSFreeMemory(p);}if(protocol!=2)return "0";
  if(!WTSQuerySessionInformation(IntPtr.Zero,session,24,out p,out n))throw new Win32Exception();
  try{if(n<40)throw new InvalidDataException("Short WTSINFO response");return Marshal.ReadInt64(p,n-40).ToString("X");}finally{WTSFreeMemory(p);}
 }
 static string TokenKey(IntPtr token,int session) {
  IntPtr p=Marshal.AllocHGlobal(128); try {int needed;if(!GetTokenInformation(token,10,p,128,out needed))throw new Win32Exception();
   using(var id=new WindowsIdentity(token))return session+":"+Marshal.ReadInt64(p,8).ToString("X")+":"+id.User.Value+":"+ConnectionStamp(session);
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
 public static int Prompt(int session,string script,int seconds) {
  IntPtr token;if(!WTSQueryUserToken(session,out token))throw new Win32Exception();IntPtr env=IntPtr.Zero;
  try {if(!CreateEnvironmentBlock(out env,token,false))throw new Win32Exception();
   string exe=Environment.GetFolderPath(Environment.SpecialFolder.System)+@"\WindowsPowerShell\v1.0\powershell.exe";
   var si=new SI{cb=Marshal.SizeOf(typeof(SI)),desktop=@"winsta0\default"};PI pi;
   var cmd=new StringBuilder("\""+exe+"\" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -STA -File \""+script+"\" -Action Prompt -ResponseSeconds "+seconds);
   if(!CreateProcessAsUser(token,exe,cmd,IntPtr.Zero,IntPtr.Zero,false,0x400,env,Path.GetDirectoryName(script),ref si,out pi))throw new Win32Exception();
   CloseHandle(pi.process);CloseHandle(pi.thread);return pi.pid;
  } finally {if(env!=IntPtr.Zero)DestroyEnvironmentBlock(env);CloseHandle(token);}
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
  using(var pipe=new NamedPipeClientStream(".","Session-Verify-v1",PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification)) {
   pipe.Connect(4000);
   if(((SecurityIdentifier)pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier))).Value!="S-1-5-18")throw new InvalidOperationException("Verification pipe is not owned by SYSTEM.");
   byte[] data=Encoding.UTF8.GetBytes(kind+":"+Convert.ToBase64String(Encoding.UTF8.GetBytes(code??""))+"\n");pipe.Write(data,0,data.Length);pipe.Flush();return ReadLine(pipe,5000)=="OK";
  }
 }
 public sealed class Verifier : IDisposable {
  readonly string salt,hash;readonly int iterations;Thread thread;volatile bool stop;public volatile bool Alive;public string Error="";
  public ConcurrentDictionary<string,DateTime> RdpAnswered=new ConcurrentDictionary<string,DateTime>();
  public ConcurrentDictionary<string,DateTime> RdpShown=new ConcurrentDictionary<string,DateTime>();
  public ConcurrentDictionary<string,bool> RdpResults=new ConcurrentDictionary<string,bool>();
  public Verifier(string s,string h,int i){salt=s;hash=h;iterations=i;thread=new Thread(Loop);thread.IsBackground=true;thread.Start();}
  void Loop() {try {while(!stop) {
   var acl=new PipeSecurity();acl.SetOwner(new SecurityIdentifier("S-1-5-18"));acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-5-18"),PipeAccessRights.FullControl,AccessControlType.Allow));acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-5-32-544"),PipeAccessRights.FullControl,AccessControlType.Allow));acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("S-1-5-11"),PipeAccessRights.ReadWrite,AccessControlType.Allow));
   using(var pipe=new NamedPipeServerStream("Session-Verify-v1",PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,4096,acl)) {
    Alive=true;pipe.WaitForConnection();if(stop)break;
    try {uint client;if(!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(),out client))throw new Win32Exception();string key;ProcessIdentity(client,out key);
     string line=ReadLine(pipe,2000);int split=line.IndexOf(':');if(split<0)throw new InvalidDataException();string kind=line.Substring(0,split);if(kind!="Rdp"&&kind!="RdpReady"&&kind!="Ssh"&&kind!="WinRm")throw new InvalidDataException();
     string code=Encoding.UTF8.GetString(Convert.FromBase64String(line.Substring(split+1)));bool pass=kind=="RdpReady"||MatchCode(code,salt,hash,iterations);code=null;
     if(kind=="RdpReady")RdpShown.TryAdd(key,DateTime.UtcNow);
     if(kind=="Rdp" && RdpAnswered.TryAdd(key,DateTime.UtcNow))RdpResults.TryAdd(key,pass);
     byte[] data=Encoding.ASCII.GetBytes(pass?"OK\n":"NO\n");pipe.Write(data,0,data.Length);pipe.Flush();
    }catch(Exception){ /* A failed/malformed request grants nothing. Never log secret data. */ }
   }
  }}catch(Exception e){Error=e.GetType().Name+": "+e.Message;}finally{Alive=false;}}
  public void Dispose(){stop=true;try{using(var p=new NamedPipeClientStream(".","Session-Verify-v1",PipeDirection.InOut)){p.Connect(1000);}}catch{}thread.Join(3000);}
 }
}
'@
$nativeSource | Set-Content -LiteralPath (Join-Path $root 'Native.cs') -Encoding UTF8
Secure-Path (Join-Path $root 'Native.cs') -Readable
$grey=@(Resolve-GreyIdentities $GreyAccounts)
Write-Json $publicPath @{Version=2;Services=$effective;GraceSeconds=$GraceSeconds;ResponseSeconds=$ResponseSeconds;SshShell=$sshShell;SshShellOption=$sshShellOption;GreySids=@($grey | ForEach-Object Sid);GreyAccounts=@($grey | ForEach-Object Account)}
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
    if($manifest.Ssh){
        $manifest.SshService.Changed=$true
        if($manifest.SshService.StartMode -eq 'Disabled'){$manifest.SshService.ExpectedMode='Manual'}
        Write-Json $manifestPath $manifest
        Copy-Item -LiteralPath $candidate -Destination $manifest.Ssh.Path -Force
        if($manifest.SshService.StartMode -eq 'Disabled'){Set-Service sshd -StartupType Manual -ErrorAction Stop}
        Restart-Service sshd -ErrorAction Stop
    }
    if(Stop-WinRm $manifest){
        $manifest.Endpoints=@();$effective=@($effective|Where-Object {$_ -ne 'WinRm'})
    }else{
        if(-not @($manifest.Endpoints).Count){throw 'WinRM could not be disabled and no safe fallback endpoints are available.'}
        foreach($ep in $manifest.Endpoints){Set-PSSessionConfiguration -Name $ep.Name -StartupScript $ep.Hook -NoServiceRestart -Force|Out-Null}
        Restart-Service WinRM -ErrorAction Stop
        Write-Warning 'WinRM remains enabled: only Microsoft.PowerShell/32 startup endpoints are gated. WinRS/custom endpoints are NOT protected. Do not treat this fallback as full WinRM protection.'
    }
    $cfg=Get-Content $publicPath -Raw|ConvertFrom-Json;$cfg.Services=@($effective);Write-Json $publicPath $cfg
    $repair=Join-Path $root 'repair';New-Item -ItemType Directory -Path $repair -Force|Out-Null;Secure-Path $repair
    foreach($path in @($installed,(Join-Path $root 'Native.cs'),$publicPath)+@($manifest.Endpoints|ForEach-Object Hook)){
        $copy=Join-Path $repair ([IO.Path]::GetFileName($path));Copy-Item -LiteralPath $path -Destination $copy -Force;Secure-Path $copy
        $manifest.ManagedFiles+= [pscustomobject]@{Path=$path;Backup=$copy;Hash=(Get-FileHash $path).Hash}
    }
    $manifest.State='Active';Write-Json $manifestPath $manifest
    Write-Host ('Session installed: RDP popup + SSH terminal gate (when sshd is installed); WinRM mode: '+$manifest.WinRmMode+'. Only non-Grey users are challenged. Console/RustDesk stays available.')
    & $installed -Action Status
}catch{
    $failure=$_.Exception.Message
    if($changed){try{Restore-Settings $manifest}catch{throw "Installation incomplete: $failure. Rollback blocked: $($_.Exception.Message). Keep the guard running and inspect $manifestPath."}}
    End-Guard;$manifest.State='Removed';Write-Json $manifestPath $manifest
    throw "Installation failed; settings rolled back: $failure"
}

}
return $engine.ToString()
}
$root=Join-Path $env:ProgramData 'Session'
$record=Join-Path $root 'rollback.json'
$work=Join-Path $env:ProgramData 'Session-Setup';Protect-Setup $work
$engine=Join-Path $work 'session-engine.ps1'
if(Test-Path $engine){if((Get-Item $engine -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Setup engine is a reparse point.'}}
Get-SessionEngineSource|Set-Content -LiteralPath $engine -Encoding UTF8
if($Remove){
    if(-not(Test-Path $record)){Write-Host 'Session is not installed.';return}
    & $engine -Action Uninstall
    return
}
$code=$null
try{
    $existing=if(Test-Path $record){Get-Content $record -Raw|ConvertFrom-Json}else{$null}
    if($Ask){$code=Read-Host 'Separate verification password (12-256 characters)' -AsSecureString}
    elseif(-not $existing -or $existing.State -eq 'Removed'){$code=ConvertTo-SecureString $UserPassword -AsPlainText -Force}
    $arguments=@{Action='Install';GraceSeconds=15;ResponseSeconds=15;Services=@('Rdp','Ssh','WinRm');GreyAccounts=$GreyTeamUsers}
    if($code){$arguments.VerificationCode=$code}
    & $engine @arguments
}finally{if($code){$code.Dispose()};$UserPassword=$null}
