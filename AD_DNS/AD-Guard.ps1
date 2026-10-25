#requires -Version 5.1
#requires -RunAsAdministrator
<#
AD account watcher with manual account containment. Run locally on the DC in Windows PowerShell.
First run: review/save current users, then monitor every 10 seconds.
B = review/update baseline; K = disable selected account + best-effort Windows session sweep; Q = quit. Keep the console open.
Alerts once per account per accepted baseline, including across script restarts.
Only users ENABLED in the baseline are watched for disabling (not built-in Guest).
Times are FIRST OBSERVED times, not the exact time an attacker made a change.
Monitoring is read-only. K explicitly disables ONE selected account and terminates its sessions/processes. This inventory is NOT a recoverable AD backup:
it contains no passwords, groups, GPOs, AD database or System State.
#>
[CmdletBinding()]
param([ValidateRange(2,300)][int]$IntervalSeconds=10)
$ErrorActionPreference='Stop'
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic
$server=$env:COMPUTERNAME
if((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4){throw 'Run this on the domain controller.'}
$domain=Get-ADDomain -Server $server
$store=Join-Path $env:ProgramData 'AD-DisabledWatch'
$desktop=[Environment]::GetFolderPath('Desktop')
if(-not $desktop){throw 'No Desktop found. Run interactively as your logged-in admin user.'}
$logDir=Join-Path $desktop 'AD-Watch'
$baselineFile=Join-Path $store 'baseline.xml'
$alertFile=Join-Path $store 'alerted.xml'
$logFile=Join-Path $logDir 'Disabled-Accounts.txt'
$mutex=New-Object Threading.Mutex($false,'Global\ADDisabledWatch')
try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
if(-not $held){$mutex.Dispose();throw 'The watcher is already running. Use its window.'}
function Log($text){
    $line='[{0}] {1}' -f ([DateTimeOffset]::Now.ToString('yyyy-MM-dd HH:mm:ss zzz')),$text
    Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8
    Write-Host $line
}
function Get-Users {
    @(Get-ADUser -Filter * -Server $server -Properties Enabled,whenCreated |
        Select-Object @{n='GUID';e={$_.ObjectGUID.ToString()}},SamAccountName,Enabled,DistinguishedName,whenCreated)
}
function Find-NewDisabled($baselineUsers,$liveUsers,$alreadyAlerted){
    $live=@{};foreach($user in $liveUsers){$live[$user.GUID]=$user}
    foreach($user in $baselineUsers){
        if($user.Enabled -eq $true -and $live.ContainsKey($user.GUID) -and
           $live[$user.GUID].Enabled -eq $false -and -not $alreadyAlerted.ContainsKey($user.GUID)){
            $live[$user.GUID]
        }
    }
}
function Save-Alerts {
    [pscustomobject]@{BaselineID=$script:baseline.ID;GUIDs=@($script:alerted.Keys);NewGUIDs=@($script:newAlerted.Keys)} |
        Export-Clixml "$alertFile.new"
    Move-Item "$alertFile.new" $alertFile -Force
}
function Update-Baseline {
    # No watcher runs concurrently while this dialog is open.
    $users=Get-Users
    $id=[guid]::NewGuid().ToString()
    $candidate=Join-Path $store ('users-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff')+'.csv')
    $users | Export-Csv -LiteralPath $candidate -NoTypeInformation -Encoding UTF8
    Start-Process notepad.exe -ArgumentList ('"'+$candidate+'"')
    $message="Review the user list opened in Notepad.`r`n`r`nAccept CURRENT account states as the new baseline? Only currently ENABLED users will be watched. Disabled accounts will not generate alerts.`r`n`r`nThis resets one-time alerts and keeps the old user lists. Clean up unwanted accounts BEFORE accepting. Monitoring is paused while this dialog is open."
    $answer=[System.Windows.Forms.MessageBox]::Show($message,'AD baseline','YesNo','Warning','Button2')
    if($answer -ne 'Yes'){return $false}
    $new=[pscustomobject]@{ID=$id;DomainSID=$domain.DomainSID.Value;DC=$server;Captured=[DateTimeOffset]::Now.ToString('o');Users=$users}
    $new | Export-Clixml "$baselineFile.new" -Depth 5
    if(Test-Path $baselineFile){Copy-Item $baselineFile (Join-Path $store "baseline-before-$id.xml")}
    Move-Item "$baselineFile.new" $baselineFile -Force
    $script:baseline=$new
    $script:alerted=@{}
    $script:newAlerted=@{}
    Save-Alerts
    Log "BASELINE ACCEPTED: $(@($users | Where-Object Enabled -eq $true).Count) enabled users watched. Inventory: $candidate"
    return $true
}
# Runs on each Windows host under the operator's administrative credentials.
$script:ContainWorker = {
    param([string]$TargetSID)
    $ErrorActionPreference='Stop'
    if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq $TargetSID){throw 'Refusing to terminate the worker/operator identity.'}
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class ADGuardWTS {
 [StructLayout(LayoutKind.Sequential)] struct Info { public int Id; public IntPtr Name; public int State; }
 [DllImport("wtsapi32.dll", EntryPoint="WTSEnumerateSessionsW", SetLastError=true)] static extern bool Enum(IntPtr h,int reserved,int version,out IntPtr p,out int count);
 [DllImport("wtsapi32.dll", EntryPoint="WTSQuerySessionInformationW", SetLastError=true)] static extern bool Query(IntPtr h,int id,int cls,out IntPtr p,out int bytes);
 [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
 [DllImport("wtsapi32.dll", SetLastError=true)] public static extern bool WTSLogoffSession(IntPtr h,int id,bool wait);
 static string Text(int id,int cls) { IntPtr p;int n;if(!Query(IntPtr.Zero,id,cls,out p,out n))throw new System.ComponentModel.Win32Exception();try{return Marshal.PtrToStringUni(p) ?? "";}finally{WTSFreeMemory(p);} }
 public static string Sid(int id) { string user=Text(id,5);if(user.Length==0)return "";string domain=Text(id,7);return ((SecurityIdentifier)new NTAccount(domain,user).Translate(typeof(SecurityIdentifier))).Value; }
 public static int[] Sessions() { IntPtr p;int n;if(!Enum(IntPtr.Zero,0,1,out p,out n))throw new System.ComponentModel.Win32Exception();try{var list=new List<int>();int size=Marshal.SizeOf(typeof(Info));for(int i=0;i<n;i++){Info row=(Info)Marshal.PtrToStructure(IntPtr.Add(p,i*size),typeof(Info));if(row.Id>0)list.Add(row.Id);}return list.ToArray();}finally{WTSFreeMemory(p);} }
}
'@
    # RDP and console: exact SID match, including disconnected sessions.
    try{
        foreach($sessionID in [ADGuardWTS]::Sessions()){
            try{
                if([ADGuardWTS]::Sid($sessionID) -eq $TargetSID){
                    if([ADGuardWTS]::WTSLogoffSession([IntPtr]::Zero,$sessionID,$false)){"LOGOFF REQUESTED: session $sessionID"}
                    else{"ERROR logoff session $sessionID : $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"}
                }
            }catch{"SESSION QUERY ERROR $sessionID : $_"}
        }
    }catch{"WTS ERROR: $_"}
    # SMB sessions hosted on this machine. Resolve full account names to SIDs.
    try{
        foreach($s in @(Get-SmbSession)){
            try{
                $sid=([Security.Principal.NTAccount]::new($s.ClientUserName)).Translate([Security.Principal.SecurityIdentifier]).Value
                if($sid -eq $TargetSID){Close-SmbSession -SessionId $s.SessionId -Force;"SMB CLOSED: session $($s.SessionId)"}
            }catch{"SMB QUERY/CLOSE ERROR session $($s.SessionId): $_"}
        }
    }catch{"SMB ERROR: $_"}
    # User-owned processes include Windows SSH shells and many user-run WinRM jobs.
    # Never kill SYSTEM sshd, shared services, or a same-named local account.
    $ownerErrors=0
    try{
        foreach($p in @(Get-CimInstance Win32_Process)){
            try{
                $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
                if($owner.ReturnValue -ne 0){$ownerErrors++;continue}
                if($owner.Sid -ne $TargetSID){continue}
                # Re-read and compare creation time and SID to avoid PID reuse.
                $fresh=Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ProcessId)"
                if(-not $fresh -or $fresh.CreationDate -ne $p.CreationDate){continue}
                $again=Invoke-CimMethod -InputObject $fresh -MethodName GetOwnerSid
                if($again.ReturnValue -eq 0 -and $again.Sid -eq $TargetSID){
                    $result=Invoke-CimMethod -InputObject $fresh -MethodName Terminate -Arguments @{Reason=[uint32]1}
                    if($result.ReturnValue -eq 0){"PROCESS TERMINATED: $($p.Name) PID $($p.ProcessId)"}else{"PROCESS TERMINATION FAILED: PID $($p.ProcessId) code $($result.ReturnValue)"}
                }
            }catch{$ownerErrors++}
        }
        "PROCESS SCAN: $ownerErrors inaccessible/exited processes (coverage may be incomplete)."
    }catch{"PROCESS SCAN ERROR: $_"}
    Start-Sleep -Seconds 2
    $left=0
    try{foreach($id in [ADGuardWTS]::Sessions()){try{if([ADGuardWTS]::Sid($id) -eq $TargetSID){$left++}}catch{"VERIFY SESSION ERROR $id : $_"}};"VERIFY: $left matching RDP/console sessions remain."}catch{"VERIFY WTS ERROR: $_"}
    $remaining=0;$unknown=0
    try{foreach($p in @(Get-CimInstance Win32_Process)){try{$o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid;if($o.ReturnValue -ne 0){$unknown++}elseif($o.Sid -eq $TargetSID){$remaining++}}catch{$unknown++}};"VERIFY: $remaining matching processes remain; $unknown owners could not be verified."}catch{"VERIFY PROCESS ERROR: $_"}
    $smbLeft=0;$smbUnknown=0
    try{foreach($s in @(Get-SmbSession)){try{if(([Security.Principal.NTAccount]::new($s.ClientUserName)).Translate([Security.Principal.SecurityIdentifier]).Value -eq $TargetSID){$smbLeft++}}catch{$smbUnknown++}};"VERIFY: $smbLeft matching SMB sessions remain; $smbUnknown identities unverified."}catch{"VERIFY SMB ERROR: $_"}
    'HOST PASS FINISHED: this is not proof of universal session/token revocation. SYSTEM-owned SSH transport, application sessions and sessions on other/unreachable hosts may remain.'
}
$script:containJobs=@()
$script:killRequested=$false
function Contain-Log($message){
    $line='[{0}] {1}' -f ([DateTimeOffset]::Now.ToString('yyyy-MM-dd HH:mm:ss zzz')),$message
    Add-Content -LiteralPath (Join-Path $logDir 'Containment.txt') -Value $line -Encoding UTF8
    Write-Host $line
}
function Find-NewAccounts($baselineUsers,$liveUsers,$seenNew){
    $known=@{};foreach($u in $baselineUsers){$known[$u.GUID]=$true}
    foreach($u in $liveUsers){if(-not $known.ContainsKey($u.GUID) -and -not $seenNew.ContainsKey($u.GUID)){$u}}
}
function Start-Containment {
    if($script:containJobs.Count){[System.Windows.Forms.MessageBox]::Show('The previous account sweep is still running. Results appear in Desktop\AD-Watch\Containment.txt.','AD Guard') | Out-Null;return}
    $users=@(Get-ADUser -Filter * -Server $server -Properties whenCreated | Sort-Object SamAccountName)
    $dialog=New-Object System.Windows.Forms.Form
    $dialog.Text='K - Disable account and end sessions';$dialog.Width=490;$dialog.Height=165;$dialog.StartPosition='CenterScreen';$dialog.TopMost=$true
    $label=New-Object System.Windows.Forms.Label
    $label.Text='Select ONE AD username:';$label.Left=15;$label.Top=12;$label.Width=420
    $pick=New-Object System.Windows.Forms.ComboBox
    $pick.Left=15;$pick.Top=38;$pick.Width=440;$pick.DropDownStyle='DropDownList'
    foreach($u in $users){[void]$pick.Items.Add($u.SamAccountName)}
    $button=New-Object System.Windows.Forms.Button
    $button.Text='Select';$button.Left=280;$button.Top=78;$button.DialogResult='OK'
    $cancel=New-Object System.Windows.Forms.Button
    $cancel.Text='Cancel';$cancel.Left=375;$cancel.Top=78;$cancel.DialogResult='Cancel'
    $dialog.Controls.AddRange(@($label,$pick,$button,$cancel));$dialog.AcceptButton=$button;$dialog.CancelButton=$cancel
    try{if($dialog.ShowDialog($form) -ne 'OK' -or $null -eq $pick.SelectedItem){return};$name=[string]$pick.SelectedItem}finally{$dialog.Dispose()}
    $selected=$users | Where-Object SamAccountName -eq $name
    # Pin the operation to GUID/SID so a renamed/replaced username cannot change the target.
    $target=Get-ADUser -Identity $selected.ObjectGUID -Server $server -Properties SID,UserPrincipalName
    $sid=$target.SID.Value
    if($sid -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'Refusing to disable the account running this watcher.'}
    if($sid -match '-(500|502)$'){throw 'Built-in domain Administrator and krbtgt are excluded from this shortcut.'}
    $computers=@(Get-ADComputer -Filter * -Server $server -Properties DNSHostName,OperatingSystem)
    $hosts=@($server)+@($computers | Where-Object {(-not $_.OperatingSystem -or $_.OperatingSystem -like '*Windows*') -and $_.Name -ine $server} | ForEach-Object {if($_.DNSHostName){$_.DNSHostName}else{$_.Name}})
    $hosts=@($hosts | Sort-Object -Unique)
    $msg="Disable $($domain.NetBIOSName)\$($target.SamAccountName)?`r`nSID: $sid`r`n`r`nThen attempt logoff of matching RDP/console sessions, close SMB sessions, and terminate processes owned by this SID (including Windows SSH shells) on $($hosts.Count) Windows/unknown-OS domain computers.`r`n`r`nUnsaved work and applications/services running as this user may be lost. Offline hosts, blocked WinRM, Linux SSH, existing tickets and SYSTEM-owned sessions are not guaranteed covered. Proceed?"
    if([System.Windows.Forms.MessageBox]::Show($form,$msg,'Confirm selected account','YesNo','Warning','Button2') -ne 'Yes'){return}
    Disable-ADAccount -Identity $target.ObjectGUID -Server $server
    if((Get-ADUser -Identity $target.ObjectGUID -Server $server).Enabled){throw 'Account disable did not verify. No host sweep started.'}
    Contain-Log "DISABLED AND VERIFIED: $($target.SamAccountName) SID=$sid on DC $server. Beginning host sweep."
    foreach($c in $computers | Where-Object {$_.OperatingSystem -and $_.OperatingSystem -notlike '*Windows*'}){Contain-Log "SKIPPED NON-WINDOWS: $($c.Name) ($($c.OperatingSystem)). SSH sessions not covered."}
    foreach($computer in $hosts){
        try{
            $job=Start-Job -ScriptBlock {
                param($computer,$localName,$workerText,$targetSID)
                $ErrorActionPreference='Stop'
                $worker=[scriptblock]::Create($workerText)
                if($computer -ieq $localName){& $worker $targetSID}
                else{$options=New-PSSessionOption -OpenTimeout 8000 -OperationTimeout 15000;Invoke-Command -ComputerName $computer -ScriptBlock $worker -ArgumentList $targetSID -SessionOption $options -ErrorAction Stop}
            } -ArgumentList $computer,$server,$script:ContainWorker.ToString(),$sid
            $script:containJobs+= [pscustomobject]@{Computer=$computer;Job=$job;Started=Get-Date}
        }catch{Contain-Log "HOST START FAILED $computer : $_"}
    }
    Contain-Log 'Sweep runs in background; account monitoring continues. K can be used again after the sweep completes. The account stays disabled even if all remote operations fail.'
}
function Poll-Containment {
    foreach($entry in @($script:containJobs)){
        $job=$entry.Job
        $errors=@()
        foreach($line in @(Receive-Job $job -ErrorAction SilentlyContinue -ErrorVariable errors)){Contain-Log "[$($entry.Computer)] $line"}
        foreach($err in $errors){Contain-Log "[$($entry.Computer)] ERROR/UNREACHABLE: $err"}
        $timeout=((Get-Date)-$entry.Started).TotalSeconds -gt 120
        if($job.State -in @('Completed','Failed','Stopped') -or $timeout){
            if($timeout -and $job.State -eq 'Running'){Contain-Log "[$($entry.Computer)] TIMEOUT: incomplete; some remote actions may have occurred. Manual verification needed.";Stop-Job $job}
            Contain-Log "[$($entry.Computer)] Worker state: $($job.State)"
            Remove-Job $job -Force
            $script:containJobs=@($script:containJobs | Where-Object {$_.Job.Id -ne $job.Id})
            if(-not $script:containJobs.Count){Contain-Log 'SWEEP FINISHED. Review each host result above; failures/skipped hosts need manual action. Existing tickets are not globally revoked.'}
        }
    }
}

try{
    New-Item -ItemType Directory -Path $store,$logDir -Force | Out-Null
    & icacls.exe $store /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Could not protect the baseline directory.'}
    if(Test-Path $baselineFile){
        $script:baseline=Import-Clixml $baselineFile
        if($baseline.DomainSID -ne $domain.DomainSID.Value -or $baseline.DC -ne $server){throw 'Saved baseline is for a different domain/DC.'}
        $script:alerted=@{}
    $script:newAlerted=@{}
        if(Test-Path $alertFile){
            $saved=Import-Clixml $alertFile
            if($saved.BaselineID -eq $baseline.ID){foreach($id in $saved.GUIDs){$script:alerted[$id]=$true};foreach($id in $saved.NewGUIDs){$script:newAlerted[$id]=$true}}
        }
    }else{if(-not(Update-Baseline)){return}}
    # A single modeless window: closing it hides it, without stopping monitoring.
    # Each account is added once; no repetitive popups for an already-alerted user.
    $form=New-Object System.Windows.Forms.Form
    $form.Text='AD ALERT - new or disabled account'
    $form.Width=760;$form.Height=320;$form.StartPosition='CenterScreen'
    $form.TopMost=$true
    $box=New-Object System.Windows.Forms.TextBox
    $box.Multiline=$true;$box.ReadOnly=$true;$box.ScrollBars='Vertical';$box.Dock='Fill'
    $form.Controls.Add($box)
    $killButton=New-Object System.Windows.Forms.Button
    $killButton.Text='K - Select account to disable and end sessions';$killButton.Dock='Bottom';$killButton.Height=38
    $killButton.Add_Click({$script:killRequested=$true})
    $form.Controls.Add($killButton)
    $form.Add_FormClosing({param($sender,$eventArgs) $eventArgs.Cancel=$true;$sender.Hide()})
    Write-Host "Watching $($domain.DNSRoot) every $IntervalSeconds seconds. B = update baseline; K = disable + end sessions; Q = quit." -ForegroundColor Cyan
    Write-Host "Log: $logFile"
    Write-Host 'One alert per account per event type per baseline. K is manual containment. Detection times are approximate.'
    $nextCheck=Get-Date
    $queryFailed=$false
    $quit=$false
    while(-not $quit){
        [System.Windows.Forms.Application]::DoEvents()
        Poll-Containment
        if($script:killRequested){$script:killRequested=$false;try{Start-Containment}catch{Log "CONTAINMENT ERROR: $_"}}
        if([Console]::KeyAvailable){
            $key=[Console]::ReadKey($true).Key
            if($key -eq 'Q'){if($script:containJobs.Count){Contain-Log 'WATCHER EXIT: pending workers will be stopped; remote actions may be incomplete. Selected account remains disabled.'};$quit=$true;continue}
            if($key -eq 'K'){$script:killRequested=$true}
            if($key -eq 'B'){
                try{if(Update-Baseline){$box.Clear();$form.Hide()}}catch{Log "BASELINE UPDATE FAILED: $_"}
                $nextCheck=Get-Date
            }
        }
        if((Get-Date) -ge $nextCheck){
            # A failed query is never interpreted as disabled or deleted users.
            $live=$null
            try{
                $live=Get-Users
                if($queryFailed){Log 'MONITOR RECOVERED: AD queries are working again.';$queryFailed=$false}
            }catch{
                if(-not $queryFailed){
                    Log "MONITOR ERROR: cannot query AD. Disabled-account detection is unavailable until queries recover. $_"
                    $box.AppendText("MONITOR ERROR: Cannot query AD. See Desktop log.`r`n")
                    $form.Show();$form.Activate();$queryFailed=$true
                }
            }
            if($null -ne $live){
                $newAccounts=@(Find-NewAccounts $baseline.Users $live $newAlerted)
                foreach($user in $newAccounts){
                    $when=[DateTimeOffset]::Now.ToString('yyyy-MM-dd HH:mm:ss zzz')
                    Log "NEW ACCOUNT SINCE BASELINE: $($user.SamAccountName) | GUID: $($user.GUID) | AD whenCreated: $($user.whenCreated) | First observed now; not proof of malicious activity."
                    $box.AppendText("$when - NEW ACCOUNT: $($user.SamAccountName) | Created: $($user.whenCreated)`r`n")
                    $script:newAlerted[$user.GUID]=$true
                }
                $newAlerts=@(Find-NewDisabled $baseline.Users $live $alerted)
                foreach($user in $newAlerts){
                    $when=[DateTimeOffset]::Now.ToString('yyyy-MM-dd HH:mm:ss zzz')
                    Log "DISABLED ACCOUNT: $($user.SamAccountName) | GUID: $($user.GUID) | First observed disabled (not exact change time)."
                    $box.AppendText("$when - DISABLED: $($user.SamAccountName)`r`n")
                    $script:alerted[$user.GUID]=$true
                }
                if($newAlerts.Count -or $newAccounts.Count){
                    Save-Alerts
                    $form.Show();$form.Activate()
                }
            }
            $nextCheck=(Get-Date).AddSeconds($IntervalSeconds)
        }
        Start-Sleep -Milliseconds 200
    }
}finally{
    foreach($entry in @($script:containJobs)){Stop-Job $entry.Job -ErrorAction SilentlyContinue;Remove-Job $entry.Job -Force -ErrorAction SilentlyContinue}
    if($form){$form.Dispose()}
    if($held){$mutex.ReleaseMutex()}
    $mutex.Dispose()
}
