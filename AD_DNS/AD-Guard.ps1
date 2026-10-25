#requires -Version 5.1
#requires -RunAsAdministrator
<#
Simple AD disabled-account watcher. Run locally on the DC in Windows PowerShell.
First run: review/save current users, then monitor every 10 seconds.
B = review/update baseline; Q = quit. Keep the console open.
Alerts once per account per accepted baseline, including across script restarts.
Only users ENABLED in the baseline are watched for disabling (not built-in Guest).
Times are FIRST OBSERVED times, not the exact time an attacker made a change.
No accounts/services are modified. This inventory is NOT a recoverable AD backup:
it contains no passwords, groups, GPOs, AD database or System State.
#>
[CmdletBinding()]
param([ValidateRange(2,300)][int]$IntervalSeconds=10)
$ErrorActionPreference='Stop'
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Windows.Forms
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
    @(Get-ADUser -Filter * -Server $server -Properties Enabled |
        Select-Object @{n='GUID';e={$_.ObjectGUID.ToString()}},SamAccountName,Enabled,DistinguishedName)
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
    [pscustomobject]@{BaselineID=$script:baseline.ID;GUIDs=@($script:alerted.Keys)} |
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
    Save-Alerts
    Log "BASELINE ACCEPTED: $(@($users | Where-Object Enabled -eq $true).Count) enabled users watched. Inventory: $candidate"
    return $true
}
try{
    New-Item -ItemType Directory -Path $store,$logDir -Force | Out-Null
    & icacls.exe $store /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Could not protect the baseline directory.'}
    if(Test-Path $baselineFile){
        $script:baseline=Import-Clixml $baselineFile
        if($baseline.DomainSID -ne $domain.DomainSID.Value -or $baseline.DC -ne $server){throw 'Saved baseline is for a different domain/DC.'}
        $script:alerted=@{}
        if(Test-Path $alertFile){
            $saved=Import-Clixml $alertFile
            if($saved.BaselineID -eq $baseline.ID){foreach($id in $saved.GUIDs){$script:alerted[$id]=$true}}
        }
    }else{if(-not(Update-Baseline)){return}}
    # A single modeless window: closing it hides it, without stopping monitoring.
    # Each account is added once; no repetitive popups for an already-alerted user.
    $form=New-Object System.Windows.Forms.Form
    $form.Text='AD ALERT - account disabled'
    $form.Width=760;$form.Height=320;$form.StartPosition='CenterScreen'
    $form.TopMost=$true
    $box=New-Object System.Windows.Forms.TextBox
    $box.Multiline=$true;$box.ReadOnly=$true;$box.ScrollBars='Vertical';$box.Dock='Fill'
    $form.Controls.Add($box)
    $form.Add_FormClosing({param($sender,$eventArgs) $eventArgs.Cancel=$true;$sender.Hide()})
    Write-Host "Watching $($domain.DNSRoot) every $IntervalSeconds seconds. B = update baseline; Q = quit." -ForegroundColor Cyan
    Write-Host "Log: $logFile"
    Write-Host 'One alert per account per baseline. No repairs. Detection times are approximate.'
    $nextCheck=Get-Date
    $queryFailed=$false
    $quit=$false
    while(-not $quit){
        [System.Windows.Forms.Application]::DoEvents()
        if([Console]::KeyAvailable){
            $key=[Console]::ReadKey($true).Key
            if($key -eq 'Q'){$quit=$true;continue}
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
                $newAlerts=@(Find-NewDisabled $baseline.Users $live $alerted)
                foreach($user in $newAlerts){
                    $when=[DateTimeOffset]::Now.ToString('yyyy-MM-dd HH:mm:ss zzz')
                    Log "DISABLED ACCOUNT: $($user.SamAccountName) | GUID: $($user.GUID) | First observed disabled (not exact change time)."
                    $box.AppendText("$when - DISABLED: $($user.SamAccountName)`r`n")
                    $script:alerted[$user.GUID]=$true
                }
                if($newAlerts.Count){
                    Save-Alerts
                    $form.Show();$form.Activate()
                }
            }
            $nextCheck=(Get-Date).AddSeconds($IntervalSeconds)
        }
        Start-Sleep -Milliseconds 200
    }
}finally{
    if($form){$form.Dispose()}
    if($held){$mutex.ReleaseMutex()}
    $mutex.Dispose()
}
