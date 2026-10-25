#requires -Version 5.1
#requires -RunAsAdministrator
<#
DNS-Guard: local Windows Server 2019 DNS server, interactive PowerShell console.
B = backup/update baseline, R = restore one missing record, Q = quit.
Checks service, zones/settings, default-scope records, forwarders and recursion.
One alert per affected zone/record-set/setting per baseline, persisted across restarts.
No automatic repairs, service restarts, record deletions or machine restores.
Backup is record/configuration inventory, not AD System State: no DNS ACLs,
DNSSEC private keys, policies, custom scopes, or guaranteed owner restoration.
Manual restore supports A, AAAA, CNAME, PTR, SRV, MX, NS in existing primary zones.
Record timestamps and SOA serial increments are ignored as routine DNS activity.
Times in Desktop log are FIRST OBSERVED, not exact attack times.
#>
[CmdletBinding()]
param([ValidateRange(2,300)][int]$IntervalSeconds=10)
$ErrorActionPreference='Stop'
Import-Module DnsServer
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic
$server=$env:COMPUTERNAME
$store=Join-Path $env:ProgramData 'DNS-Guard'
$desktop=[Environment]::GetFolderPath('Desktop')
if(-not $desktop){throw 'Run interactively as your logged-in admin user.'}
$logDir=Join-Path $desktop 'DNS-Watch'
$logFile=Join-Path $logDir 'DNS-Changes.txt'
$activeFile=Join-Path $store 'active.xml'
$seenFile=Join-Path $store 'alerted.xml'
$mutex=New-Object Threading.Mutex($false,'Global\DNSGuardInteractive')
try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
if(-not $held){$mutex.Dispose();throw 'DNS-Guard is already running.'}
function Log($message){
    $line='[{0}] {1}' -f ([DateTimeOffset]::Now.ToString('yyyy-MM-dd HH:mm:ss zzz')),$message
    Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8
    Write-Host $line
}
function Json($value){ConvertTo-Json -InputObject $value -Depth 12 -Compress}
function Record-Key($record){('{0}|{1}|{2}' -f $record.Zone,$record.Name,$record.Type).ToLowerInvariant()}
function Record-Value($record){
    $d=[ordered]@{}
    foreach($p in @($record.Data.Keys | Sort-Object)){
        if($record.Type -eq 'SOA' -and $p -eq 'SerialNumber'){continue}
        $d[$p]=$record.Data[$p]
    }
    Json ([ordered]@{TTL=$record.TTL;Data=$d})
}
function Read-DNS {
    $zones=@(Get-DnsServerZone -ComputerName $server | Where-Object { -not $_.IsAutoCreated })
    $zoneList=@();$records=@()
    foreach($z in $zones){
        $settings=[ordered]@{}
        foreach($p in @('ZoneType','IsDsIntegrated','IsReverseLookupZone','IsPaused','IsShutdown','DynamicUpdate','ReplicationScope','SecureSecondaries','Notify','MasterServers','SecondaryServers','NotifyServers')){
            $settings[$p]=@($z.$p | ForEach-Object {[string]$_} | Sort-Object)
        }
        $zoneList+=[pscustomobject]@{Name=$z.ZoneName.ToLowerInvariant();Settings=(Json $settings)}
        if([string]$z.ZoneType -eq 'Forwarder'){continue}
        # If any query fails, fail the whole sample rather than infer mass deletions.
        foreach($r in @(Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ComputerName $server)){
            $data=[ordered]@{}
            foreach($p in @($r.RecordData.CimInstanceProperties | Sort-Object Name)){
                $values=@($p.Value | ForEach-Object {
                    $v=[string]$_
                    if($p.Name -match '^(HostNameAlias|PtrDomainName|DomainName|NameServer|MailExchange|PrimaryServer|ResponsiblePerson)$'){$v=$v.TrimEnd('.').ToLowerInvariant()+'.'}
                    $v
                })
                $data[$p.Name]=$values
            }
            $records+=[pscustomobject]@{Zone=$z.ZoneName.ToLowerInvariant();Name=$r.HostName.ToLowerInvariant();Type=[string]$r.RecordType;TTL=[long]$r.TimeToLive.TotalSeconds;Dynamic=($null -ne $r.Timestamp -and ([datetime]$r.Timestamp).Year -gt 1601);Data=$data}
        }
    }
    $f=Get-DnsServerForwarder -ComputerName $server
    $rec=Get-DnsServerRecursion -ComputerName $server
    $config=Json ([ordered]@{Forwarders=@($f.IPAddress | ForEach-Object {[string]$_} | Sort-Object);UseRootHint=$f.UseRootHint;ForwarderTimeout=$f.Timeout;RecursionEnabled=$rec.Enable})
    [pscustomobject]@{Zones=$zoneList;Records=$records;Config=$config}
}
function Compare-DNS($old,$now){
    $oz=@{};$nz=@{}
    foreach($z in $old.Zones){$oz[$z.Name]=$z};foreach($z in $now.Zones){$nz[$z.Name]=$z}
    foreach($name in $oz.Keys){
        if(-not $nz.ContainsKey($name)){[pscustomobject]@{Key="zone:$name";Detail="MISSING ZONE: $name"}}
        elseif($oz[$name].Settings -cne $nz[$name].Settings){[pscustomobject]@{Key="zone:$name";Detail="ZONE SETTINGS CHANGED: $name | Before: $($oz[$name].Settings) | Now: $($nz[$name].Settings)"}}
    }
    foreach($name in $nz.Keys){if(-not $oz.ContainsKey($name)){[pscustomobject]@{Key="zone:$name";Detail="NEW ZONE: $name"}}}
    $a=@{};$b=@{}
    foreach($r in $old.Records){$k=Record-Key $r;$a[$k]=@($a[$k])+(Record-Value $r)}
    foreach($r in $now.Records){$k=Record-Key $r;$b[$k]=@($b[$k])+(Record-Value $r)}
    foreach($k in @(@($a.Keys)+@($b.Keys) | Sort-Object -Unique)){
        $zone=($k -split '\|')[0]
        # One zone alert instead of hundreds of record alerts when a zone disappears.
        if(-not $oz.ContainsKey($zone) -or -not $nz.ContainsKey($zone)){continue}
        $before=Json @($a[$k] | Where-Object {$null -ne $_} | Sort-Object)
        $after=Json @($b[$k] | Where-Object {$null -ne $_} | Sort-Object)
        if($before -cne $after){
            $kind=if(-not $b.ContainsKey($k)){'MISSING'}elseif(-not $a.ContainsKey($k)){'NEW'}else{'CHANGED'}
            [pscustomobject]@{Key="record:$k";Detail="$kind RECORD SET: $k | Before: $before | Now: $after"}
        }
    }
    if($old.Config -cne $now.Config){[pscustomobject]@{Key='server:config';Detail="FORWARDERS/RECURSION CHANGED | Before: $($old.Config) | Now: $($now.Config)"}}
}
function Save-Seen {
    [pscustomobject]@{BaselineID=$script:baseline.ID;Keys=@($script:seen.Keys)} | Export-Clixml "$seenFile.new"
    Move-Item "$seenFile.new" $seenFile -Force
}
function Update-Baseline {
    $state=Read-DNS
    $id=[guid]::NewGuid().ToString()
    $folder=New-Item -ItemType Directory (Join-Path $store ('backup-'+(Get-Date -Format 'yyyyMMdd-HHmmss-fff')))
    $candidate=[pscustomobject]@{ID=$id;Server=$server;Captured=[DateTimeOffset]::Now.ToString('o');Folder=$folder.FullName;State=$state}
    $candidate | Export-Clixml "$folder\snapshot.xml" -Depth 20
    $state.Records | Select-Object Zone,Name,Type,TTL,Dynamic,@{n='Data';e={Json $_.Data}} | Export-Csv "$folder\records.csv" -NoTypeInformation -Encoding UTF8
    $state.Zones | Export-Csv "$folder\zones.csv" -NoTypeInformation -Encoding UTF8
    Set-Content "$folder\server-settings.txt" $state.Config -Encoding UTF8
    Start-Process notepad.exe -ArgumentList ('"'+$folder.FullName+'\records.csv"')
    $msg="DNS inventory saved to:`r`n$folder`r`n`r`nAccept these current records/settings as the baseline? Review records.csv, zones.csv and server-settings.txt first. Old backups are retained. Accepting resets one-time alerts.`r`n`r`nThis is a record/configuration backup, not a full AD backup. Monitoring is paused during this dialog."
    if([System.Windows.Forms.MessageBox]::Show($msg,'DNS baseline','YesNo','Warning','Button2') -ne 'Yes'){return $false}
    $candidate | Export-Clixml "$activeFile.new" -Depth 20
    Move-Item "$activeFile.new" $activeFile -Force
    $script:baseline=$candidate;$script:seen=@{};Save-Seen
    Log "BACKUP ACCEPTED: $($state.Zones.Count) zones, $($state.Records.Count) records. $folder"
    return $true
}
function Restore-Record {
    $current=Read-DNS
    $supported=@('A','AAAA','CNAME','PTR','SRV','MX','NS')
    $missing=@();$index=0
    foreach($r in $baseline.State.Records){
        if($r.Type -notin $supported){continue}
        $same=@($current.Records | Where-Object {(Record-Key $_) -eq (Record-Key $r)})
        # Conservative: do not add a competing value to a changed/multivalue record set.
        if($same.Count -eq 0 -and $r.Zone -in $current.Zones.Name){
            $index++;$missing+=[pscustomobject]@{Number=$index;Record=$r}
        }
    }
    if(-not $missing.Count){[System.Windows.Forms.MessageBox]::Show('No supported completely missing record sets in existing zones. Changed records or missing zones need manual review.','DNS restore') | Out-Null;return}
    $list=Join-Path $logDir 'Missing-Records.txt'
    $missing | ForEach-Object {"$($_.Number): $($_.Record.Zone) | $($_.Record.Name) | $($_.Record.Type) | $(Json $_.Record.Data)"} | Set-Content $list -Encoding UTF8
    Start-Process notepad.exe -ArgumentList ('"'+$list+'"')
    $choice=[Microsoft.VisualBasic.Interaction]::InputBox('Enter the number of ONE record from Missing-Records.txt. Cancel returns to monitoring.','Restore DNS record')
    if(-not $choice){return}
    $number=0
    if(-not [int]::TryParse($choice,[ref]$number) -or $number -lt 1 -or $number -gt $missing.Count){throw 'Invalid record number.'}
    $r=$missing[$number-1].Record
    if([System.Windows.Forms.MessageBox]::Show("Restore $($r.Name) [$($r.Type)] in $($r.Zone)?`r`n$(Json $r.Data)`r`n`r`nOriginal AD ownership/ACLs are NOT restored. Dynamic records receive a fresh timestamp.",'Restore DNS record','YesNo','Warning','Button2') -ne 'Yes'){return}
    $z=Get-DnsServerZone -Name $r.Zone -ComputerName $server
    if([string]$z.ZoneType -ne 'Primary' -or $z.IsPaused -or $z.IsShutdown){throw 'Restore requires an active existing primary zone.'}
    # Recheck after the dialog in case the record has re-registered in the meantime.
    $fresh=@(Get-DnsServerResourceRecord -ZoneName $r.Zone -ComputerName $server)
    if(@($fresh | Where-Object {$_.HostName -ieq $r.Name -and ($_.RecordType -eq $r.Type -or $_.RecordType -eq 'CNAME' -or $r.Type -eq 'CNAME')}).Count){throw 'A same-type or conflicting record is now present. Nothing changed.'}
    $p=@{ZoneName=$r.Zone;Name=$r.Name;ComputerName=$server;TimeToLive=[TimeSpan]::FromSeconds($r.TTL);ErrorAction='Stop'}
    if($r.Dynamic){$p.AgeRecord=$true}
    $d=$r.Data
    switch($r.Type){
        'A'{$p.A=$true;$p.IPv4Address=[string]$d.IPv4Address[0]}
        'AAAA'{$p.AAAA=$true;$p.IPv6Address=[string]$d.IPv6Address[0]}
        'CNAME'{$p.CName=$true;$p.HostNameAlias=[string]$d.HostNameAlias[0]}
        'PTR'{$p.Ptr=$true;$p.PtrDomainName=[string]$d.PtrDomainName[0]}
        'NS'{$p.NS=$true;$p.NameServer=[string]$d.NameServer[0]}
        'MX'{$p.MX=$true;$p.MailExchange=[string]$d.MailExchange[0];$p.Preference=[uint16]$d.Preference[0]}
        'SRV'{$p.Srv=$true;$p.DomainName=[string]$d.DomainName[0];$p.Priority=[uint16]$d.Priority[0];$p.Weight=[uint16]$d.Weight[0];$p.Port=[uint16]$d.Port[0]}
    }
    Add-DnsServerResourceRecord @p
    $after=Read-DNS
    if(-not @($after.Records | Where-Object {(Record-Key $_) -eq (Record-Key $r) -and (Record-Value $_) -ceq (Record-Value $r)}).Count){throw 'Add returned, but verification did not match. Inspect DNS Manager.'}
    Log "RESTORED AND VERIFIED: $(Record-Key $r) $(Json $r.Data)"
}
function Show-Alerts($items){
    $fresh=@($items | Where-Object {-not $script:seen.ContainsKey($_.Key)})
    foreach($item in $fresh){
        Log $item.Detail
        $box.AppendText("$(Get-Date -Format 'HH:mm:ss') - $($item.Detail)`r`n`r`n")
        $script:seen[$item.Key]=$true
    }
    if($fresh.Count){Save-Seen;$form.Show();$form.Activate()}
}
try{
    New-Item -ItemType Directory -Path $store,$logDir -Force | Out-Null
    & icacls.exe $store /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Could not protect DNS backup directory.'}
    if(Test-Path $activeFile){
        $script:baseline=Import-Clixml $activeFile
        if($baseline.Server -ne $server){throw 'Baseline belongs to another DNS server.'}
        $script:seen=@{}
        if(Test-Path $seenFile){$saved=Import-Clixml $seenFile;if($saved.BaselineID -eq $baseline.ID){foreach($key in $saved.Keys){$script:seen[$key]=$true}}}
    }else{if(-not(Update-Baseline)){return}}
    $form=New-Object System.Windows.Forms.Form
    $form.Text='DNS ALERT - change detected';$form.Width=850;$form.Height=360;$form.StartPosition='CenterScreen';$form.TopMost=$true
    $box=New-Object System.Windows.Forms.TextBox
    $box.Multiline=$true;$box.ReadOnly=$true;$box.ScrollBars='Vertical';$box.Dock='Fill';$form.Controls.Add($box)
    $form.Add_FormClosing({param($sender,$e) $e.Cancel=$true;$sender.Hide()})
    Write-Host 'DNS watcher: B = backup/update baseline; R = restore one missing record; Q = quit.' -ForegroundColor Cyan
    Write-Host "Log: $logFile | Backup: $($baseline.Folder)"
    Write-Host 'One alert per affected item per baseline. Keep this window open. Normal DNS registration can also cause changes.'
    $nextCheck=Get-Date;$quit=$false
    while(-not $quit){
        [System.Windows.Forms.Application]::DoEvents()
        if([Console]::KeyAvailable){
            $key=[Console]::ReadKey($true).Key
            if($key -eq 'Q'){$quit=$true;continue}
            if($key -eq 'B'){try{if(Update-Baseline){$box.Clear();$form.Hide()}}catch{Log "BACKUP FAILED: $_"};$nextCheck=Get-Date}
            if($key -eq 'R'){try{Restore-Record}catch{Log "RESTORE ERROR: $_"};$nextCheck=Get-Date}
        }
        if((Get-Date) -ge $nextCheck){
            try{
                $svc=Get-Service DNS
                if($svc.Status -ne 'Running'){Set-Content (Join-Path $logDir 'Current-Differences.txt') 'DNS SERVICE NOT RUNNING: current records could not be checked.';Show-Alerts @([pscustomobject]@{Key='service:DNS';Detail="DNS SERVICE NOT RUNNING: $($svc.Status)"})}
                else{
                    $current=Read-DNS
                    $changes=@(Compare-DNS $baseline.State $current)
                    # Current report stays current even after one-time notifications have fired.
                    @("Current differences as of $([DateTimeOffset]::Now.ToString('o'))")+@($changes | ForEach-Object {$_.Detail}) | Set-Content (Join-Path $logDir 'Current-Differences.txt') -Encoding UTF8
                    Show-Alerts $changes
                }
            }catch{Set-Content (Join-Path $logDir 'Current-Differences.txt') 'MONITOR ERROR: current records could not be checked. See DNS-Changes.txt.';Show-Alerts @([pscustomobject]@{Key='monitor:error';Detail="MONITOR ERROR: DNS queries failed; record-change detection unavailable for this sample. $_"})}
            $nextCheck=(Get-Date).AddSeconds($IntervalSeconds)
        }
        Start-Sleep -Milliseconds 200
    }
}finally{
    if($form){$form.Dispose()}
    if($held){$mutex.ReleaseMutex()};$mutex.Dispose()
}
