#Requires -Version 5.1
<# Read-only triage for 10.111.11.0/24. Run elevated:
    .\ipsweep.ps1           full sweep in three tiers; each tier prints what it found as it finishes
    .\ipsweep.ps1 -Quick    tier 1 only (a few minutes)
Tier 1  known hiding places: live connections, SMB, ARP/DNS cache, firewall rules, hosts file, IIS logs,
        PowerShell history, user/startup/temp folders, IIS config and web root, services, tasks, WMI, key registry spots
Tier 2  event logs (last 7 days; only the event IDs that carry an address, a command or a new task/service) + correlation
Tier 3  deep scan: whole-registry text, then up to 20 minutes of disk files (IIS, users, startup, temp, ProgramData first; Windows last)
Ctrl+C stops at any time and still prints and saves what was found so far.
Direct = a connection, logon, access or web-request record for that IP. Correlated = linked to it through a shared
process or logon ID (NOT proof the IP issued the command). Reference = the IP is only written in text.
Fixed settings: 7 days of logs, 50000 events per query, files up to 300 MB. No findings does not mean clean.
No auditing changes, blocking or deletion. Evidence and coverage/errors: C:\BlueLogs\IpSweep\<run-id>.
#>
[CmdletBinding()]
param([switch]$Quick)
$Days=7;$MaxEventsPerLog=50000;$MaxFileMB=300;$DiskMinutes=20;$HotMinutes=4;$IisMinutes=4
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$script:Findings=New-Object Collections.ArrayList
$script:Coverage=New-Object Collections.ArrayList
$script:Seen=New-Object 'Collections.Generic.HashSet[string]'
$script:History=New-Object Collections.ArrayList
$script:DiskErrors=New-Object Collections.ArrayList
$script:ScannedFiles=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:Completed=$false
$script:SubnetRegex='(?i)(?<![0-9a-z:.])(?:\:\:ffff\:)?10\.111\.11\.(?:0|[1-9][0-9]{0,2})(?![0-9.])'

function Normalize-SubnetIP([string]$Text){
 if(-not $Text){return $null};$s=$Text.Trim().Trim('[',']');$ip=$null
 # Reject ambiguous dotted IPv4 spelling BEFORE .NET normalization (e.g. octal/short forms).
 if($s -notmatch ':' -and $s -notmatch '^10\.111\.11\.(0|[1-9][0-9]{0,2})$'){return $null}
 if($s -match '(?i)^::ffff:(\d+\.\d+\.\d+\.\d+)$' -and $Matches[1] -notmatch '^10\.111\.11\.(0|[1-9][0-9]{0,2})$'){return $null}
 if(-not [Net.IPAddress]::TryParse($s,[ref]$ip)){return $null}
 if($ip.IsIPv4MappedToIPv6){$ip=$ip.MapToIPv4()}
 if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){return $null}
 $b=$ip.GetAddressBytes();if($b[0] -eq 10 -and $b[1] -eq 111 -and $b[2] -eq 11){return $ip.ToString()};return $null
}
function Find-SubnetIPs([string]$Text){
 $seen=New-Object 'Collections.Generic.HashSet[string]'
 foreach($m in [regex]::Matches($Text,$script:SubnetRegex)){ $ip=Normalize-SubnetIP $m.Value;if($ip -and $seen.Add($ip)){$ip} }
}
function Add-Coverage([string]$Stage,[string]$Status,[int64]$Scanned,[string]$Detail){
 [void]$script:Coverage.Add([pscustomobject][ordered]@{Stage=$Stage;Status=$Status;Scanned=$Scanned;Detail=$Detail;TimeUTC=(Get-Date).ToUniversalTime().ToString('o')})
}
function Add-Finding([string]$Category,[string]$Source,[string]$IP,[string]$Item,[string]$Detail,$Time,[string]$LogName='',[string]$RecordId='',[string]$ProcessGuid='',[string]$LogonId='',[string]$Account=''){
 $ip=Normalize-SubnetIP $IP;if(-not $ip){return}
 $utc=if($Time){([datetimeoffset]$Time).UtcDateTime.ToString('o')}else{''}
 $row=[pscustomobject][ordered]@{Category=$Category;IP=$ip;Source=$Source;Item=$Item;Detail=$Detail;TimeUTC=$utc;LogName=$LogName;RecordId=$RecordId;ProcessGuid=$ProcessGuid;LogonId=$LogonId;Account=$Account}
 $keyRow=$row
 if($Source -in @('Live TCP','SMB session','SMB open file')){$keyRow=$row|Select-Object * -ExcludeProperty TimeUTC}
 $sha=[Security.Cryptography.SHA256]::Create()
 try{$key=[Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($keyRow|ConvertTo-Json -Compress -Depth 8))))}finally{$sha.Dispose()}
 if($script:Seen.Add($key)){[void]$script:Findings.Add($row);Write-Host ('{0}: {1} {2} {3}' -f $Category,$ip,$Source,$Item)}
}
function Add-References([string]$Source,[string]$Item,[string]$Text,$Time){
 foreach($ip in @(Find-SubnetIPs $Text)){Add-Finding 'Reference' $Source $ip $Item $Text $Time}
}
function Save-Reports{
 ConvertTo-Json -InputObject @($script:Findings.ToArray()) -Depth 8|Set-Content -LiteralPath (Join-Path $script:Output 'findings.json.tmp') -Encoding UTF8
 Move-Item -LiteralPath (Join-Path $script:Output 'findings.json.tmp') -Destination (Join-Path $script:Output 'findings.json') -Force
 if($script:Findings.Count){$script:Findings|Export-Csv -LiteralPath (Join-Path $script:Output 'findings.csv') -NoTypeInformation -Encoding UTF8}
 $script:Coverage|Export-Csv -LiteralPath (Join-Path $script:Output 'coverage.csv') -NoTypeInformation -Encoding UTF8
 if($script:DiskErrors.Count){$script:DiskErrors|Export-Csv -LiteralPath (Join-Path $script:Output 'file-errors.csv') -NoTypeInformation -Encoding UTF8}
}
function Invoke-Stage([string]$Name,[scriptblock]$Code){
 Write-Host "Scanning $Name ..."
 try{& $Code}catch{Add-Coverage $Name 'ERROR' 0 $_.Exception.Message;Write-Warning "$Name : $($_.Exception.Message)"}finally{Save-Reports}
}
function Get-ProcessMap{
 $procs=@{};$services=@{}
 foreach($p in Get-CimInstance Win32_Process){$procs[[int]$p.ProcessId]=$p}
 foreach($s in Get-CimInstance Win32_Service){if($s.ProcessId -gt 0){$key=[int]$s.ProcessId;if(-not $services.ContainsKey($key)){$services[$key]=@()};$services[$key]+=$s.Name}}
 [pscustomobject]@{Processes=$procs;Services=$services}
}
function Describe-Process($Map,[int]$ProcessId){
 $p=$Map.Processes[$ProcessId]
 if(-not $p){return "PID $ProcessId (process unavailable at collection)"}
 return ('{0}; PID={1}; started={2}; path={3}; services={4}; command={5}' -f $p.Name,$ProcessId,$p.CreationDate,$p.ExecutablePath,($Map.Services[$ProcessId] -join ','),$p.CommandLine)
}
function Collect-Live{
 $map=Get-ProcessMap;$now=Get-Date;$n=0
 foreach($c in Get-NetTCPConnection){$n++;$ip=Normalize-SubnetIP $c.RemoteAddress;if($ip){
  # Re-read the owner; a vanished/reused PID must not silently implicate the earlier process.
  $p=$map.Processes[[int]$c.OwningProcess];$current=Get-CimInstance Win32_Process -Filter "ProcessId=$($c.OwningProcess)"
  $item=if($p -and $current -and $current.CreationDate -eq $p.CreationDate){Describe-Process $map ([int]$c.OwningProcess)}else{"PID $($c.OwningProcess); ownership changed/unavailable during snapshot"}
  Add-Finding 'Direct' 'Live TCP' $ip $item ("State=$($c.State); local=$($c.LocalAddress):$($c.LocalPort); remote=$($c.RemoteAddress):$($c.RemotePort). Snapshot association, not proof of remote command execution.") $now
 }}
 Add-Coverage 'Live TCP/processes' 'OK' $n 'TCP snapshot only; UDP does not expose a peer in Get-NetUDPEndpoint. Process/service labels are point-in-time associations.'
 foreach($p in $map.Processes.Values){Add-References 'Process text' (Describe-Process $map ([int]$p.ProcessId)) ($p.ExecutablePath+' '+$p.CommandLine) $p.CreationDate}
}
function Collect-Smb{
 $n=0;$sessions=@{}
 foreach($s in Get-SmbSession){$n++;$ip=Normalize-SubnetIP $s.ClientComputerName;$sessions[[string]$s.SessionId]=$ip;if($ip){Add-Finding 'Direct' 'SMB session' $ip ([string]$s.ClientUserName) ($s|Select-Object SessionId,ClientComputerName,NumOpens,Dialect|ConvertTo-Json -Compress) (Get-Date)}}
 foreach($f in Get-SmbOpenFile){$n++;$ip=$sessions[[string]$f.SessionId];if(-not $ip){$ip=Normalize-SubnetIP $f.ClientComputerName};if($ip){Add-Finding 'Direct' 'SMB open file' $ip $f.Path ("Account=$($f.ClientUserName); SessionId=$($f.SessionId); FileId=$($f.FileId)") (Get-Date)}}
 Add-Coverage 'SMB live state' 'OK' $n 'Hostnames are not resolved retrospectively; only literal peer IPs are attributable.'
}
function Get-EventData($Event){
 $xml=New-Object Xml.XmlDocument;$xml.LoadXml([string]$Event.ToXml());$data=@{};$i=0
 foreach($n in @($xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']"))){
  if($null -eq $n){continue};$name=[string]$n.GetAttribute('Name');if(-not $name){$name='Value'+$i};if($data.ContainsKey($name)){$name=$name+'_'+$i};$data[$name]=[string]$n.InnerText;$i++
 }
 [pscustomobject]@{Id=[int]$Event.Id;Log=[string]$Event.LogName;Provider=[string]$Event.ProviderName;RecordId=[string]$Event.RecordId;Time=$Event.TimeCreated;Data=$data;Xml=$xml.OuterXml}
}
function Process-Event($e,[string]$Name){
 $d=$e.Data
 if(($Name -eq 'Security' -and $e.Id -in @(4624,4688,4663)) -or ($Name -eq 'Microsoft-Windows-Sysmon/Operational' -and $e.Id -in @(1,3,7,11))){[void]$script:History.Add($e)}
 $direct=@()
 if($Name -eq 'Security'){
  if($e.Id -in @(4624,4625,4648,5140,5145)){$direct=@('IpAddress')}
  if($e.Id -eq 5156){$direct=@('SourceAddress','DestAddress')}
 }elseif($Name -eq 'Microsoft-Windows-Sysmon/Operational' -and $e.Id -eq 3){$direct=@('SourceIp','DestinationIp')}
 $reported=New-Object 'Collections.Generic.HashSet[string]'
 foreach($key in $direct){$ip=Normalize-SubnetIP $d[$key];if($ip){[void]$reported.Add($ip);Add-Finding 'Direct' ("Event $($e.Id) / $key") $ip ($d.Image+$d.Application+$d.TargetUserName+$d.ShareName) ($d|ConvertTo-Json -Depth 6 -Compress) $e.Time $e.Log $e.RecordId $d.ProcessGuid $d.TargetLogonId $d.TargetUserName}}
 foreach($ip in @(Find-SubnetIPs $e.Xml)){if(-not $reported.Contains($ip)){Add-Finding 'Reference' ("Event $($e.Id) text") $ip $e.Provider $e.Xml $e.Time $e.Log $e.RecordId $d.ProcessGuid '' ''}}
}
function Get-EventQueryResult($Filter){
 if($Filter -is [string]){Get-WinEvent -FilterXml $Filter -MaxEvents ($MaxEventsPerLog+1) -ErrorAction Stop}
 else{Get-WinEvent -FilterHashtable $Filter -MaxEvents ($MaxEventsPerLog+1) -ErrorAction Stop}
}
# One query = one log + a server-side filter (event IDs, and for logons also "has a real address"). The log service cannot
# match an address prefix, so the 10.111.11.x test itself is done here in PowerShell on the narrowed result.
function Collect-EventQuery([string]$Label,[string]$Log,$Filter,$Fallback=$null){
 $count=0;$failures=0;$limited=$false;$mode='server-side filter on event ID'
 if($Filter -is [string]){$mode='server-side filter on event ID and a non-empty address'}
 try{
  $meta=Get-WinEvent -ListLog $Log -ErrorAction Stop
  if(-not $meta.IsEnabled){Add-Coverage "Log: $Label" 'UNAVAILABLE' 0 'Channel disabled; historical records, if any, are still queried.'}
 }catch{Add-Coverage "Log: $Label" 'ERROR' 0 $_.Exception.Message;return}
 for($attempt=0;$attempt -lt 2;$attempt++){
  $f=if($attempt -eq 0){$Filter}else{$Fallback}
  try{
   Get-EventQueryResult $f|ForEach-Object {
    $count++
    if($count -gt $MaxEventsPerLog){$limited=$true;return}
    try{ Process-Event (Get-EventData $_) $Log }catch{$failures++;if($failures -le 10){Add-Coverage "Log parse: $Label" 'ERROR' 1 $_.Exception.Message}}
   }
   break
  }catch{
   if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){Add-Coverage "Log: $Label" 'EMPTY' 0 'No retained records matched; this does not prove no activity.';return}
   if($attempt -eq 0 -and $null -ne $Fallback){$mode='event-ID filter only (the address filter was rejected: '+$_.Exception.Message+')';continue}
   Add-Coverage "Log: $Label" 'ERROR' $count $_.Exception.Message;return
  }
 }
 $status=if($limited -or $failures){'PARTIAL'}else{'OK'}
 Add-Coverage "Log: $Label" $status ([math]::Min($count,$MaxEventsPerLog)) ("Last $Days days; $mode; newest $MaxEventsPerLog event limit; truncated=$limited; record errors=$failures. This does not establish audit coverage before collection.")
}
function Get-EventPlans{
 $start=(Get-Date).AddDays(-$Days);$ms=[int64]$Days*86400000
 $secXml="<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=5140 or EventID=5145) and TimeCreated[timediff(@SystemTime) &lt;= $ms]] and EventData[Data[@Name='IpAddress']!='-' and Data[@Name='IpAddress']!='::1' and Data[@Name='IpAddress']!='127.0.0.1']]</Select></Query></QueryList>"
 $plans=New-Object Collections.ArrayList
 function P([string]$Label,[string]$Log,$Ids){
  $h=@{LogName=$Log;StartTime=$start};if($Ids){$h['Id']=@($Ids)}
  [void]$plans.Add(@{Label=$Label;Log=$Log;Filter=$h;Fallback=$null})
 }
 [void]$plans.Add(@{Label='Security logons/shares with an address';Log='Security';Filter=$secXml;Fallback=@{LogName='Security';Id=@(4624,4625,4648,5140,5145);StartTime=$start}})
 P 'Security processes/tasks/objects' 'Security' @(4688,4663,4697,4698,4702)
 P 'Security filtering platform (5156)' 'Security' @(5156)
 P 'System service installs' 'System' @(7045)
 P 'Sysmon' 'Microsoft-Windows-Sysmon/Operational' @(1,3,7,11)
 P 'PowerShell Operational' 'Microsoft-Windows-PowerShell/Operational' @(4103,4104)
 P 'Windows PowerShell' 'Windows PowerShell' @(400,403)
 P 'WinRM Operational' 'Microsoft-Windows-WinRM/Operational' @(6,91,161,168,169)
 P 'RDP connection manager' 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' @(1149)
 P 'RDP session manager' 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' @(21,22,24,25)
 P 'Task Scheduler Operational' 'Microsoft-Windows-TaskScheduler/Operational' @(106,140,141,200,201)
 P 'OpenSSH Operational' 'OpenSSH/Operational' $null
 $plans.ToArray()
}
function Normalize-LogonId([string]$Id){
 try{if($Id -match '^0x[0-9a-f]+$'){return [Convert]::ToUInt64($Id.Substring(2),16).ToString()};if($Id -match '^\d+$'){return [uint64]$Id}}catch{};return ''
}
function Correlate-History{
 $sysmon=@{};$logons=@{};$count=0
 foreach($e in $script:History){
  if($e.Log -eq 'Microsoft-Windows-Sysmon/Operational' -and $e.Id -eq 3 -and $e.Data.ProcessGuid){
   $ips=@();foreach($k in @('SourceIp','DestinationIp')){$ip=Normalize-SubnetIP $e.Data[$k];if($ip){$ips+=$ip}}
   if($ips.Count){$key=$e.Data.ProcessGuid.ToLowerInvariant();if(-not $sysmon.ContainsKey($key)){$sysmon[$key]=@{}};foreach($ip in $ips){if(-not $sysmon[$key].ContainsKey($ip)){$sysmon[$key][$ip]=[pscustomobject]@{Event=$e;IPs=@($ip);NetworkRecords=0}};$sysmon[$key][$ip].NetworkRecords++}}
  }
  if($e.Log -eq 'Security' -and $e.Id -eq 4624 -and $script:BootTime -and $e.Time -ge $script:BootTime){
   $ip=Normalize-SubnetIP $e.Data.IpAddress;$key=[string](Normalize-LogonId $e.Data.TargetLogonId)
   if($ip -and $key -and $key -ne '0'){if(-not $logons.ContainsKey($key)){$logons[$key]=New-Object Collections.ArrayList};[void]$logons[$key].Add([pscustomobject]@{Event=$e;IP=$ip})}
  }
 }
 foreach($e in $script:History){
  if($e.Log -eq 'Microsoft-Windows-Sysmon/Operational' -and $e.Id -in @(1,7,11) -and $e.Data.ProcessGuid){
   $key=$e.Data.ProcessGuid.ToLowerInvariant()
   foreach($link in @($sysmon[$key].Values)){if(-not $link){continue};foreach($ip in $link.IPs){
    $item=if($e.Id -eq 11){$e.Data.TargetFilename}elseif($e.Id -eq 7){$e.Data.ImageLoaded}else{$e.Data.Image}
    Add-Finding 'Correlated' 'Sysmon ProcessGuid' $ip $item ("Same ProcessGuid as $($link.NetworkRecords) matching network record(s), example record $($link.Event.RecordId) at $($link.Event.Time.ToUniversalTime().ToString('o')); association does NOT prove the remote IP caused this action. Event data: "+($e.Data|ConvertTo-Json -Compress)) $e.Time $e.Log $e.RecordId $e.Data.ProcessGuid '' $e.Data.User;$count++
   }}
  }
  if($e.Log -eq 'Security' -and $e.Id -in @(4688,4663) -and $script:BootTime -and $e.Time -ge $script:BootTime){
   # 4688 Target identity, when present, is the actual new-process account (e.g. runas).
   $field=if($e.Id -eq 4688 -and $e.Data.TargetUserSid -and $e.Data.TargetUserSid -ne 'S-1-0-0' -and $e.Data.TargetUserSid -ne '-'){ 'Target' }else{'Subject'}
   $key=[string](Normalize-LogonId $e.Data[($field+'LogonId')]);$sid=$e.Data[($field+'UserSid')]
   $link=@($logons[$key]|Where-Object {$_ -and $_.Event.Time -le $e.Time -and $_.Event.Data.TargetUserSid -eq $sid}|Sort-Object {$_.Event.Time} -Descending|Select-Object -First 1)
   if($link.Count){$l=$link[0];$item=if($e.Id -eq 4688){$e.Data.NewProcessName}else{$e.Data.ObjectName}
    Add-Finding 'Correlated' 'Security logon ID and SID' $l.IP $item ("Same current-boot logon ID and SID as 4624 record $($l.Event.RecordId); session association, NOT proof the peer issued the command. Event data: "+($e.Data|ConvertTo-Json -Compress)) $e.Time $e.Log $e.RecordId '' $key $e.Data[($field+'UserName')];$count++
   }
  }
 }
 Add-Coverage 'Historical correlation' 'OK' $count 'Sysmon uses ProcessGuid; Security uses matching SID/logon ID after the current boot only. Missing audit records prevent attribution. A related file is not proof of execution.'
 if(-not $script:BootTime){Add-Coverage 'Security logon correlation' 'SKIPPED' 0 'Boot time unavailable; logon-ID correlation was skipped to avoid cross-reboot reuse.'}
}
function Collect-ServicesAndTasks{
 $n=0
 foreach($s in Get-CimInstance Win32_Service){$n++;Add-References 'Service definition text' $s.Name ($s|Select-Object Name,StartName,PathName,State,ProcessId|ConvertTo-Json -Compress) (Get-Date)}
 Add-Coverage 'Service definitions' 'OK' $n 'An IP in a service path is a reference, not proof of execution from that IP.'
 $n=0;$errors=0
 foreach($t in Get-ScheduledTask){try{$n++;$xml=Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath;Add-References 'Scheduled task XML text' ($t.TaskPath+$t.TaskName) $xml (Get-Date)}catch{$errors++;Add-Coverage ('Task: '+$t.TaskPath+$t.TaskName) 'ERROR' 0 $_.Exception.Message}}
 Add-Coverage 'Scheduled task definitions' $(if($errors){'PARTIAL'}else{'OK'}) $n "Task definitions only; errors=$errors. Task history requires existing event logging."
}
function Collect-Wmi{
 foreach($class in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')){
  try{$items=@(Get-CimInstance -Namespace root/subscription -ClassName $class);foreach($i in $items){Add-References 'WMI subscription text' $class ($i|Select-Object * -ExcludeProperty Cim*|ConvertTo-Json -Depth 5 -Compress) (Get-Date)};Add-Coverage "WMI: $class" 'OK' $items.Count 'Read-only definitions.'}catch{Add-Coverage "WMI: $class" 'ERROR' 0 $_.Exception.Message}
 }
}
function Scan-RegistryTree([string[]]$Roots,[string]$Label,[int]$Minutes,[string]$Note){
 $total=0;$errors=0;$partial=$false;$until=(Get-Date).AddMinutes($Minutes)
 foreach($root in $Roots){
  if(-not (Test-Path -LiteralPath $root)){continue}
  $stack=New-Object 'Collections.Generic.Stack[string]';$stack.Push($root)
  while($stack.Count){
   if((Get-Date) -gt $until){$partial=$true;break}
   $key=$stack.Pop()
   try{
    # The key path itself is checked too: e.g. Terminal Server Client\Servers\<address> stores the address as a key name.
    Add-References 'Registry key name' $key $key (Get-Date)
    $props=Get-ItemProperty -LiteralPath $key
    foreach($p in $props.PSObject.Properties){if($p.Name -like 'PS*'){continue};if($p.Value -is [string] -or $p.Value -is [string[]]){$total++;Add-References 'Registry text' ($key+'\'+$p.Name) ($p.Value -join ' ') (Get-Date)}}
    foreach($k in Get-ChildItem -LiteralPath $key){$stack.Push($k.PSPath)}
   }catch{$errors++;if($errors -le 30){Add-Coverage ('Registry key: '+$key) 'ERROR' 0 $_.Exception.Message}}
  }
  if($partial){break}
 }
 $status=if($errors -or $partial){'PARTIAL'}else{'OK'}
 Add-Coverage $Label $status $total ("$Note Time budget ${Minutes}m reached=$partial; unreadable keys=$errors; string values and key names only; no offline hives.")
}
function Collect-RegistryDeep{
 Scan-RegistryTree @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE','Registry::HKEY_LOCAL_MACHINE\SYSTEM','Registry::HKEY_USERS') 'Registry (whole)' 3 'HKLM SOFTWARE/SYSTEM and loaded user hives.'
}
function Collect-RegistryHot{
 $hives=@('Registry::HKEY_LOCAL_MACHINE')
 $hives+=@(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue|Where-Object {$_.PSChildName -notlike '*_Classes'}|ForEach-Object {$_.PSPath})
 $rel=@('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce','Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run','Software\Microsoft\Windows NT\CurrentVersion\Winlogon','Software\Microsoft\Windows NT\CurrentVersion\Windows','Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','Software\Microsoft\Terminal Server Client','Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths','Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU','Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU','Network','Software\Microsoft\Command Processor','Software\Policies\Microsoft\Windows\WinRM')
 $roots=New-Object Collections.ArrayList
 foreach($h in $hives){foreach($r in $rel){[void]$roots.Add($h+'\'+$r)}}
 [void]$roots.Add('Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp')
 [void]$roots.Add('Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation')
 Scan-RegistryTree @($roots.ToArray()) 'Registry (known spots)' 2 'Run/RunOnce, Winlogon, IFEO, RDP client history, typed paths, run/mapped-drive history, WinRM policy in HKLM and loaded user hives. Users who are not logged in have unloaded hives that are NOT read.'
}
function Collect-Firewall{
 $key='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules';$n=0
 $props=(Get-ItemProperty -LiteralPath $key).PSObject.Properties
 foreach($p in $props){
  if($p.Name -like 'PS*'){continue};$n++;$v=[string]$p.Value
  foreach($ip in @(Find-SubnetIPs $v)){
   $name=if($v -match '\|Name=([^|]*)'){$Matches[1]}else{$p.Name};$act=if($v -match '\|Action=([^|]*)'){$Matches[1]}else{''};$dir=if($v -match '\|Dir=([^|]*)'){$Matches[1]}else{''}
   Add-Finding 'Reference' 'Firewall rule' $ip ("$name [$act/$dir]") $v (Get-Date)
  }
 }
 Add-Coverage 'Firewall rules' 'OK' $n 'Rules stored in the registry policy store; an address in a rule is a reference, not a connection.'
}
function Collect-Network{
 $n=0
 try{
  foreach($x in Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop){$n++;$ip=Normalize-SubnetIP ([string]$x.IPAddress)
   if($ip -and ([string]$x.State -notin @('Unreachable','Incomplete'))){Add-Finding 'Direct' 'ARP/neighbor cache' $ip ("MAC $($x.LinkLayerAddress); state $($x.State); interface $($x.InterfaceAlias)") 'Neighbor-table entry: this host exchanged traffic with the address on its local network recently. No direction, protocol or content.' (Get-Date)}}
  Add-Coverage 'ARP/neighbor cache' 'OK' $n 'Only recent local-network contact is cached; entries expire within minutes.'
 }catch{Add-Coverage 'ARP/neighbor cache' 'ERROR' 0 $_.Exception.Message}
 try{
  $n=0;foreach($x in Get-DnsClientCache -ErrorAction Stop){$n++;Add-References 'DNS client cache' ([string]$x.Entry) (([string]$x.Entry)+' '+([string]$x.Data)) (Get-Date)}
  Add-Coverage 'DNS client cache' 'OK' $n 'Names resolved recently; an address here is a reference, not a connection.'
 }catch{Add-Coverage 'DNS client cache' 'ERROR' 0 $_.Exception.Message}
}
function Get-IisScannerSource{
@'
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
public class IisLogResult {
 public List<string> FieldSets=new List<string>();
 public List<string> Lines=new List<string>();
 public long Matched=0;
}
public static class IisLogScan {
 static readonly Regex Rx=new Regex(@"(?<![0-9A-Za-z:.])10\.111\.11\.(?:0|[1-9][0-9]{0,2})(?![0-9.])",RegexOptions.Compiled);
 public static IisLogResult Scan(string path,int maxLines,DateTime deadline) {
  IisLogResult r=new IisLogResult();
  using(FileStream fs=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))
  using(StreamReader sr=new StreamReader(fs,Encoding.UTF8,true,65536)) {
   string line;long n=0;
   while((line=sr.ReadLine())!=null) {
    n++;
    if((n&4095)==0 && DateTime.UtcNow>deadline) throw new TimeoutException("IIS log budget reached");
    if(line.Length>0 && line[0]=='#') {
     if(line.StartsWith("#Fields:",StringComparison.Ordinal)) {string f=line.Substring(8).Trim();if(r.FieldSets.Count==0||r.FieldSets[r.FieldSets.Count-1]!=f)r.FieldSets.Add(f);}
     continue;
    }
    if(line.IndexOf("10.111.11.",StringComparison.Ordinal)<0) continue;
    if(!Rx.IsMatch(line)) continue;
    r.Matched++;
    if(r.Lines.Count<maxLines) r.Lines.Add((r.FieldSets.Count-1).ToString()+"\t"+line);
   }
  }
  return r;
 }
}
'@
}
function Get-IisLogDirs{
 $dirs=New-Object Collections.ArrayList
 [void]$dirs.Add((Join-Path $env:SystemDrive 'inetpub\logs\LogFiles'));[void]$dirs.Add((Join-Path $env:SystemRoot 'System32\LogFiles\HTTPERR'))
 $cfg=Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
 if(Test-Path -LiteralPath $cfg){try{
  $txt=[IO.File]::ReadAllText($cfg)
  foreach($m in [regex]::Matches($txt,'<(?:logFile|centralW3CLogFile|centralBinaryLogFile)\b[^>]*?\bdirectory="([^"]+)"')){$p=[Environment]::ExpandEnvironmentVariables($m.Groups[1].Value);if($p -and -not $dirs.Contains($p)){[void]$dirs.Add($p)}}
 }catch{}}
 $dirs.ToArray()
}
function Collect-IisLogs{
 if(-not ('IisLogScan' -as [type])){Add-Type -TypeDefinition (Get-IisScannerSource)}
 $deadline=(Get-Date).ToUniversalTime().AddMinutes($IisMinutes);$cut=(Get-Date).AddDays(-$Days)
 $files=0;$bytes=[int64]0;$matched=[int64]0;$captured=[int64]0;$errs=0;$timedOut=$false;$per=@{};$refs=0
 foreach($dir in @(Get-IisLogDirs)){
  if(-not (Test-Path -LiteralPath $dir -PathType Container)){continue}
  $list=@(Get-ChildItem -LiteralPath $dir -Recurse -File -Force -Filter *.log -ErrorAction SilentlyContinue|Where-Object {$_.LastWriteTime -ge $cut}|Sort-Object LastWriteTime -Descending)
  foreach($f in $list){
   if((Get-Date).ToUniversalTime() -gt $deadline){$timedOut=$true;break}
   try{$r=[IisLogScan]::Scan($f.FullName,5000,$deadline)}catch{if("$($_.Exception.Message)" -like '*budget reached*'){$timedOut=$true;break};$errs++;[void]$script:DiskErrors.Add([pscustomobject]@{Path=$f.FullName;Reason=$_.Exception.Message});continue}
   $files++;$bytes+=$f.Length;$matched+=$r.Matched;$captured+=$r.Lines.Count
   $maps=@{}
   foreach($line in $r.Lines){
    $tab=$line.IndexOf("`t");$set=[int]$line.Substring(0,$tab);$text=$line.Substring($tab+1)
    if(-not $maps.ContainsKey($set)){$ix=@{};if($set -ge 0){$names=$r.FieldSets[$set] -split ' ';for($i=0;$i -lt $names.Count;$i++){$ix[$names[$i]]=$i}};$maps[$set]=$ix}
    $ix=$maps[$set];$vals=$text -split ' ';$ip=$null
    if($ix.ContainsKey('c-ip') -and $ix['c-ip'] -lt $vals.Count){$ip=Normalize-SubnetIP $vals[$ix['c-ip']]}
    if($ip){
     if(-not $per.ContainsKey($ip)){$per[$ip]=[pscustomobject]@{Count=0;First='';Last='';Status=@{};Uris=@{};Files=@{}}}
     $a=$per[$ip];$a.Count++;$a.Files[$f.FullName]=1
     if($ix.ContainsKey('date') -and $ix.ContainsKey('time')){$t=$vals[$ix['date']]+'T'+$vals[$ix['time']]+'Z';if(-not $a.First -or $t -lt $a.First){$a.First=$t};if($t -gt $a.Last){$a.Last=$t}}
     if($ix.ContainsKey('sc-status')){$s=$vals[$ix['sc-status']];$a.Status[$s]=1+[int]$a.Status[$s]}
     if($ix.ContainsKey('cs-uri-stem')){$u=(($(if($ix.ContainsKey('cs-method')){$vals[$ix['cs-method']]+' '}else{''}))+$vals[$ix['cs-uri-stem']]);$a.Uris[$u]=1+[int]$a.Uris[$u]}
    }elseif($refs -lt 200){
     foreach($x in @(Find-SubnetIPs $text)){$refs++;Add-Finding 'Reference' 'IIS log text' $x $f.FullName $text (Get-Date)}
    }
   }
  }
  if($timedOut){break}
 }
 foreach($ip in $per.Keys){
  $a=$per[$ip]
  $top=(@($a.Uris.GetEnumerator()|Sort-Object Value -Descending|Select-Object -First 5|ForEach-Object {"$($_.Key) x$($_.Value)"}) -join '; ')
  $st=(@($a.Status.GetEnumerator()|Sort-Object Name|ForEach-Object {"$($_.Key)x$($_.Value)"}) -join ',')
  $item="$($a.Count) request(s) $($a.First) .. $($a.Last) UTC; status $st; top: $top"
  $fileList=(@($a.Files.Keys|Select-Object -First 5) -join '; ')
  Add-Finding 'Direct' 'IIS log' $ip $item ("Web server request records with this client address in: $fileList") $a.Last
 }
 $status=if($timedOut -or $errs -or $captured -lt $matched){'PARTIAL'}else{'OK'}
 Add-Coverage 'IIS/HTTP logs' $status $files ("Files from the last $Days days read=$files ($([math]::Round($bytes/1MB)) MB); matching lines=$matched, captured=$captured (first 5000 per file); budget ${IisMinutes}m reached=$timedOut; read errors=$errs. Times are as logged (IIS default UTC). Requests from a proxy appear under the proxy address unless X-Forwarded-For is logged.")
}
function Get-FileScannerSource{
@'
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
public static class IpSweepFileScan {
 static readonly Regex Rx=new Regex(@"(?i)(?<![0-9a-z:.])(?:::ffff:)?10\.111\.11\.(?:0|[1-9][0-9]{0,2})(?![0-9.])",RegexOptions.Compiled);
 static void Match(string value,HashSet<string> found,bool final) {
  foreach(Match m in Rx.Matches(value)) {
   // Do not accept a partial last octet at a block boundary; the overlap handles it next time.
   if(!final && m.Index+m.Length>=value.Length-1) continue;
   string s=m.Value; int pos=s.LastIndexOf(':'); if(pos>=0) s=s.Substring(pos+1);
   int n; if(Int32.TryParse(s.Substring(s.LastIndexOf('.')+1),out n) && n>=0 && n<=255) found.Add(s);
  }
 }
 public static string[] Scan(string path,DateTime deadline) {
  HashSet<string> hits=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  using(FileStream fs=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)) {
   byte[] buffer=new byte[65536+128];int carry=0;
   while(true){
    if(DateTime.UtcNow>deadline) throw new TimeoutException("Disk scan budget reached during a file.");
    int n=fs.Read(buffer,carry,65536);int length=n+carry;bool final=n==0;
    Match(Encoding.ASCII.GetString(buffer,0,length),hits,final);
    // Both byte alignments and both UTF-16 byte orders; do not restrict by filename/extension.
    for(int offset=0;offset<2;offset++) {int chars=(length-offset)/2*2;if(chars>0){
     Match(Encoding.Unicode.GetString(buffer,offset,chars),hits,final);
     Match(Encoding.BigEndianUnicode.GetString(buffer,offset,chars),hits,final);
    }}
    if(final) break;
    carry=Math.Min(128,length);Array.Copy(buffer,length-carry,buffer,0,carry);
   }
  }
  string[] result=new string[hits.Count];hits.CopyTo(result);Array.Sort(result);return result;
 }
}
'@
}
function Scan-OneFile($f,[datetime]$Deadline,[string]$Source,[bool]$Zone,$st){
 if(-not $script:ScannedFiles.Add($f.FullName)){$st.Again++;return}
 if($f.Length -gt $MaxFileMB*1MB){$st.Oversize++;return}
 try{
  $before=$f.LastWriteTimeUtc;$size=$f.Length;$hits=[IpSweepFileScan]::Scan($f.FullName,$Deadline);$st.Count++
  $after=Get-Item -LiteralPath $f.FullName -Force
  foreach($ip in $hits){Add-Finding 'Reference' $Source $ip $f.FullName ("IP literal in ASCII/UTF-16 bytes; size=$size; changedDuringRead=$($after.Length -ne $size -or $after.LastWriteTimeUtc -ne $before). Not proof of execution, authorship, or remote access.") $before}
  # Only the download-origin stream is inspected; other alternate streams are outside this scan.
  if($Zone){
   $stream=Get-Item -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
   if($stream){Add-References 'Zone.Identifier text' ($f.FullName+':Zone.Identifier') (Get-Content -LiteralPath $f.FullName -Stream Zone.Identifier -Raw) $before}
  }
 }catch{
  if("$($_.Exception.Message)" -like '*budget reached*'){$st.TimedOut=$true}
  else{$st.Errors++;[void]$script:DiskErrors.Add([pscustomobject]@{Path=$f.FullName;Reason=$_.Exception.Message})}
 }
}
# Walks the given paths in order (files or folders); folders in $Late are walked last. Returns the counters.
function Scan-Tree([string[]]$Roots,[datetime]$Deadline,[string[]]$Late=@(),[string[]]$ZonePrefixes=@(),[string]$Source='File bytes'){
 $st=@{Count=0;Oversize=0;Links=0;Errors=0;Excluded=0;Again=0;TimedOut=$false}
 $visited=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 $lateQueue=New-Object 'Collections.Generic.List[string]';$stack=New-Object 'Collections.Generic.Stack[string]'
 $skipPaths=@($script:Output,'C:\BlueLogs\IpSweep',(Join-Path $env:SystemRoot 'System32\winevt\Logs'))
 for($pi=$Roots.Count-1;$pi -ge 0;$pi--){if(Test-Path -LiteralPath $Roots[$pi]){$stack.Push($Roots[$pi])}}
 $lastProg=Get-Date
 while($true){
  if(-not $stack.Count){if($lateQueue.Count){foreach($l in $lateQueue){$stack.Push($l)};$lateQueue.Clear()}else{break}}
  if((Get-Date).ToUniversalTime() -gt $Deadline){$st.TimedOut=$true;break}
  $dir=$stack.Pop()
  if(-not $visited.Add($dir)){continue}
  if(((Get-Date)-$lastProg).TotalSeconds -ge 15){$lastProg=Get-Date;Write-Host ('[{0}] still scanning - {1} files read, now in {2}' -f (Get-Date).ToString('HH:mm:ss'),$st.Count,$dir) -ForegroundColor DarkGray}
  if(Test-Path -LiteralPath $dir -PathType Leaf){
   $one=Get-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue
   if($one){Scan-OneFile $one $Deadline $Source $true $st}
   continue
  }
  try{$children=@(Get-ChildItem -LiteralPath $dir -Force)}catch{$st.Errors++;[void]$script:DiskErrors.Add([pscustomobject]@{Path=$dir;Reason=$_.Exception.Message});continue}
  foreach($f in $children){
   if((Get-Date).ToUniversalTime() -gt $Deadline){$st.TimedOut=$true;break}
   if($f.Attributes -band [IO.FileAttributes]::ReparsePoint){$st.Links++;continue}
   if($f.PSIsContainer){
    $skip=($f.Name -eq 'System Volume Information')
    foreach($x in $skipPaths){if($f.FullName -ieq $x){$skip=$true}}
    if($skip){$st.Excluded++;continue}
    if($Late -contains $f.FullName){[void]$lateQueue.Add($f.FullName)}else{$stack.Push($f.FullName)}
    continue
   }
   if($f.FullName -ieq $PSCommandPath){$st.Excluded++;continue}
   $zone=$false;foreach($zp in $ZonePrefixes){if($f.FullName.StartsWith($zp,[StringComparison]::OrdinalIgnoreCase)){$zone=$true;break}}
   Scan-OneFile $f $Deadline $Source $zone $st
   if($st.TimedOut){break}
  }
  if($st.TimedOut){break}
 }
 return $st
}
function Add-FileCoverage([string]$Stage,$st,[string]$Detail){
 $bad=($st.TimedOut -or $st.Errors -or $st.Oversize -or $st.Links)
 Add-Coverage $Stage $(if($bad){'PARTIAL'}else{'OK'}) $st.Count ("$Detail timedOut=$($st.TimedOut); over ${MaxFileMB}MB=$($st.Oversize); reparse points skipped=$($st.Links); excluded=$($st.Excluded); already read in an earlier step=$($st.Again); read errors=$($st.Errors). No archive unpacking, decryption, deleted-file recovery, network drives, or offline hives. UTF-8/ASCII and UTF-16 IP literals only; Zone.Identifier is the only alternate stream read.")
}
function Collect-HotFiles{
 if(-not ('IpSweepFileScan' -as [type])){Add-Type -TypeDefinition (Get-FileScannerSource)}
 $sd=$env:SystemDrive;$targets=New-Object Collections.ArrayList
 foreach($p in @((Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'),(Join-Path $env:SystemRoot 'System32\drivers\etc\lmhosts.sam'),(Join-Path $env:SystemRoot 'System32\inetsrv\config'),"$sd\inetpub\wwwroot",(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'),(Join-Path $env:SystemRoot 'Tasks'),(Join-Path $env:SystemRoot 'Temp'),"$sd\Temp")){[void]$targets.Add($p)}
 $zone=@("$sd\Users","$sd\inetpub","$sd\Temp",(Join-Path $env:SystemRoot 'Temp'))
 foreach($u in @(Get-ChildItem "$sd\Users" -Directory -Force -ErrorAction SilentlyContinue)){
  foreach($rel in @('AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine','AppData\Roaming\Microsoft\Windows\Recent','AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup','AppData\Local\Microsoft\Terminal Server Client','AppData\Local\Temp','Desktop','Downloads','Documents')){[void]$targets.Add((Join-Path $u.FullName $rel))}
 }
 $deadline=(Get-Date).ToUniversalTime().AddMinutes($HotMinutes)
 $st=Scan-Tree @($targets.ToArray()) $deadline @() $zone 'File bytes (known folder)'
 Add-FileCoverage 'Known folders' $st "hosts file, PowerShell history, recent items, RDP client cache, startup, temp, user desktop/downloads/documents, IIS config and web root; budget ${HotMinutes}m."
}
function Collect-DeepFiles{
 if(-not ('IpSweepFileScan' -as [type])){Add-Type -TypeDefinition (Get-FileScannerSource)}
 $deadline=(Get-Date).ToUniversalTime().AddMinutes($DiskMinutes)
 $roots=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|ForEach-Object { $_.DeviceID+'\' })
 $sysDrive=$env:SystemDrive
 $priority=@("$sysDrive\inetpub","$sysDrive\Users","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup","$sysDrive\Temp","$env:SystemRoot\Temp","$env:SystemRoot\System32\Tasks","$env:SystemRoot\System32\inetsrv\config","$env:ProgramData","$sysDrive\BlueOps")
 $late=@($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)})|Where-Object {$_}
 $zone=@("$sysDrive\Users","$sysDrive\inetpub","$sysDrive\Temp","$env:SystemRoot\Temp","$env:ProgramData")
 $st=Scan-Tree @($priority+$roots) $deadline @($late) $zone 'File bytes'
 Add-FileCoverage 'Disk text references' $st "Fixed drives=$($roots -join ','); budget=${DiskMinutes}m. Order: IIS, user profiles, startup, temp, task and ProgramData folders first; Windows and Program Files last, so a timeout cuts off the least likely places."
}
$script:SummaryLines=New-Object Collections.ArrayList
function Emit([string]$Text,[string]$Color='White'){Write-Host $Text -ForegroundColor $Color;[void]$script:SummaryLines.Add($Text)}
function Short([string]$Text,[int]$Max){if($null -eq $Text){return ''};$t=($Text -replace '\s+',' ').Trim();if($t.Length -gt $Max){return $t.Substring(0,$Max-3)+'...'};return $t}
function Show-Results{
 $f=@($script:Findings.ToArray())
 Emit '' ;Emit ("=== RESULTS: $($f.Count) finding(s) tied to 10.111.11.x on $env:COMPUTERNAME$(if($Quick){' (QUICK: tier 1 only)'}) ===") 'Cyan'
 if(-not $f.Count){Emit 'No findings. That does NOT mean clean - read the coverage gaps below.' 'Yellow'}
 else{
  Emit '';Emit 'IPs found:' 'Cyan'
  foreach($g in ($f|Group-Object IP|Sort-Object Name)){
   $d=@($g.Group|Where-Object Category -eq 'Direct').Count;$c=@($g.Group|Where-Object Category -eq 'Correlated').Count;$r=@($g.Group|Where-Object Category -eq 'Reference').Count
   Emit ('  '+$g.Name.PadRight(15)+"  Direct $d   Correlated $c   Reference $r")
  }
  $meaning=@{Direct='recorded connection / logon / access event';Correlated='linked by shared process or logon ID, not proof';Reference='IP only appears as text'}
  $color=@{Direct='Red';Correlated='Yellow';Reference='Gray'}
  foreach($cat in @('Direct','Correlated','Reference')){
   $rows=@($f|Where-Object Category -eq $cat|Sort-Object IP,Source);$cap=200;if($cat -eq 'Reference'){$cap=50}
   Emit '';Emit ("$($cat.ToUpper()) ($($rows.Count)) - $($meaning[$cat])") $color[$cat]
   foreach($x in ($rows|Select-Object -First $cap)){Emit ('  '+([string]$x.IP).PadRight(15)+' '+(Short $x.Source 28).PadRight(28)+' '+(Short $x.Item 110))}
   if($rows.Count -gt $cap){Emit ("  ...$($rows.Count-$cap) more in findings.csv") 'DarkGray'}
  }
 }
 $bad=@($script:Coverage|Where-Object {$_.Status -ne 'OK'})
 Emit '';Emit ("COVERAGE GAPS ($($bad.Count)) - everything is in coverage.csv") 'Yellow'
 foreach($c in $bad){Emit ('  '+([string]$c.Status).PadRight(11)+' '+$c.Stage+' - '+(Short $c.Detail 100))}
 Emit '';Emit "Saved: $script:Output  (findings.csv, coverage.csv, summary.txt)" 'Green'
 $script:SummaryLines|Set-Content -LiteralPath (Join-Path $script:Output 'summary.txt') -Encoding UTF8
}
function Assert-OutputPath([string]$Path){
 $p=[IO.Path]::GetFullPath($Path);while($p){if(Test-Path -LiteralPath $p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw "Output path contains a link: $p"}};$p=[IO.Path]::GetDirectoryName($p)}
}
# Entry point. Functions above can be loaded for non-Windows logic tests without collecting data.
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 Desktop.'}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run Windows PowerShell as Administrator.'}
$script:Output=Join-Path 'C:\BlueLogs\IpSweep' ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
Assert-OutputPath $script:Output;New-Item -ItemType Directory -Path $script:Output -Force|Out-Null
$acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)');Set-Acl -LiteralPath $script:Output -AclObject $acl
Write-Host "Reports: $script:Output"
@"
Read-only triage of 10.111.11.0/24 on $env:COMPUTERNAME. Started: $((Get-Date).ToUniversalTime().ToString('o')).
Direct = observed connection/logon/access event, not automatically execution.
Correlated = a shared ProcessGuid or current-boot SID/logon ID, not remote causation.
Reference = IP text only (or a count of web-request records for an address, see Direct / IIS log). Read coverage.csv and file-errors.csv before drawing conclusions.
No findings does not mean clean. Past activity exists only if retained logging captured it.
Open CSV/JSON as text when investigating untrusted command lines (spreadsheet formulas may be embedded).
"@|Set-Content -LiteralPath (Join-Path $script:Output 'README.txt') -Encoding UTF8
try{$script:BootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime}catch{$script:BootTime=$null;Add-Coverage 'Boot time' 'ERROR' 0 $_.Exception.Message}
function Show-Tier([string]$Name,[datetime]$Started){
 $f=@($script:Findings.ToArray())
 $d=@($f|Where-Object Category -eq 'Direct').Count;$c=@($f|Where-Object Category -eq 'Correlated').Count;$r=@($f|Where-Object Category -eq 'Reference').Count
 Write-Host ('=== {0} done in {1}s - {2} finding(s) so far: Direct {3}, Correlated {4}, Reference {5} ===' -f $Name,[int]((Get-Date)-$Started).TotalSeconds,$f.Count,$d,$c,$r) -ForegroundColor Cyan
}
try{
 $t=Get-Date;Write-Host '--- Tier 1: known hiding places ---' -ForegroundColor Cyan
 Invoke-Stage 'Live TCP' {Collect-Live}
 Invoke-Stage 'Live SMB' {Collect-Smb}
 Invoke-Stage 'ARP/DNS cache' {Collect-Network}
 Invoke-Stage 'Firewall rules' {Collect-Firewall}
 Invoke-Stage 'Service/task definitions' {Collect-ServicesAndTasks}
 Invoke-Stage 'WMI subscriptions' {Collect-Wmi}
 Invoke-Stage 'Registry known spots' {Collect-RegistryHot}
 Invoke-Stage 'IIS/HTTP logs' {Collect-IisLogs}
 Invoke-Stage 'Known folders' {Collect-HotFiles}
 Show-Tier 'Tier 1' $t
 if($Quick){
  Add-Coverage 'Mode' 'PARTIAL' 0 'QUICK: only tier 1 ran. Event logs, whole-registry text and the deep disk scan were NOT run. Run without -Quick for those.'
 }else{
  $t=Get-Date;Write-Host '--- Tier 2: event logs ---' -ForegroundColor Cyan
  foreach($plan in @(Get-EventPlans)){Invoke-Stage $plan.Label {Collect-EventQuery $plan.Label $plan.Log $plan.Filter $plan.Fallback}}
  Invoke-Stage 'Historical correlation' {Correlate-History}
  Show-Tier 'Tier 2' $t
  $t=Get-Date;Write-Host '--- Tier 3: deep scan (up to about 25 minutes; Ctrl+C keeps what is found) ---' -ForegroundColor Cyan
  Invoke-Stage 'Registry (whole)' {Collect-RegistryDeep}
  Invoke-Stage 'File references' {Collect-DeepFiles}
  Show-Tier 'Tier 3' $t
 }
 $script:Completed=$true
}finally{
 if(-not $script:Completed){Write-Host 'Stopped early - the results below are what was found so far.' -ForegroundColor Yellow;Add-Coverage 'Run' 'INTERRUPTED' 0 'Stopped before all steps finished; later steps did not run.'}
 Save-Reports
 Show-Results
}
