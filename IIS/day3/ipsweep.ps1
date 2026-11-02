#Requires -Version 5.1
<# Read-only triage for 10.111.11.0/24. Run elevated, no arguments: .\ipsweep.ps1
When it finishes it prints every IP found and what is tied to it, then any coverage gaps.
Direct = a connection, logon or access event recorded for that IP. Correlated = linked to it through a shared
process or logon ID (NOT proof the IP issued the command). Reference = the IP is only written in text.
Fixed settings: last 7 days of logs, 50000 events per log, files up to 300 MB, 20 minutes of disk scanning
(IIS, user profiles, startup, temp and task folders first, Windows last). No findings does not mean clean.
No auditing changes, blocking or deletion. Evidence and coverage/errors: C:\BlueLogs\IpSweep\<run-id>.
#>
$Days=7;$MaxEventsPerLog=50000;$MaxFileMB=300;$DiskMinutes=20
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$script:Findings=New-Object Collections.ArrayList
$script:Coverage=New-Object Collections.ArrayList
$script:Seen=New-Object 'Collections.Generic.HashSet[string]'
$script:History=New-Object Collections.ArrayList
$script:DiskErrors=New-Object Collections.ArrayList
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
function Collect-EventLog([string]$Name){
 $count=0;$failures=0;$limited=$false
 try{
  $meta=Get-WinEvent -ListLog $Name -ErrorAction Stop
  if(-not $meta.IsEnabled){Add-Coverage "Log: $Name" 'UNAVAILABLE' 0 'Channel disabled; historical records, if any, are still queried.'}
  # Windows Event Log XPath lacks contains(); filter fields in PowerShell instead.
  Get-WinEvent -FilterHashtable @{LogName=$Name;StartTime=(Get-Date).AddDays(-$Days)} -MaxEvents ($MaxEventsPerLog+1) -ErrorAction Stop|ForEach-Object {
   $count++
   if($count -gt $MaxEventsPerLog){$limited=$true;return}
   try{
    $e=Get-EventData $_;$d=$e.Data
    if(($Name -eq 'Security' -and $e.Id -in @(4624,4688,4663)) -or ($Name -eq 'Microsoft-Windows-Sysmon/Operational' -and $e.Id -in @(1,3,7,11))){[void]$script:History.Add($e)}
    $direct=@()
    if($Name -eq 'Security'){
     if($e.Id -in @(4624,4625,5140,5145)){$direct=@('IpAddress')}
     if($e.Id -eq 5156){$direct=@('SourceAddress','DestAddress')}
    }elseif($Name -eq 'Microsoft-Windows-Sysmon/Operational' -and $e.Id -eq 3){$direct=@('SourceIp','DestinationIp')}
    $reported=New-Object 'Collections.Generic.HashSet[string]'
    foreach($key in $direct){$ip=Normalize-SubnetIP $d[$key];if($ip){[void]$reported.Add($ip);Add-Finding 'Direct' ("Event $($e.Id) / $key") $ip ($d.Image+$d.Application+$d.TargetUserName+$d.ShareName) ($d|ConvertTo-Json -Depth 6 -Compress) $e.Time $e.Log $e.RecordId $d.ProcessGuid $d.TargetLogonId $d.TargetUserName}}
    foreach($ip in @(Find-SubnetIPs $e.Xml)){if(-not $reported.Contains($ip)){Add-Finding 'Reference' ("Event $($e.Id) text") $ip $e.Provider $e.Xml $e.Time $e.Log $e.RecordId $d.ProcessGuid '' ''}}
   }catch{$failures++;if($failures -le 10){Add-Coverage "Log parse: $Name" 'ERROR' 1 $_.Exception.Message}}
  }
  $status=if($limited -or $failures){'PARTIAL'}else{'OK'}
  Add-Coverage "Log: $Name" $status ([math]::Min($count,$MaxEventsPerLog)) ("Last $Days days; newest $MaxEventsPerLog event limit; truncated=$limited; record errors=$failures. This does not establish audit coverage before collection.")
 }catch{
  if($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){Add-Coverage "Log: $Name" 'EMPTY' 0 'No retained records matched the time window; this does not prove no activity.'}
  else{Add-Coverage "Log: $Name" 'ERROR' $count $_.Exception.Message}
 }
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
function Collect-Registry{
 $total=0;$errors=0;$until=(Get-Date).AddMinutes(3)
 foreach($root in @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE','Registry::HKEY_LOCAL_MACHINE\SYSTEM','Registry::HKEY_USERS')){
  $stack=New-Object 'Collections.Generic.Stack[string]';$stack.Push($root)
  while($stack.Count){if((Get-Date) -gt $until){Add-Coverage 'Registry' 'PARTIAL' $total 'Three-minute registry budget reached; only HKLM SOFTWARE/SYSTEM and loaded user hives are in scope.';return}
   $key=$stack.Pop()
   try{
    $props=Get-ItemProperty -LiteralPath $key
    foreach($p in $props.PSObject.Properties){if($p.Name -like 'PS*'){continue};if($p.Value -is [string] -or $p.Value -is [string[]]){$total++;Add-References 'Registry text' ($key+'\'+$p.Name) ($p.Value -join ' ') (Get-Date)}}
    foreach($k in Get-ChildItem -LiteralPath $key){$stack.Push($k.PSPath)}
   }catch{$errors++;if($errors -le 30){Add-Coverage ('Registry key: '+$key) 'ERROR' 0 $_.Exception.Message}}
  }
 }
 Add-Coverage 'Registry' $(if($errors){'PARTIAL'}else{'OK'}) $total "String values only in HKLM SOFTWARE/SYSTEM and loaded user hives; unreadable keys=$errors; no offline hive loading."
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
function Collect-Files{
 Add-Type -TypeDefinition (Get-FileScannerSource)
 $deadline=(Get-Date).ToUniversalTime().AddMinutes($DiskMinutes);$count=0;$oversize=0;$links=0;$errors=0;$excluded=0;$timedOut=$false
 $roots=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|ForEach-Object { $_.DeviceID+'\' })
 $stack=New-Object 'Collections.Generic.Stack[string]';foreach($root in $roots){$stack.Push($root)}
 # Stack is last-in-first-out: push in reverse so the first priority folder is scanned first.
 $sysDrive=$env:SystemDrive
 $priority=@("$sysDrive\inetpub","$sysDrive\Users","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup","$sysDrive\Temp","$env:SystemRoot\Temp","$env:SystemRoot\System32\Tasks","$env:SystemRoot\System32\inetsrv\config","$env:ProgramData","$sysDrive\BlueOps")
 $late=@($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)})|Where-Object {$_}
 $visited=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 $lateQueue=New-Object 'Collections.Generic.List[string]'
 for($pi=$priority.Count-1;$pi -ge 0;$pi--){if(Test-Path -LiteralPath $priority[$pi] -PathType Container){$stack.Push($priority[$pi])}}
 while($true){
  if(-not $stack.Count){if($lateQueue.Count){foreach($l in $lateQueue){$stack.Push($l)};$lateQueue.Clear()}else{break}}
  if((Get-Date).ToUniversalTime() -gt $deadline){$timedOut=$true;break}
  $dir=$stack.Pop()
  if(-not $visited.Add($dir)){continue}
  try{$children=@(Get-ChildItem -LiteralPath $dir -Force)}catch{$errors++;[void]$script:DiskErrors.Add([pscustomobject]@{Path=$dir;Reason=$_.Exception.Message});continue}
  foreach($f in $children){
   if((Get-Date).ToUniversalTime() -gt $deadline){$timedOut=$true;break}
   if($f.Attributes -band [IO.FileAttributes]::ReparsePoint){$links++;continue}
   if($f.PSIsContainer){
    if($f.FullName -ieq $script:Output -or $f.Name -eq 'System Volume Information' -or $f.FullName -ieq (Join-Path $env:SystemRoot 'System32\winevt\Logs')){$excluded++;continue}
    if($late -contains $f.FullName){[void]$lateQueue.Add($f.FullName)}else{$stack.Push($f.FullName)}
    continue
   }
   if($f.FullName -ieq $PSCommandPath){$excluded++;continue}
   if($f.Length -gt $MaxFileMB*1MB){$oversize++;continue}
   try{
    $before=$f.LastWriteTimeUtc;$size=$f.Length;$hits=[IpSweepFileScan]::Scan($f.FullName,$deadline);$count++
    $after=Get-Item -LiteralPath $f.FullName -Force
    foreach($ip in $hits){Add-Finding 'Reference' 'File bytes' $ip $f.FullName ("IP literal in ASCII/UTF-16 bytes; size=$size; changedDuringRead=$($after.Length -ne $size -or $after.LastWriteTimeUtc -ne $before). Not proof of execution, authorship, or remote access.") $before}
    # Only the download-origin stream is inspected; other alternate streams are outside this scan.
    $stream=Get-Item -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
    if($stream){Add-References 'Zone.Identifier text' ($f.FullName+':Zone.Identifier') (Get-Content -LiteralPath $f.FullName -Stream Zone.Identifier -Raw) $before}
   }catch{$errors++;[void]$script:DiskErrors.Add([pscustomobject]@{Path=$f.FullName;Reason=$_.Exception.Message})}
  }
 }
 Add-Coverage 'Disk text references' $(if($timedOut -or $errors -or $oversize -or $links){'PARTIAL'}else{'OK'}) $count ("Fixed drives=$($roots -join ','); budget=${DiskMinutes}m; timedOut=$timedOut; over ${MaxFileMB}MB=$oversize; reparse points skipped=$links; excluded directories/self=$excluded; read errors=$errors. Order: IIS, user profiles, startup, temp, task and ProgramData folders first; Windows and Program Files last, so a timeout cuts off the least likely places. No archive unpacking, decryption, deleted-file recovery, network drives, or offline hives. UTF-8/ASCII and UTF-16 IP literals only; other ADS not scanned.")
}
$script:SummaryLines=New-Object Collections.ArrayList
function Emit([string]$Text,[string]$Color='White'){Write-Host $Text -ForegroundColor $Color;[void]$script:SummaryLines.Add($Text)}
function Short([string]$Text,[int]$Max){if($null -eq $Text){return ''};$t=($Text -replace '\s+',' ').Trim();if($t.Length -gt $Max){return $t.Substring(0,$Max-3)+'...'};return $t}
function Show-Results{
 $f=@($script:Findings.ToArray())
 Emit '' ;Emit ("=== RESULTS: $($f.Count) finding(s) tied to 10.111.11.x on $env:COMPUTERNAME ===") 'Cyan'
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
Reference = IP text only. Read coverage.csv and file-errors.csv before drawing conclusions.
No findings does not mean clean. Past activity exists only if retained logging captured it.
Open CSV/JSON as text when investigating untrusted command lines (spreadsheet formulas may be embedded).
"@|Set-Content -LiteralPath (Join-Path $script:Output 'README.txt') -Encoding UTF8
try{$script:BootTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime}catch{$script:BootTime=$null;Add-Coverage 'Boot time' 'ERROR' 0 $_.Exception.Message}
Invoke-Stage 'Live TCP' {Collect-Live}
Invoke-Stage 'Live SMB' {Collect-Smb}
$logs=@('Security','System','Application','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational','Windows PowerShell','Microsoft-Windows-WinRM/Operational','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational','Microsoft-Windows-TerminalServices-LocalSessionManager/Operational','Microsoft-Windows-TaskScheduler/Operational','OpenSSH/Operational')
foreach($name in @($logs|Sort-Object -Unique)){Invoke-Stage $name {Collect-EventLog $name}}
Invoke-Stage 'Historical correlation' {Correlate-History}
Invoke-Stage 'Service/task definitions' {Collect-ServicesAndTasks}
Invoke-Stage 'WMI subscriptions' {Collect-Wmi}
Invoke-Stage 'Registry references' {Collect-Registry}
Invoke-Stage 'File references' {Collect-Files}
Save-Reports
Show-Results
