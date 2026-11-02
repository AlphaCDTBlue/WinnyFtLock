#Requires -Version 5.1
<#
Fix-Site503.ps1 - finds and fixes why the IIS website returns HTTP 503.
Run elevated in 64-bit Windows PowerShell 5.1:  .\Fix-Site503.ps1      (undo its changes: .\Fix-Site503.ps1 -Undo)
Order: check what is wrong, then try one safe fix at a time and re-test the site after each. It stops as soon as the
site answers. Fixes, in order:
  1 start WAS/W3SVC if stopped      2 start + recycle stopped application pools
  3 reset pool limits that cause 503 (CPU limit, tiny queue, rapid-fail stop)     4 give the pool read access to the site folder
  5 switch a broken custom pool identity to ApplicationPoolIdentity (reverted at once if it does not help)
  6 restart WAS/W3SVC (brief outage; uses BlueOps if present)
It also looks for something that keeps stopping the pool (tasks/processes) and reports it. It never touches site files,
accounts or the IIS config files. Log: C:\BlueLogs\fix503_<host>_<time>.txt   Changes: C:\BlueLogs\Fix503\changes.json
#>
[CmdletBinding()]
param([switch]$Undo)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 as Administrator.'}
if(-not(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Open Windows PowerShell as Administrator.'}

$AppCmd=Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
if(-not(Test-Path -LiteralPath $AppCmd)){throw 'IIS is not installed (appcmd.exe not found).'}
$LogDir='C:\BlueLogs';$ChangeDir=Join-Path $LogDir 'Fix503';$ChangeFile=Join-Path $ChangeDir 'changes.json'
New-Item -ItemType Directory -Path $ChangeDir -Force|Out-Null
$Log=Join-Path $LogDir ('fix503_'+$env:COMPUTERNAME+'_'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.txt')
$script:Changes=New-Object System.Collections.ArrayList
$script:FixedAt=''

function Say([string]$Text,[string]$Color='Gray'){Write-Host $Text -ForegroundColor $Color;try{Add-Content -LiteralPath $Log -Value $Text}catch{}}
function Invoke-AppCmd{
 $o=@(& $AppCmd @args 2>&1)
 if($LASTEXITCODE -ne 0){throw ('appcmd '+($args -join ' ')+' failed: '+(($o|Out-String).Trim()))}
 return $o
}
function Save-Changes{ConvertTo-Json -InputObject @($script:Changes.ToArray()) -Depth 6|Set-Content -LiteralPath $ChangeFile -Encoding UTF8}
function Add-Change($Kind,$Target,$Setting,$Old,$New){
 [void]$script:Changes.Add([pscustomobject]@{Time=(Get-Date).ToString('o');Kind=$Kind;Target=$Target;Setting=$Setting;Old=$Old;New=$New});Save-Changes
}

# ---------------- Undo ----------------
if($Undo){
 if(-not(Test-Path -LiteralPath $ChangeFile)){Say 'No recorded changes to undo.' Yellow;return}
 $list=@(Get-Content -LiteralPath $ChangeFile -Raw|ConvertFrom-Json)
 [array]::Reverse($list)
 foreach($c in $list){
  try{
   if($c.Kind -eq 'pool'){Invoke-AppCmd set apppool $c.Target ('/'+$c.Setting+':'+$c.Old)|Out-Null;Say ('Restored pool '+$c.Target+' '+$c.Setting+' = '+$c.Old) Green}
   elseif($c.Kind -eq 'acl'){& icacls.exe $c.Target /remove:g $c.Setting|Out-Null;Say ('Removed '+$c.Setting+' access added on '+$c.Target) Green}
   elseif($c.Kind -eq 'identity'){Say ('Pool '+$c.Target+' identity was a custom account ('+$c.Old+'). Set it again by hand if you still need it: appcmd set apppool "'+$c.Target+'" /processModel.identityType:SpecificUser /processModel.userName:'+$c.Old+' /processModel.password:<password>') Yellow}
   else{Say ('Nothing to undo for '+$c.Kind+' '+$c.Target) DarkGray}
  }catch{Say ('Could not undo '+$c.Kind+' '+$c.Target+': '+$_.Exception.Message) Red}
 }
 Move-Item -LiteralPath $ChangeFile -Destination ($ChangeFile+'.undone-'+(Get-Date -Format 'HHmmss')) -Force
 return
}

# ---------------- IIS model (appcmd plain-text output) ----------------
function Get-IisSites{
 $out=@()
 foreach($l in @(Invoke-AppCmd list site)){
  if("$l" -match '^SITE "(?<n>.+?)" \(id:(?<id>\d+),bindings:(?<b>.*),state:(?<s>\w+)\)\s*$'){
   $out+=,[pscustomobject]@{Name=$Matches.n;Id=$Matches.id;Bindings=@($Matches.b -split ',' |Where-Object{$_});State=$Matches.s}
  }
 }
 return $out
}
function Get-IisApps{
 $out=@()
 foreach($l in @(Invoke-AppCmd list app)){
  if("$l" -match '^APP "(?<n>.+?)" \(applicationPool:(?<p>.+?)\)\s*$'){$out+=,[pscustomobject]@{Name=$Matches.n;Pool=$Matches.p}}
 }
 return $out
}
function Get-IisVdirs{
 $out=@()
 foreach($l in @(Invoke-AppCmd list vdir)){
  if("$l" -match '^VDIR "(?<n>.+?)" \(physicalPath:(?<p>.+)\)\s*$'){$out+=,[pscustomobject]@{Name=$Matches.n;Path=[Environment]::ExpandEnvironmentVariables($Matches.p)}}
 }
 return $out
}
function Get-IisPools{
 $out=@()
 foreach($l in @(Invoke-AppCmd list apppool)){
  if("$l" -match '^APPPOOL "(?<n>.+?)" \((?<d>.*)\)\s*$'){
   $pname=$Matches.n;$pdetail=$Matches.d;$st=''
   if($pdetail -match 'state:(\w+)'){$st=$Matches[1]}
   $out+=,[pscustomobject]@{Name=$pname;State=$st}
  }
 }
 return $out
}
function Get-PoolValue([string]$Pool,[string]$Key){return (((Invoke-AppCmd list apppool $Pool ('/text:'+$Key))|Out-String).Trim())}
function Set-PoolValue([string]$Pool,[string]$Key,[string]$New,[string]$Why){
 $old=Get-PoolValue $Pool $Key
 if($old -ieq $New){return $false}
 Invoke-AppCmd set apppool $Pool ('/'+$Key+':'+$New)|Out-Null
 Add-Change 'pool' $Pool $Key $old $New
 Say ('  changed pool '+$Pool+': '+$Key+' '+$old+' -> '+$New+'  ('+$Why+')') Cyan
 return $true
}

# Sites the test should cover: every started site that has an http binding; pools come from the site's root application.
function Get-Targets{
 $apps=@(Get-IisApps);$targets=@()
 foreach($s in @(Get-IisSites)){
  $app=$apps|Where-Object{$_.Name -ieq ($s.Name+'/')}|Select-Object -First 1
  $url='';$hostName=''
  foreach($b in $s.Bindings){
   if($b -match '^http/(?<ip>[^:]*):(?<port>\d+):(?<h>.*)$'){$url='http://127.0.0.1:'+$Matches.port+'/';$hostName=$Matches.h;break}
  }
  $targets+=,[pscustomobject]@{Site=$s.Name;State=$s.State;Pool=$(if($app){$app.Pool}else{''});Url=$url;HostName=$hostName}
 }
 return $targets
}
function Test-Url([string]$Url,[string]$HostName){
 if(-not $Url){return [pscustomobject]@{Code=-1;Text='no http binding'}}
 try{
  $r=[Net.HttpWebRequest]::Create($Url);$r.Timeout=20000;$r.AllowAutoRedirect=$false;$r.UserAgent='Fix-Site503'
  if($HostName){$r.Host=$HostName}
  $resp=$null
  try{$resp=$r.GetResponse()}catch [Net.WebException]{$resp=$_.Exception.Response;if(-not $resp){return [pscustomobject]@{Code=0;Text=$_.Exception.Message}}}
  $code=[int]$resp.StatusCode;$txt=[string]$resp.StatusDescription;$resp.Close()
  return [pscustomobject]@{Code=$code;Text=$txt}
 }catch{return [pscustomobject]@{Code=0;Text=$_.Exception.Message}}
}
# Returns the sites that are still failing (503, or no answer at all).
function Get-Failing{
 $bad=@()
 foreach($t in @(Get-Targets|Where-Object{$_.State -eq 'Started' -and $_.Url})){
  $r=Test-Url $t.Url $t.HostName
  if($r.Code -eq 503 -or $r.Code -eq 0){$bad+=,[pscustomobject]@{Site=$t.Site;Code=$r.Code;Text=$r.Text}}
 }
 return $bad
}
function Check-Fixed([string]$Step){
 Start-Sleep -Seconds 2
 $bad=@(Get-Failing)
 if(-not $bad.Count){$script:FixedAt=$Step;Say ('  Site answers now (no 503) after: '+$Step) Green;return $true}
 Say ('  still failing: '+(($bad|ForEach-Object{$_.Site+' -> '+$_.Code+' '+$_.Text}) -join '; ')) Yellow
 return $false
}

# ---------------- evidence ----------------
function Show-Events{
 Say 'WAS (IIS service) events, last 2 hours:'
 try{
  $ev=@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-WAS';StartTime=(Get-Date).AddHours(-2)} -MaxEvents 8 -ErrorAction Stop)
  foreach($e in $ev){$m=(($e.Message -split "`r?`n")[0]);if($m.Length -gt 230){$m=$m.Substring(0,230)};Say ('  {0:HH:mm:ss} id {1}: {2}' -f $e.TimeCreated,$e.Id,$m)}
  $ids=@($ev|ForEach-Object{$_.Id}|Sort-Object -Unique)
  if($ids -contains 5002 -or $ids -contains 5057){Say '  -> 5002/5057: the pool was shut off after its worker process kept failing (rapid-fail protection).' DarkYellow}
  if($ids -contains 5021 -or $ids -contains 5059){Say '  -> 5021/5059: the pool identity could not log on (wrong or expired password, locked/disabled account).' DarkYellow}
  if($ids -contains 5139 -or $ids -contains 5189){Say '  -> 5139/5189: a pool CPU limit or setting is shutting the pool down.' DarkYellow}
  return $ids
 }catch{Say '  (none found)';return @()}
}
function Show-AppErrors{
 Say 'IIS/.NET errors in the Application log, last 2 hours:'
 try{
  $ev=@(Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2;StartTime=(Get-Date).AddHours(-2)} -MaxEvents 80 -ErrorAction Stop|Where-Object{$_.ProviderName -match '(?i)iis|asp\.net|\.net runtime|application error|w3svc|^was$'}|Select-Object -First 6)
  if(-not $ev.Count){Say '  (none found)'}
  foreach($e in $ev){$m=(($e.Message -split "`r?`n")[0]);if($e.ProviderName -eq 'Application Error'){$m=(($e.Message -split "`r?`n")|Select-Object -First 4) -join ' ';}if($m.Length -gt 260){$m=$m.Substring(0,260)};Say ('  {0:HH:mm:ss} {1} id {2}: {3}' -f $e.TimeCreated,$e.ProviderName,$e.Id,$m)}
 }catch{Say '  (none found)'}
}
function Show-RequestQueues{
 Say 'HTTP.sys request queues:'
 try{
  $name='';$any=$false
  foreach($l in @(& netsh.exe http show servicestate view=requestq 2>&1)){
   if("$l" -match 'Request queue name:\s*(.+?)\s*$'){$name=$Matches[1]}
   elseif($name -and "$l" -match '^\s*State:\s*(.+?)\s*$'){Say ('  '+$name+': '+$Matches[1]);$name='';$any=$true}
  }
  if(-not $any){Say '  (nothing listed)'}
 }catch{Say '  (could not read request queues)'}
}
# Something that keeps stopping the pool: scheduled tasks and running processes that call stop commands.
$StopPattern='(?i)stop-webapppool|stop-website|stop\s+apppool|stop\s+site|iisreset(\.exe)?\s+/stop|net1?\s+stop\s+(w3svc|was)|sc(\.exe)?\s+stop\s+(w3svc|was)|stop-service[^\r\n]{0,60}(w3svc|was)'
function Find-PoolStoppers{
 Say 'Looking for anything that stops IIS or the pool:'
 $hits=0
 try{
  foreach($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)){
   if($t.TaskName -match '^(gitat|watchdogs|Remo)'){continue}
   $text=(@($t.Actions|ForEach-Object{[string]$_.Execute+' '+[string]$_.Arguments}) -join ' ')
   $why=''
   if($text -match $StopPattern){$why='its command'}
   else{
    foreach($m in [regex]::Matches($text,'(?i)[a-z]:\\[^"''<>|]+?\.(ps1|bat|cmd|vbs)')){
     $f=$m.Value
     try{if((Test-Path -LiteralPath $f -PathType Leaf) -and ((Get-Item -LiteralPath $f).Length -lt 2MB) -and ((Get-Content -LiteralPath $f -Raw -ErrorAction Stop) -match $StopPattern)){$why='the script '+$f;break}}catch{}
    }
   }
   if($why){$hits++;Say ('  SUSPECT task '+$t.TaskPath+$t.TaskName+' ('+$t.State+'): stop command in '+$why) Red}
  }
 }catch{Say ('  (task scan stopped: '+$_.Exception.Message+')')}
 try{
  foreach($p in @(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object{$_.ProcessId -ne $PID -and $_.CommandLine -and $_.CommandLine -match $StopPattern})){
   $hits++;Say ('  SUSPECT process '+$p.Name+' (PID '+$p.ProcessId+'): '+$p.CommandLine.Substring(0,[math]::Min(200,$p.CommandLine.Length))) Red
  }
 }catch{}
 if(-not $hits){Say '  (nothing found)'}else{Say '  -> Disable these (Remo.ps1 -Action Once or End-Schedule.ps1 disables all non-Remo tasks), or the fix will be undone.' DarkYellow}
 return $hits
}

# ---------------- run ----------------
Say ('Fix-Site503 on '+$env:COMPUTERNAME+'  '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) Cyan
Say ('Log: '+$Log) DarkGray
Say ''
$targets=@(Get-Targets)
Say 'Sites:'
foreach($t in $targets){
 $r=Test-Url $t.Url $t.HostName
 Say ('  '+$t.Site+'  state='+$t.State+'  pool='+$t.Pool+'  url='+$(if($t.Url){$t.Url}else{'(no http binding)'})+'  -> '+$(if($r.Code -gt 0){[string]$r.Code+' '+$r.Text}elseif($r.Code -eq 0){'NO ANSWER: '+$r.Text}else{$r.Text}))
}
Say 'Services:'
foreach($n in 'WAS','W3SVC'){$s=Get-Service -Name $n -ErrorAction SilentlyContinue;Say ('  '+$n+': '+$(if($s){[string]$s.Status}else{'not installed'}))}
Say 'Application pools:'
foreach($p in @(Get-IisPools)){Say ('  '+$p.Name+': '+$p.State)}
Show-RequestQueues
$ids=@(Show-Events)
Show-AppErrors
[void](Find-PoolStoppers)
Say ''

$bad=@(Get-Failing)
$testable=@($targets|Where-Object{$_.State -eq 'Started' -and $_.Url}).Count
if(-not $testable){
 Say 'No started site with an http binding to test, so nothing was changed. Start the site first (appcmd start site "<name>") and run this again.' Yellow
}elseif(-not $bad.Count){
 Say 'No site is returning 503 or failing to answer right now. Nothing to fix.' Green
}else{
 Say 'Fixing (re-testing after each step):' Cyan
 $poolNames=@($targets|Where-Object{$_.State -eq 'Started' -and $_.Pool}|ForEach-Object{$_.Pool}|Sort-Object -Unique)
 if(-not $poolNames.Count){$poolNames=@(Get-IisPools|ForEach-Object{$_.Name})}

 # 1 services
 Say '1. IIS services'
 foreach($n in 'WAS','W3SVC'){
  $s=Get-Service -Name $n -ErrorAction SilentlyContinue
  if($s -and $s.Status -ne 'Running'){
   try{Start-Service -Name $n;Say ('  started '+$n) Cyan}
   catch{
    $ctl='C:\BlueOps\Svc-Control.ps1'
    if($n -eq 'W3SVC' -and (Test-Path -LiteralPath $ctl)){try{& $ctl -Service IIS -Action Start|Out-Null;Say '  started W3SVC through BlueOps' Cyan}catch{Say ('  could not start '+$n+': '+$_.Exception.Message) Red}}
    else{Say ('  could not start '+$n+': '+$_.Exception.Message) Red}
   }
  }
 }
 if(-not $script:FixedAt -and (Check-Fixed 'IIS services')){}

 # 2 pools
 if(-not $script:FixedAt){
  Say '2. Start and recycle the pools'
  foreach($pn in $poolNames){
   try{
    $st=(Get-PoolValue $pn 'state')
    if($st -ne 'Started'){Invoke-AppCmd start apppool $pn|Out-Null;Say ('  started pool '+$pn) Cyan}else{Invoke-AppCmd recycle apppool $pn|Out-Null;Say ('  recycled pool '+$pn) Cyan}
   }catch{Say ('  pool '+$pn+': '+$_.Exception.Message) Red}
  }
  foreach($t in $targets){if($t.State -ne 'Started'){try{Invoke-AppCmd start site $t.Site|Out-Null;Say ('  started site '+$t.Site) Cyan}catch{Say ('  site '+$t.Site+': '+$_.Exception.Message) Red}}}
  [void](Check-Fixed 'pool start/recycle')
 }

 # 3 pool limits that cause 503
 if(-not $script:FixedAt){
  Say '3. Pool limits that cause 503'
  $changed=$false
  foreach($pn in $poolNames){
   try{
    $lim=0;[void][int]::TryParse((Get-PoolValue $pn 'cpu.limit'),[ref]$lim)
    if($lim -gt 0){if(Set-PoolValue $pn 'cpu.limit' '0' 'a CPU limit can shut the pool down'){$changed=$true}}
    $q=0;[void][int]::TryParse((Get-PoolValue $pn 'queueLength'),[ref]$q)
    if($q -lt 1000){if(Set-PoolValue $pn 'queueLength' '1000' 'a tiny request queue answers 503 under load'){$changed=$true}}
    if(($ids -contains 5002) -or ($ids -contains 5057)){if(Set-PoolValue $pn 'failure.rapidFailProtection' 'false' 'keeps the pool from being shut off after repeated failures'){$changed=$true}}
    if((Get-PoolValue $pn 'autoStart') -ieq 'false'){if(Set-PoolValue $pn 'autoStart' 'true' 'pool must start automatically'){$changed=$true}}
   }catch{Say ('  pool '+$pn+': '+$_.Exception.Message) Red}
  }
  if($changed){foreach($pn in $poolNames){try{Invoke-AppCmd recycle apppool $pn|Out-Null}catch{}};[void](Check-Fixed 'pool limits')}else{Say '  nothing to change.'}
 }

 # 4 folder access
 if(-not $script:FixedAt){
  Say '4. Pool access to the site folder and IIS temp folder'
  $changed=$false
  try{
   $temp=Join-Path $env:SystemDrive 'inetpub\temp\appPools'
   if(-not(Test-Path -LiteralPath $temp)){New-Item -ItemType Directory -Path $temp -Force|Out-Null;Say ('  created missing '+$temp) Cyan;$changed=$true}
  }catch{Say ('  temp folder: '+$_.Exception.Message) Red}
  $vdirs=@(Get-IisVdirs)
  foreach($t in @($targets|Where-Object{$_.State -eq 'Started'})){
   $v=$vdirs|Where-Object{$_.Name -ieq ($t.Site+'/')}|Select-Object -First 1
   if(-not $v -or -not (Test-Path -LiteralPath $v.Path)){if($v){Say ('  site folder missing: '+$v.Path) Red};continue}
   try{
    $acl=Get-Acl -LiteralPath $v.Path
    $ok=$false
    foreach($r in $acl.Access){
     if($r.AccessControlType -ne 'Allow'){continue}
     $who=[string]$r.IdentityReference
     if($who -match '(?i)IIS_IUSRS$|IIS AppPool\\|\\Users$|^Everyone$|Authenticated Users$'){if(($r.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq [Security.AccessControl.FileSystemRights]::ReadAndExecute){$ok=$true;break}}
    }
    if(-not $ok){
     & icacls.exe $v.Path /grant 'IIS_IUSRS:(OI)(CI)(RX)'|Out-Null
     if($LASTEXITCODE -eq 0){Add-Change 'acl' $v.Path 'IIS_IUSRS' '' 'RX';Say ('  gave IIS_IUSRS read access to '+$v.Path) Cyan;$changed=$true}
    }
   }catch{Say ('  ACL check on '+$v.Path+': '+$_.Exception.Message) Red}
  }
  if($changed){foreach($pn in $poolNames){try{Invoke-AppCmd recycle apppool $pn|Out-Null}catch{}};[void](Check-Fixed 'folder access')}else{Say '  access looks fine.'}
 }

 # 5 broken custom identity
 if(-not $script:FixedAt){
  Say '5. Pool identity'
  foreach($pn in $poolNames){
   try{
    $type=Get-PoolValue $pn 'processModel.identityType'
    if($type -ine 'SpecificUser'){Say ('  '+$pn+': '+$type+' (fine)');continue}
    $user=Get-PoolValue $pn 'processModel.userName';$pass=Get-PoolValue $pn 'processModel.password'
    Say ('  '+$pn+' runs as '+$user+'; trying ApplicationPoolIdentity instead') Yellow
    Invoke-AppCmd set apppool $pn '/processModel.identityType:ApplicationPoolIdentity'|Out-Null
    Invoke-AppCmd recycle apppool $pn|Out-Null
    if(Check-Fixed ('pool identity '+$pn+' -> ApplicationPoolIdentity')){Add-Change 'identity' $pn 'processModel.identityType' $user 'ApplicationPoolIdentity'}
    else{
     Invoke-AppCmd set apppool $pn '/processModel.identityType:SpecificUser' ('/processModel.userName:'+$user) ('/processModel.password:'+$pass)|Out-Null
     Invoke-AppCmd recycle apppool $pn|Out-Null
     Say ('  no improvement; '+$pn+' set back to '+$user) DarkGray
    }
   }catch{Say ('  pool '+$pn+': '+$_.Exception.Message) Red}
   if($script:FixedAt){break}
  }
 }

 # 6 restart the services
 if(-not $script:FixedAt){
  Say '6. Restart WAS/W3SVC (short outage)'
  $ctl='C:\BlueOps\Svc-Control.ps1'
  try{
   if(Test-Path -LiteralPath $ctl){& $ctl -Service IIS -Action Restart|Out-Null;Say '  restarted through BlueOps' Cyan}
   else{Restart-Service -Name W3SVC -Force;Say '  restarted W3SVC' Cyan}
   foreach($pn in $poolNames){try{if((Get-PoolValue $pn 'state') -ne 'Started'){Invoke-AppCmd start apppool $pn|Out-Null}}catch{}}
   Start-Sleep -Seconds 5
   [void](Check-Fixed 'service restart')
  }catch{Say ('  restart failed: '+$_.Exception.Message) Red}
 }
}

# ---------------- stability watch ----------------
Say ''
Say 'Stability watch (20 seconds):'
$poolsToWatch=@(Get-Targets|Where-Object{$_.Pool}|ForEach-Object{$_.Pool}|Sort-Object -Unique)
$last=@{};$flips=0
for($i=0;$i -lt 20;$i++){
 foreach($pn in $poolsToWatch){
  try{$st=Get-PoolValue $pn 'state'}catch{$st='?'}
  if($last.ContainsKey($pn) -and $last[$pn] -ne $st){$flips++;Say ('  '+(Get-Date -Format 'HH:mm:ss')+' pool '+$pn+' changed '+$last[$pn]+' -> '+$st) Red}
  $last[$pn]=$st
 }
 Start-Sleep -Seconds 1
}
foreach($pn in $poolsToWatch){Say ('  '+$pn+' ended '+$last[$pn])}
$finalBad=@(Get-Failing)

Say ''
if(-not $finalBad.Count -and -not $flips){
 if($script:FixedAt){Say ('RESULT: FIXED. The site answers and the pool stayed up. What fixed it: '+$script:FixedAt) Green}else{Say 'RESULT: site answers and the pool stayed up.' Green}
}elseif(-not $finalBad.Count){
 Say 'RESULT: site answers now, but a pool changed state during the watch - something is stopping or crashing it. See the SUSPECT lines and events above.' Yellow
}else{
 Say ('RESULT: NOT FIXED. Still failing: '+(($finalBad|ForEach-Object{$_.Site+' -> '+$_.Code}) -join '; ')) Red
 Say 'Send the log above. The WAS/Application error lines name the cause; a "faulting module" line means a bad module or the app itself is crashing the worker process.' Yellow
}
Say ('Changes made: '+$script:Changes.Count+$(if($script:Changes.Count){'  (undo with .\Fix-Site503.ps1 -Undo)'}else{''}))
Say ('Log: '+$Log) DarkGray
