#Requires -Version 5.1
<#
Fix-HttpError.ps1 - finds why the IIS website returns an error of one class, then fixes what it safely can.
Run elevated in 64-bit Windows PowerShell 5.1:   .\Fix-HttpError.ps1 <number>
  3 = 3xx redirects     4 = 4xx (400 401 403 404)     5 = 5xx (500 502 503 504)
  6 = no answer at all (refused / timed out / reset - HTTP has no 6xx, so this is the "site does not respond" class)
  0 = undo what earlier runs changed.      300 / 400 / 500 / 600 work too.
It reads the real error (IIS detail page, IIS log sub-status, HTTP.sys log, events), applies one fix at a time and
re-tests after each. It stops as soon as the class of error is gone.
BlueOps (Deploy-BlueOps) is assumed: W3SVC stop/restart/config is locked to SYSTEM, so service actions go through
C:\BlueOps\Svc-Control.ps1, and anything an administrator is refused is retried as SYSTEM through a one-use task.
If Remo or gitat is active it is PAUSED before the first change (it would restore its approved copy within 10 s and undo
the fix). It is left paused; the end of the run says how to resume. Site files are never overwritten: only MISSING files are
copied back from the approved baseline, and a malformed web.config is renamed, not deleted.
Log: C:\BlueLogs\fixhttp_<host>_<time>.txt     Changes (for 0): C:\BlueLogs\FixHttp\changes.json
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true,Position=0)][int]$Class)
$ErrorActionPreference='Stop'
if($Class -ge 100){$Class=[int][math]::Floor($Class/100)}
if($Class -notin 0,3,4,5,6){throw 'Use one number: 3 (3xx), 4 (4xx), 5 (5xx), 6 (no answer at all), or 0 to undo.'}
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 as Administrator.'}
if(-not(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Open Windows PowerShell as Administrator.'}
$AppCmd=Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
if(-not(Test-Path -LiteralPath $AppCmd)){throw 'IIS is not installed (appcmd.exe not found).'}
$LogDir='C:\BlueLogs';$Work=Join-Path $LogDir 'FixHttp';$ChangeFile=Join-Path $Work 'changes.json'
New-Item -ItemType Directory -Path $Work -Force|Out-Null
$Log=Join-Path $LogDir ('fixhttp_'+$env:COMPUTERNAME+'_'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.txt')
$script:Changes=New-Object System.Collections.ArrayList
$script:Fixed=$false;$script:Mutated=$false;$script:PauseDone=$false;$script:PausedBy=@()
if(Test-Path -LiteralPath $ChangeFile){try{foreach($c in @(Get-Content -LiteralPath $ChangeFile -Raw|ConvertFrom-Json)){[void]$script:Changes.Add($c)}}catch{}}

function Say([string]$Text,[string]$Color='Gray'){Write-Host $Text -ForegroundColor $Color;try{Add-Content -LiteralPath $Log -Value $Text}catch{}}
function Save-Changes{ConvertTo-Json -InputObject @($script:Changes.ToArray()) -Depth 6|Set-Content -LiteralPath $ChangeFile -Encoding UTF8}
function Add-Change($Kind,$Target,$Setting,$Old,$New,$Extra=''){
 [void]$script:Changes.Add([pscustomobject]@{Time=(Get-Date).ToString('o');Kind=$Kind;Target=$Target;Setting=$Setting;Old=$Old;New=$New;Extra=$Extra});Save-Changes
}
function Invoke-AppCmd{
 $o=@(& $AppCmd @args 2>&1)
 if($LASTEXITCODE -ne 0){throw ('appcmd '+($args -join ' ')+' failed: '+(($o|Out-String).Trim()))}
 return $o
}

# ---------------- running as SYSTEM (BlueOps/gitat protected things) ----------------
function Invoke-AsSystem([string]$Code){
 $id=[guid]::NewGuid().ToString('N');$dir=Join-Path $env:ProgramData ('FixHttp-'+$id);$name='FixHttp-'+$id
 New-Item -ItemType Directory -Path $dir -Force|Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)');Set-Acl -LiteralPath $dir -AclObject $acl
 $run=Join-Path $dir 'run.ps1';$out=Join-Path $dir 'out.txt';$done=Join-Path $dir 'done'
 Set-Content -LiteralPath $run -Encoding UTF8 -Value ('$ErrorActionPreference=''Continue'';& { '+$Code+' } *>&1 | Out-File -LiteralPath '''+$out+''' -Encoding UTF8;''x'' | Set-Content -LiteralPath '''+$done+'''')
 try{
  $act=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$run+'"')
  Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $act -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)) -User SYSTEM -RunLevel Highest|Out-Null
  Start-ScheduledTask -TaskName $name -TaskPath '\'
  $until=(Get-Date).AddSeconds(120);$kicked=$false
  while(-not(Test-Path -LiteralPath $done) -and (Get-Date) -lt $until){
   Start-Sleep -Milliseconds 500
   if(-not $kicked -and ((Get-Date) -gt $until.AddSeconds(-110))){$t=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue;if($t -and $t.State -eq 'Disabled'){Enable-ScheduledTask -TaskName $name -TaskPath '\'|Out-Null;Start-ScheduledTask -TaskName $name -TaskPath '\'};$kicked=$true}
  }
  if(Test-Path -LiteralPath $out){return (Get-Content -LiteralPath $out -Raw)}
  return ''
 }finally{
  try{Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue}catch{}
  try{Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue}catch{}
 }
}

# ---------------- BlueOps / recovery tools ----------------
function Get-FixEnv{
 $e=[ordered]@{Controller='C:\BlueOps\Svc-Control.ps1';Locked=$false;Gitat=$false;Remo=$false;RemoScript=''}
 try{if(((& sc.exe sdshow W3SVC 2>&1)|Out-String) -match '\(D;;DCWPDTSD;;;AU\)'){$e.Locked=$true}}catch{}
 try{$t=Get-ScheduledTask -TaskName gitat -TaskPath '\' -ErrorAction SilentlyContinue;if($t -and $t.Settings.Enabled -and (Test-Path 'C:\ProgramData\IISCache\settings.json') -and -not (Test-Path 'C:\ProgramData\IISCache\paused')){$e.Gitat=$true}}catch{}
 try{$f='C:\ProgramData\Remo\deployment.json';if(Test-Path -LiteralPath $f){$d=Get-Content -LiteralPath $f -Raw|ConvertFrom-Json;if($d.State -eq 'Active' -and -not $d.Paused){$e.Remo=$true;$e.RemoScript=[string]$d.Supervisor}}}catch{}
 return [pscustomobject]$e
}
# Called before the first change to IIS config, files or ACLs.
function Ensure-Paused{
 $script:Mutated=$true
 if($script:PauseDone){return}
 $script:PauseDone=$true
 if($script:Env.Remo -and $script:Env.RemoScript -and (Test-Path -LiteralPath $script:Env.RemoScript)){
  try{(& $script:Env.RemoScript -Action Pause *>&1)|ForEach-Object{Say ('  [Remo] '+$_) DarkGray};$script:PausedBy+='Remo';Start-Sleep -Seconds 12}catch{Say ('  could not pause Remo: '+$_.Exception.Message) Red}
 }
 if($script:Env.Gitat){try{New-Item -ItemType File -Path 'C:\ProgramData\IISCache\paused' -Force|Out-Null;$script:PausedBy+='gitat';Start-Sleep -Seconds 12}catch{Say ('  could not pause gitat: '+$_.Exception.Message) Red}}
 if($script:PausedBy.Count){Say ('  paused '+($script:PausedBy -join ' + ')+' so it does not restore its old copy over the fix') Yellow}
}
function Invoke-W3svc([string]$Action){
 $svc=Get-Service -Name W3SVC -ErrorAction Stop
 if($Action -eq 'Start' -and $svc.Status -eq 'Running'){return $true}
 if($Action -eq 'Start'){try{Start-Service -Name W3SVC -ErrorAction Stop;return $true}catch{Say ('  direct start refused ('+$_.Exception.Message+'); using BlueOps') DarkGray}}
 $ctl=$script:Env.Controller
 if(Test-Path -LiteralPath $ctl){
  $until=(Get-Date).AddSeconds(40)
  while((Test-Path 'C:\BlueOps\request.json') -and (Get-Date) -lt $until){Start-Sleep -Seconds 2}
  foreach($x in @(& $ctl -Service IIS -Action $Action)){if($null -ne $x -and $x.PSObject.Properties['Success'] -and -not $x.Success){throw 'BlueOps reported a failed service action.'}}
 }elseif($Action -eq 'Stop'){Stop-Service -Name W3SVC -Force}elseif($Action -eq 'Restart'){Restart-Service -Name W3SVC -Force}else{Start-Service -Name W3SVC}
 if($Action -eq 'Stop'){return $true}
 $until=(Get-Date).AddSeconds(45)
 do{Start-Sleep -Seconds 1;$s=(Get-Service -Name W3SVC).Status}while($s -ne 'Running' -and (Get-Date) -lt $until)
 if($s -ne 'Running'){throw ('W3SVC is '+$s+' after '+$Action)}
 return $true
}

# ---------------- IIS model (appcmd plain-text output) ----------------
function Get-Model{
 $apps=@{};foreach($l in @(Invoke-AppCmd list app)){if("$l" -match '^APP "(?<n>.+?)" \(applicationPool:(?<p>.+?)\)\s*$'){$apps[$Matches.n]=$Matches.p}}
 $vd=@{};foreach($l in @(Invoke-AppCmd list vdir)){if("$l" -match '^VDIR "(?<n>.+?)" \(physicalPath:(?<p>.+)\)\s*$'){$vd[$Matches.n]=[Environment]::ExpandEnvironmentVariables($Matches.p)}}
 $out=@()
 foreach($l in @(Invoke-AppCmd list site)){
  if("$l" -match '^SITE "(?<n>.+?)" \(id:(?<id>\d+),bindings:(?<b>.*),state:(?<s>\w+)\)\s*$'){
   $n=$Matches.n;$id=$Matches.id;$b=@($Matches.b -split ','|Where-Object{$_});$st=$Matches.s
   $http=$null;$https=$null
   foreach($x in $b){if($x -match '^http/(?<ip>[^:]*):(?<port>\d+):(?<h>.*)$' -and -not $http){$http=[pscustomobject]@{Port=[int]$Matches.port;Host=$Matches.h}}elseif($x -match '^https/' -and -not $https){$https=$x}}
   $out+=,[pscustomobject]@{Name=$n;Id=$id;State=$st;Bindings=$b;Pool=[string]$apps[$n+'/'];Path=[string]$vd[$n+'/'];Http=$http;Https=$https}
  }
 }
 return $out
}
function Get-PoolValue([string]$Pool,[string]$Key){return (((Invoke-AppCmd list apppool $Pool ('/text:'+$Key))|Out-String).Trim())}
function Set-PoolValue([string]$Pool,[string]$Key,[string]$New,[string]$Why){
 $old=Get-PoolValue $Pool $Key
 if($old -ieq $New){return $false}
 Ensure-Paused
 Invoke-AppCmd set apppool $Pool ('/'+$Key+':'+$New)|Out-Null
 Add-Change 'pool' $Pool $Key $old $New
 Say ('  pool '+$Pool+': '+$Key+' '+$old+' -> '+$New+'   ('+$Why+')') Cyan
 return $true
}
function Get-CfgAttrs([string]$Site,[string]$Section,[string]$Tag){
 try{$t=((Invoke-AppCmd list config $Site ('/section:'+$Section))|Out-String)}catch{return $null}
 $m=[regex]::Match($t,'<'+[regex]::Escape($Tag)+'(\s[^>]*)?/?>')
 $h=@{};if($m.Success){foreach($a in [regex]::Matches($m.Groups[1].Value,'([\w\.\-:]+)\s*=\s*"([^"]*)"')){$h[$a.Groups[1].Value]=$a.Groups[2].Value}}
 return $h
}
function Get-CfgText([string]$Site,[string]$Section){try{return (((Invoke-AppCmd list config $Site ('/section:'+$Section))|Out-String))}catch{return ''}}
function Set-Cfg([string]$Site,[string]$Section,[string]$Tag,[string]$Attr,[string]$New,[string]$Why){
 $cur=Get-CfgAttrs $Site $Section $Tag
 if($null -eq $cur){throw ('section '+$Section+' cannot be read')}
 $old=[string]$cur[$Attr]
 if($old -ieq $New){return $false}
 Ensure-Paused
 $commit=''
 try{Invoke-AppCmd set config $Site ('/section:'+$Section) ('/'+$Attr+':'+$New)|Out-Null}
 catch{Invoke-AppCmd set config $Site ('/section:'+$Section) ('/'+$Attr+':'+$New) '/commit:apphost'|Out-Null;$commit='apphost'}
 Add-Change 'config' $Site ($Section+'|'+$Attr) $old $New $commit
 Say ('  '+$Site+' '+$Section+': '+$Attr+' '+$(if($old){$old}else{'(empty)'})+' -> '+$(if($New){$New}else{'(empty)'})+'   ('+$Why+')') Cyan
 return $true
}
function Add-CfgItem([string]$Site,[string]$Section,[string]$Item,[string]$Why){
 Ensure-Paused
 $commit=''
 try{Invoke-AppCmd set config $Site ('/section:'+$Section) ('/+'+$Item)|Out-Null}
 catch{Invoke-AppCmd set config $Site ('/section:'+$Section) ('/+'+$Item) '/commit:apphost'|Out-Null;$commit='apphost'}
 Add-Change 'configadd' $Site ($Section+'|'+$Item) '' '' $commit
 Say ('  '+$Site+' '+$Section+': added '+$Item+'   ('+$Why+')') Cyan
 return $true
}

# ---------------- file and folder helpers ----------------
function Test-XmlFile([string]$Path){try{[void][xml](Get-Content -LiteralPath $Path -Raw -ErrorAction Stop);return $true}catch{return $false}}
function Save-Sddl([string]$Path){
 $a=Get-Acl -LiteralPath $Path;$f=Join-Path $Work ('acl-'+[guid]::NewGuid().ToString('N')+'.sddl')
 Set-Content -LiteralPath $f -Value $a.GetSecurityDescriptorSddlForm('Access') -Encoding ASCII;return $f
}
function Edit-Acl([string]$Path,[string]$Code,[string]$Why){
 Ensure-Paused
 $saved=Save-Sddl $Path
 $full='$p='''+$Path+''';$a=Get-Acl -LiteralPath $p;'+$Code+';Set-Acl -LiteralPath $p -AclObject $a'
 try{& ([scriptblock]::Create($full))}
 catch{Say ('  administrator refused ('+$_.Exception.Message+'); retrying as SYSTEM') DarkGray;[void](Invoke-AsSystem $full)}
 Add-Change 'aclsddl' $Path 'Access' $saved '';Say ('  '+$Path+': '+$Why) Cyan
}
function Grant-SiteAccess($Site){
 $changed=$false;$p=$Site.Path
 if(-not $p -or -not (Test-Path -LiteralPath $p)){return $false}
 $acl=Get-Acl -LiteralPath $p;$ok=$false;$denies=@()
 foreach($r in $acl.Access){
  $who=[string]$r.IdentityReference
  if($who -notmatch '(?i)IIS_IUSRS$|IUSR$|IIS AppPool\\|\\Users$|^Everyone$|Authenticated Users$'){continue}
  if($r.AccessControlType -eq 'Deny' -and (($r.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read) -ne 0)){$denies+=$who}
  if($r.AccessControlType -eq 'Allow' -and (($r.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq [Security.AccessControl.FileSystemRights]::ReadAndExecute)){$ok=$true}
 }
 if($denies.Count){
  $names=($denies|Sort-Object -Unique)
  $code='foreach($r in @($a.Access)){if($r.AccessControlType -eq ''Deny'' -and (@('+(($names|ForEach-Object{"'"+$_+"'"}) -join ',')+') -contains [string]$r.IdentityReference)){[void]$a.RemoveAccessRule($r)}}'
  Edit-Acl $p $code ('removed deny entries for '+($names -join ', '));$changed=$true
 }
 if(-not $ok){
  $code='$r=New-Object Security.AccessControl.FileSystemAccessRule(''IIS_IUSRS'',''ReadAndExecute'',''ContainerInherit,ObjectInherit'',''None'',''Allow'');$a.AddAccessRule($r)'
  Edit-Acl $p $code 'gave IIS_IUSRS read access';$changed=$true
 }
 return $changed
}
# Copies back only files that are MISSING from the approved baseline copy (never overwrites).
function Restore-Missing($Site){
 $root=$Site.Path;if(-not $root){return 0}
 $cands=@()
 foreach($d in @(Get-ChildItem -LiteralPath $env:ProgramData -Directory -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '^(Remo|RemoOnce)-[0-9a-f]{32}$'}|Sort-Object LastWriteTime -Descending)){$cands+=Join-Path $d.FullName 'settings.json'}
 $cands+=@((Join-Path $env:ProgramData 'IISCache\settings.json'),(Join-Path $env:ProgramData 'watchdogs\settings.json'))
 foreach($c in $cands){
  if(-not(Test-Path -LiteralPath $c)){continue}
  try{
   $m=Get-Content -LiteralPath $c -Raw|ConvertFrom-Json
   foreach($t in @($m.Targets)){
    if(([string]$t.Root).TrimEnd('\') -ine $root.TrimEnd('\')){continue}
    $src=[string]$t.Repo;if(-not(Test-Path -LiteralPath $src)){continue}
    Ensure-Paused
    if(-not(Test-Path -LiteralPath $root)){New-Item -ItemType Directory -Path $root -Force|Out-Null}
    $added=@()
    foreach($f in Get-ChildItem -LiteralPath $src -Recurse -File -Force -ErrorAction SilentlyContinue){
     $rel=$f.FullName.Substring($src.TrimEnd('\').Length+1)
     if($rel -match '^\.git(\\|$)'){continue}
     $dst=Join-Path $root $rel
     if(-not(Test-Path -LiteralPath $dst)){New-Item -ItemType Directory -Path (Split-Path $dst -Parent) -Force|Out-Null;Copy-Item -LiteralPath $f.FullName -Destination $dst;$added+=$dst}
    }
    if($added.Count){$lst=Join-Path $Work ('added-'+[guid]::NewGuid().ToString('N')+'.txt');Set-Content -LiteralPath $lst -Value $added -Encoding UTF8;Add-Change 'filesadded' $root '' $lst '';Say ('  copied back '+$added.Count+' missing file(s) from '+$src) Cyan}
    return $added.Count
   }
  }catch{Say ('  baseline '+$c+': '+$_.Exception.Message) DarkGray}
 }
 return 0
}

# ---------------- probes ----------------
function Invoke-Probe([string]$Url,[string]$HostName){
 $r=[pscustomobject]@{Url=$Url;Code=0;Sub='';Status='';Location='';Headers=@{};Body='';Detail=@{};Error=''}
 try{
  $q=[Net.HttpWebRequest]::Create($Url);$q.Timeout=20000;$q.ReadWriteTimeout=20000;$q.AllowAutoRedirect=$false;$q.UserAgent='Fix-HttpError';$q.KeepAlive=$false
  if($HostName){$q.Host=$HostName}
  $resp=$null
  try{$resp=$q.GetResponse()}catch [Net.WebException]{$resp=$_.Exception.Response;$r.Error=$_.Exception.Message;if(-not $resp){return $r}}
  $r.Code=[int]$resp.StatusCode;$r.Status=[string]$resp.StatusDescription;$r.Location=[string]$resp.Headers['Location']
  foreach($k in $resp.Headers.AllKeys){$r.Headers[$k]=[string]$resp.Headers[$k]}
  try{$sr=New-Object IO.StreamReader($resp.GetResponseStream());$txt=$sr.ReadToEnd();if($txt.Length -gt 30000){$txt=$txt.Substring(0,30000)};$r.Body=$txt;$sr.Dispose()}catch{}
  $resp.Close()
  if($r.Body -match 'HTTP Error (\d{3})\.(\d+)'){$r.Sub=$Matches[2]}
  foreach($m in [regex]::Matches($r.Body,'(?is)<th[^>]*>\s*([^<]+?)\s*</th>\s*<td[^>]*>\s*(.*?)\s*</td>')){$r.Detail[$m.Groups[1].Value.Trim()]=(($m.Groups[2].Value -replace '<[^>]+>','') -replace '\s+',' ').Trim()}
 }catch{$r.Error=$_.Exception.Message}
 return $r
}
function Test-Bad($r){
 if($Class -eq 6){return ($r.Code -eq 0)}
 if($r.Code -eq 0){return $true}
 return ([math]::Floor($r.Code/100) -eq $Class)
}
function Get-Probes{
 $list=@()
 foreach($s in @($script:Model|Where-Object{$_.State -eq 'Started' -and $_.Http})){
  $base='http://127.0.0.1:'+$s.Http.Port
  $paths=@('/')+@($script:ExtraPaths)
  foreach($p in ($paths|Select-Object -Unique)){$list+=,[pscustomobject]@{Site=$s.Name;Url=$base+$p;Host=$s.Http.Host;Path=$p}}
 }
 return $list
}
function Run-Probes{
 $res=@()
 foreach($p in @(Get-Probes)){$r=Invoke-Probe $p.Url $p.Host;$r|Add-Member NoteProperty Site $p.Site;$r|Add-Member NoteProperty Path $p.Path;$res+=,$r}
 return $res
}
function Show-Probes($res){
 foreach($r in @($res)){Say ('  '+$r.Site+'  '+$r.Path+'  -> '+$(if($r.Code){[string]$r.Code+$(if($r.Sub){'.'+$r.Sub}else{''})+' '+$r.Status}else{'NO ANSWER ('+$r.Error+')'}))}
}
function Check-Fixed([string]$Step){
 Start-Sleep -Seconds 2
 try{$script:Model=@(Get-Model)}catch{}
 $res=@(Run-Probes)
 if(-not $res.Count){Say '  (no started site with an http binding to test)' Yellow;return $false}
 $bad=@($res|Where-Object{Test-Bad $_})
 if(-not $bad.Count){$script:FinalProbes=$res;Say ('  Fixed: no longer a '+$(if($Class -eq 6){'no-answer'}else{[string]$Class+'xx'})+' error after: '+$Step) Green;return $true}
 Say ('  still failing: '+(($bad|ForEach-Object{$_.Path+' -> '+$_.Code+$(if($_.Sub){'.'+$_.Sub}else{''})}) -join '; ')) Yellow
 return $false
}
function Try-Step([string]$Title,[scriptblock]$Do){
 if($script:Fixed){return}
 Say '';Say $Title Cyan
 try{
  $res=@(& $Do)
  if($res.Count -gt 0 -and $res[-1] -eq $true){if(Check-Fixed $Title){$script:Fixed=$true}}else{Say '  nothing to change here.' DarkGray}
 }catch{Say ('  step failed: '+$_.Exception.Message) Red}
}

# ---------------- evidence ----------------
$SubText=@{
 '400'='bad request (HTTP.sys or request filtering rejected it)';'401.1'='login failed';'401.2'='authentication is configured so anonymous requests are refused';'401.3'='NTFS permissions refuse the account';
 '403.1'='execute access denied (handler access policy)';'403.2'='read access denied';'403.3'='write access denied';'403.4'='SSL required but not used';'403.6'='IP address rejected (ipSecurity)';'403.14'='directory listing denied and no default document';
 '404.0'='file or folder not found';'404.3'='no MIME type for this file extension';'404.4'='no handler for this URL';'404.5'='URL sequence denied (request filtering)';'404.7'='file extension denied (request filtering)';'404.8'='hidden segment (request filtering)';'404.11'='double escaping denied';'404.14'='URL too long';'404.15'='query string too long';
 '500.0'='module/application error';'500.19'='configuration file invalid';'500.21'='module not recognized';'500.23'='integrated pipeline config error';'500.24'='impersonation error in integrated mode';'500.50'='URL Rewrite error';
 '502.2'='gateway/CGI returned an invalid response';'503'='pool stopped, disabled, queue full or worker failing';'504'='gateway timeout'}
function Explain([int]$Code,[string]$Sub){
 $k=[string]$Code+$(if($Sub){'.'+$Sub}else{''});if($SubText.ContainsKey($k)){return $SubText[$k]};if($SubText.ContainsKey([string]$Code)){return $SubText[[string]$Code]};return ''
}
function Read-Tail([string]$Path,[int]$Bytes=400000){
 $fs=New-Object IO.FileStream($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
 try{
  $head=New-Object byte[] ([int][math]::Min(8192,$fs.Length));[void]$fs.Read($head,0,$head.Length)
  $start=[math]::Max(0,$fs.Length-$Bytes);[void]$fs.Seek($start,[IO.SeekOrigin]::Begin)
  $sr=New-Object IO.StreamReader($fs);$t=$sr.ReadToEnd()
  return @(([Text.Encoding]::ASCII.GetString($head) -split "`r?`n"),($t -split "`r?`n"))
 }finally{$fs.Dispose()}
}
# IIS log: statuses of the chosen class in the last 3 hours, with sub-status / win32 status and the URLs.
function Get-LogEvidence{
 $found=@{};$uris=@{}
 if($Class -eq 6){return [pscustomobject]@{Counts=$found;Uris=@()}}
 foreach($s in @($script:Model)){
  try{
   $dirRaw=((Invoke-AppCmd list site $s.Name '/text:logFile.directory')|Out-String).Trim()
   $dir=Join-Path ([Environment]::ExpandEnvironmentVariables($dirRaw)) ('W3SVC'+$s.Id)
   $file=Get-ChildItem -LiteralPath $dir -Filter 'u_ex*.log' -ErrorAction Stop|Sort-Object LastWriteTime -Descending|Select-Object -First 1
   if(-not $file){continue}
   $parts=Read-Tail $file.FullName;$fields=@()
   foreach($l in $parts[0]){if($l -like '#Fields:*'){$fields=@($l.Substring(9).Trim() -split ' ')}}
   foreach($l in $parts[1]){if($l -like '#Fields:*'){$fields=@($l.Substring(9).Trim() -split ' ')}}
   if(-not $fields.Count){continue}
   $ix=@{};for($i=0;$i -lt $fields.Count;$i++){$ix[$fields[$i]]=$i}
   if(-not $ix.ContainsKey('sc-status')){continue}
   $cut=(Get-Date).ToUniversalTime().AddHours(-3)
   foreach($l in $parts[1]){
    if(-not $l -or $l[0] -eq '#'){continue}
    $f=$l -split ' ';if($f.Count -lt $fields.Count){continue}
    $st=0;if(-not [int]::TryParse($f[$ix['sc-status']],[ref]$st)){continue}
    if([math]::Floor($st/100) -ne $Class){continue}
    $dt=[datetime]::MinValue
    if($ix.ContainsKey('date') -and $ix.ContainsKey('time') -and [datetime]::TryParseExact($f[$ix['date']]+' '+$f[$ix['time']],'yyyy-MM-dd HH:mm:ss',$null,[Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal,[ref]$dt) -and $dt -lt $cut){continue}
    $sub=if($ix.ContainsKey('sc-substatus')){$f[$ix['sc-substatus']]}else{'0'};$w=if($ix.ContainsKey('sc-win32-status')){$f[$ix['sc-win32-status']]}else{'0'}
    $k=[string]$st+'.'+$sub+' (win32 '+$w+')';$found[$k]=1+[int]$found[$k]
    if($ix.ContainsKey('cs-uri-stem')){$u=$f[$ix['cs-uri-stem']];$uris[$u]=1+[int]$uris[$u]}
   }
  }catch{}
 }
 $top=@($uris.GetEnumerator()|Sort-Object Value -Descending|Select-Object -First 3|ForEach-Object{$_.Key})
 return [pscustomobject]@{Counts=$found;Uris=$top}
}
function Get-HttpErrEvidence{
 $c=@{}
 try{
  $f=Get-ChildItem -LiteralPath (Join-Path $env:windir 'System32\LogFiles\HTTPERR') -Filter 'httperr*.log' -ErrorAction Stop|Sort-Object LastWriteTime -Descending|Select-Object -First 1
  if($f){foreach($l in (Read-Tail $f.FullName 200000)[1]){if(-not $l -or $l[0] -eq '#'){continue};$p=$l -split ' ';if($p.Count -lt 13){continue};$st=$p[9];if($Class -eq 6 -and $st -ne '-'){continue};if($Class -ne 6 -and $st -notlike ([string]$Class+'*')){continue};$k=$st+' '+$p[11];$c[$k]=1+[int]$c[$k]}}
 }catch{}
 return $c
}
function Get-RecentEvents{
 $ids=@()
 try{
  foreach($e in @(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-WAS';StartTime=(Get-Date).AddHours(-2)} -MaxEvents 6 -ErrorAction Stop)){
   $m=(($e.Message -split "`r?`n")[0]);if($m.Length -gt 200){$m=$m.Substring(0,200)};Say ('    WAS '+$e.TimeCreated.ToString('HH:mm:ss')+' id '+$e.Id+': '+$m);$ids+=$e.Id
  }
 }catch{}
 try{
  foreach($e in @(Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2;StartTime=(Get-Date).AddHours(-2)} -MaxEvents 60 -ErrorAction Stop|Where-Object{$_.ProviderName -match '(?i)iis|asp\.net|\.net runtime|application error|w3svc|^was$'}|Select-Object -First 4)){
   $m=(($e.Message -split "`r?`n")|Select-Object -First 3) -join ' ';if($m.Length -gt 240){$m=$m.Substring(0,240)};Say ('    APP '+$e.TimeCreated.ToString('HH:mm:ss')+' '+$e.ProviderName+' id '+$e.Id+': '+$m)
  }
 }catch{}
 return $ids
}

# ---------------- undo (0) ----------------
if($Class -eq 0){
 if(-not $script:Changes.Count){Say 'No recorded changes to undo.' Yellow;return}
 $list=@($script:Changes.ToArray());[array]::Reverse($list);$fail=0
 foreach($c in $list){
  try{
   switch($c.Kind){
    'pool'{Invoke-AppCmd set apppool $c.Target ('/'+$c.Setting+':'+$c.Old)|Out-Null}
    'config'{$p=$c.Setting -split '\|';if($c.Extra){Invoke-AppCmd set config $c.Target ('/section:'+$p[0]) ('/'+$p[1]+':'+$c.Old) '/commit:apphost'|Out-Null}else{Invoke-AppCmd set config $c.Target ('/section:'+$p[0]) ('/'+$p[1]+':'+$c.Old)|Out-Null}}
    'configadd'{$i=$c.Setting.IndexOf('|');$sec=$c.Setting.Substring(0,$i);$item=$c.Setting.Substring($i+1);if($c.Extra){Invoke-AppCmd set config $c.Target ('/section:'+$sec) ('/-'+$item) '/commit:apphost'|Out-Null}else{Invoke-AppCmd set config $c.Target ('/section:'+$sec) ('/-'+$item)|Out-Null}}
    'aclsddl'{$a=Get-Acl -LiteralPath $c.Target;$a.SetSecurityDescriptorSddlForm((Get-Content -LiteralPath $c.Old -Raw).Trim(),'Access');Set-Acl -LiteralPath $c.Target -AclObject $a}
    'filesadded'{foreach($f in @(Get-Content -LiteralPath $c.Old)){if($f -and (Test-Path -LiteralPath $f)){Remove-Item -LiteralPath $f -Force}}}
    'filerenamed'{if(Test-Path -LiteralPath $c.Old){if(Test-Path -LiteralPath $c.Target){Move-Item -LiteralPath $c.Target -Destination ($c.Target+'.fixhttp-undo') -Force};Move-Item -LiteralPath $c.Old -Destination $c.Target -Force}}
    'apphost'{Copy-Item -LiteralPath $c.Old -Destination $c.Target -Force}
    'fw-created'{Remove-NetFirewallRule -Name $c.Target}
    'fw-disabled'{Enable-NetFirewallRule -Name $c.Target}
    'binding'{Invoke-AppCmd set site $c.Target ('/-bindings.[protocol=''http'',bindingInformation='''+$c.Setting+''']')|Out-Null}
    default{Say ('  '+$c.Kind+' '+$c.Target+': nothing to undo ('+$c.Setting+')') DarkGray;continue}
   }
   Say ('Undone: '+$c.Kind+' '+$c.Target+' '+$c.Setting) Green
  }catch{$fail++;Say ('Could not undo '+$c.Kind+' '+$c.Target+': '+$_.Exception.Message) Red}
 }
 if(-not $fail){Move-Item -LiteralPath $ChangeFile -Destination ($ChangeFile+'.undone-'+(Get-Date -Format 'HHmmss')) -Force}
 Say 'If Remo or gitat is active it will restore its own approved copy again; pause it first if you want the undo to stay.' DarkGray
 return
}

# ---------------- start ----------------
Say ('Fix-HttpError '+$Class+' on '+$env:COMPUTERNAME+'  '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) Cyan
Say ('Log: '+$Log) DarkGray
$script:Env=Get-FixEnv
Say ('Environment: BlueOps '+$(if(Test-Path $script:Env.Controller){'present'}else{'NOT found'})+', W3SVC lock '+$(if($script:Env.Locked){'ON (stop/restart only through BlueOps)'}else{'not detected'})+', Remo '+$(if($script:Env.Remo){'ACTIVE'}else{'no'})+', gitat '+$(if($script:Env.Gitat){'ACTIVE'}else{'no'}))

# applicationHost.config itself broken? (every IIS error follows from this)
$appHost=Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if(-not(Test-XmlFile $appHost)){
 Say '' ;Say 'applicationHost.config is not valid XML - IIS cannot read its configuration.' Red
 $cand=@()
 foreach($root in @((Join-Path $env:windir 'System32\inetsrv\backup'),(Join-Path $env:windir 'System32\inetsrv\History'))){
  if(Test-Path -LiteralPath $root){foreach($d in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue){$f=Join-Path $d.FullName 'applicationHost.config';if(Test-Path -LiteralPath $f){$cand+=Get-Item -LiteralPath $f}}}
 }
 $pick=$cand|Sort-Object LastWriteTime -Descending|Where-Object{Test-XmlFile $_.FullName}|Select-Object -First 1
 if($pick){
  Ensure-Paused
  $bad=Join-Path $Work ('applicationHost.bad-'+(Get-Date -Format 'yyyyMMdd-HHmmss'));Copy-Item -LiteralPath $appHost -Destination $bad
  try{Copy-Item -LiteralPath $pick.FullName -Destination $appHost -Force}catch{[void](Invoke-AsSystem ('Copy-Item -LiteralPath '''+$pick.FullName+''' -Destination '''+$appHost+''' -Force'))}
  Add-Change 'apphost' $appHost '' $bad '';Say ('  restored applicationHost.config from '+$pick.FullName+' (the bad file is saved as '+$bad+')') Cyan
  Start-Sleep -Seconds 3
 }else{Say '  no valid backup found in inetsrv\backup or inetsrv\History. Restore the file from the approved baseline (Remo/gitat iiscfg copy).' Red;return}
}

$script:Model=@(Get-Model)
$script:ExtraPaths=@()
Say ''
Say 'Sites and pools:'
foreach($s in $script:Model){Say ('  '+$s.Name+'  state='+$s.State+'  pool='+$s.Pool+'  folder='+$s.Path+'  bindings='+($s.Bindings -join ' '))}
Say 'Services:'
foreach($n in 'WAS','W3SVC'){$sv=Get-Service -Name $n -ErrorAction SilentlyContinue;Say ('  '+$n+': '+$(if($sv){[string]$sv.Status}else{'not installed'}))}

Say ''
Say 'Evidence:' Cyan
$ev=Get-LogEvidence
$script:ExtraPaths=@($ev.Uris|Where-Object{$_ -and $_ -ne '/'})
$res=@(Run-Probes)
$first=$null
Say '  requests now:'
Show-Probes $res
if(-not $res.Count){Say '  (no started site with an http binding, so nothing to request)'}
$bad=@($res|Where-Object{Test-Bad $_})
if($bad.Count){$first=$bad[0]}
if($first -and $first.Code){
 $why=Explain $first.Code $first.Sub;if($why){Say ('  meaning: '+$first.Code+$(if($first.Sub){'.'+$first.Sub})+' = '+$why) Yellow}
 foreach($k in 'Module','Notification','Handler','Error Code','Config Error','Config File','Requested URL','Physical Path','Logon User'){if($first.Detail.ContainsKey($k) -and $first.Detail[$k]){Say ('  '+$k+': '+$first.Detail[$k])}}
 foreach($h in 'Location','WWW-Authenticate','Server','X-Powered-By'){if($first.Headers.ContainsKey($h)){Say ('  header '+$h+': '+$first.Headers[$h])}}
}
if($ev.Counts.Count){Say ('  IIS log (last 3 h): '+(($ev.Counts.GetEnumerator()|Sort-Object Value -Descending|Select-Object -First 5|ForEach-Object{[string]$_.Value+' x '+$_.Key}) -join ' | '))}
$he=Get-HttpErrEvidence
if($he.Count){Say ('  HTTP.sys log: '+(($he.GetEnumerator()|Sort-Object Value -Descending|Select-Object -First 4|ForEach-Object{[string]$_.Value+' x '+$_.Key}) -join ' | '))}
Say '  recent events:';$ids=@(Get-RecentEvents)
if($script:ExtraPaths.Count){Say ('  also testing the URLs that failed in the log: '+($script:ExtraPaths -join ', '))}
$sub=if($first){$first.Sub}else{''}
$code=if($first){$first.Code}else{0}

if(-not $bad.Count -and $res.Count){
 Say ''
 Say ('Nothing is returning a '+$(if($Class -eq 6){'no-answer'}else{[string]$Class+'xx'})+' right now, so there is nothing to fix. Run it again with the number that matches the error you see.') Green
 $script:Fixed=$true;$script:FinalProbes=$res
}elseif(-not $res.Count -and $Class -ne 6){
 Say ''
 Say 'No started site has an http binding to test. Run .\Fix-HttpError.ps1 6 to bring the site up first.' Yellow
 $script:Fixed=$true
}

# ================= shared steps =================
function Step-Services{
 $c=$false
 $was=Get-Service -Name WAS -ErrorAction SilentlyContinue
 if($was -and $was.Status -ne 'Running'){Start-Service -Name WAS;Say '  started WAS' Cyan;$c=$true}
 $w3=Get-Service -Name W3SVC -ErrorAction SilentlyContinue
 if($w3 -and $w3.Status -ne 'Running'){[void](Invoke-W3svc 'Start');Say '  started W3SVC' Cyan;$c=$true}
 return $c
}
function Step-SitesPools{
 $c=$false
 foreach($s in $script:Model){
  if($s.Pool){$st=Get-PoolValue $s.Pool 'state';if($st -ne 'Started'){Invoke-AppCmd start apppool $s.Pool|Out-Null;Say ('  started pool '+$s.Pool) Cyan;$c=$true}}
  if($s.State -ne 'Started'){Invoke-AppCmd start site $s.Name|Out-Null;Say ('  started site '+$s.Name) Cyan;$c=$true}
 }
 return $c
}
function Step-Access{
 $c=$false;foreach($s in $script:Model){if($s.State -eq 'Started'){if(Grant-SiteAccess $s){$c=$true}}}
 try{$tmp=Join-Path $env:SystemDrive 'inetpub\temp\appPools';if(-not(Test-Path -LiteralPath $tmp)){New-Item -ItemType Directory -Path $tmp -Force|Out-Null;Say ('  created missing '+$tmp) Cyan;$c=$true}}catch{}
 if($c){foreach($s in $script:Model){if($s.Pool){try{Invoke-AppCmd recycle apppool $s.Pool|Out-Null}catch{}}}}
 return $c
}
function Step-Content{
 $c=$false
 foreach($s in $script:Model|Where-Object{$_.State -eq 'Started'}){
  if(-not $s.Path){continue}
  $files=@();if(Test-Path -LiteralPath $s.Path){$files=@(Get-ChildItem -LiteralPath $s.Path -Recurse -File -Force -ErrorAction SilentlyContinue|Select-Object -First 1)}
  $why=''
  if(-not(Test-Path -LiteralPath $s.Path)){$why='folder is missing'}elseif(-not $files.Count){$why='folder is empty'}
  elseif($code -in 404,403 -or $sub -in '14','0'){$why='files may be missing'}
  if($why){Say ('  '+$s.Name+': '+$s.Path+' - '+$why);if((Restore-Missing $s) -gt 0){$c=$true}else{Say '  no approved baseline copy found for this folder (or nothing was missing).' DarkGray}}
 }
 return $c
}
function Step-WebConfig{
 $c=$false
 foreach($s in $script:Model|Where-Object{$_.Path}){
  $f=Join-Path $s.Path 'web.config'
  if((Test-Path -LiteralPath $f) -and -not (Test-XmlFile $f)){
   Ensure-Paused;$new=$f+'.broken-'+(Get-Date -Format 'yyyyMMdd-HHmmss')
   try{Move-Item -LiteralPath $f -Destination $new}catch{[void](Invoke-AsSystem ('Move-Item -LiteralPath '''+$f+''' -Destination '''+$new+''''))}
   Add-Change 'filerenamed' $f '' $new '';Say ('  '+$f+' is not valid XML; renamed to '+$new) Cyan
   [void](Restore-Missing $s);$c=$true
  }
 }
 return $c
}
function Step-W3svcRestart{
 [void](Invoke-W3svc 'Restart');Say '  W3SVC restarted' Cyan
 foreach($s in $script:Model){if($s.Pool){try{if((Get-PoolValue $s.Pool 'state') -ne 'Started'){Invoke-AppCmd start apppool $s.Pool|Out-Null}}catch{}}}
 Start-Sleep -Seconds 4;return $true
}

# ================= class 3 =================
if($Class -eq 3 -and -not $script:Fixed){
 Try-Step '3a. Follow the redirect chain' {
  $seen=@();$cur=$first;$n=0
  while($cur -and $cur.Location -and $n -lt 8){
   $n++;Say ('  hop '+$n+': '+$cur.Code+' -> '+$cur.Location)
   if($seen -contains $cur.Location){Say '  REDIRECT LOOP' Red;break}
   $seen+=$cur.Location
   $u=$null;try{$u=[uri]$cur.Location}catch{break}
   if($u.IsAbsoluteUri -and $u.Host -notin '127.0.0.1','localhost',([string]$env:COMPUTERNAME).ToLower() -and -not ($script:Model|Where-Object{$_.Http -and $_.Http.Host -ieq $u.Host})){Say ('  the redirect sends visitors OFF this server to '+$u.Host) Red;break}
   if($u.Scheme -eq 'https' -and -not ($script:Model|Where-Object{$_.Https})){Say '  it redirects to https, but no site has an https binding' Red;break}
   $port=if($u.IsAbsoluteUri){$u.Port}else{80}
   $site=$script:Model|Where-Object{$_.Http}|Select-Object -First 1
   $next=Invoke-Probe ('http://127.0.0.1:'+$site.Http.Port+$(if($u.IsAbsoluteUri){$u.PathAndQuery}else{$cur.Location})) $site.Http.Host
   $cur=$next
  }
  return $false
 }
 Try-Step '3b. Turn off a site-level redirect (httpRedirect)' {
  $c=$false
  foreach($s in $script:Model|Where-Object{$_.State -eq 'Started'}){
   $a=Get-CfgAttrs $s.Name 'httpRedirect' 'httpRedirect'
   if($a -and $a['enabled'] -ieq 'true'){Say ('  '+$s.Name+' redirects everything to '+$a['destination']);if(Set-Cfg $s.Name 'httpRedirect' 'httpRedirect' 'enabled' 'false' 'redirect disabled'){$c=$true}}
  }
  return $c
 }
 Try-Step '3c. Turn off URL Rewrite redirect rules' {
  $c=$false
  foreach($s in $script:Model|Where-Object{$_.State -eq 'Started'}){
   $t=Get-CfgText $s.Name 'system.webServer/rewrite/rules'
   foreach($m in [regex]::Matches($t,'(?is)<rule\s+([^>]*)>(.*?)</rule>')){
    if($m.Groups[2].Value -notmatch '<action[^>]*type="Redirect"'){continue}
    if($m.Groups[1].Value -match 'enabled="false"'){continue}
    if($m.Groups[1].Value -notmatch 'name="([^"]+)"'){continue}
    $rn=$Matches[1]
    Ensure-Paused
    try{Invoke-AppCmd set config $s.Name '/section:system.webServer/rewrite/rules' ('/[name='''+$rn+'''].enabled:false')|Out-Null}catch{Invoke-AppCmd set config $s.Name '/section:system.webServer/rewrite/rules' ('/[name='''+$rn+'''].enabled:false') '/commit:apphost'|Out-Null}
    Add-Change 'config-rule' $s.Name ('rewrite rule '+$rn) 'true' 'false' '';Say ('  '+$s.Name+': disabled redirect rule '+$rn+' (turn it back on by hand in IIS Manager if it was needed)') Cyan;$c=$true
   }
  }
  return $c
 }
 Try-Step '3d. Restore missing site files' {Step-Content}
}

# ================= class 4 =================
if($Class -eq 4 -and -not $script:Fixed){
 Try-Step '4a. Site folder and files' {Step-Content}
 Try-Step '4b. Broken web.config' {Step-WebConfig}
 Try-Step '4c. Anonymous authentication (401)' {
  $c=$false
  foreach($s in $script:Model|Where-Object{$_.State -eq 'Started'}){
   $a=Get-CfgAttrs $s.Name 'anonymousAuthentication' 'anonymousAuthentication'
   if($null -eq $a){continue}
   if($a['enabled'] -ieq 'false' -and ($code -eq 401 -or $code -eq 403)){if(Set-Cfg $s.Name 'anonymousAuthentication' 'anonymousAuthentication' 'enabled' 'true' 'visitors must be allowed in anonymously'){$c=$true}}
   $u=[string]$a['userName']
   if($code -eq 401 -and $u){
    $ok=$true;try{$lu=Get-LocalUser -Name $u -ErrorAction Stop;if(-not $lu.Enabled){$ok=$false}}catch{if($_.Exception.GetType().Name -match 'UserNotFound'){$ok=$false}}
    if(-not $ok){if(Set-Cfg $s.Name 'anonymousAuthentication' 'anonymousAuthentication' 'userName' '' ('anonymous account '+$u+' is missing or disabled; using the pool identity')){$c=$true}}
   }
  }
  return $c
 }
 Try-Step '4d. Default document (403.14 / 404 on the home page)' {
  $c=$false
  foreach($s in $script:Model|Where-Object{$_.State -eq 'Started' -and $_.Path -and (Test-Path -LiteralPath $_.Path)}){
   $a=Get-CfgAttrs $s.Name 'defaultDocument' 'defaultDocument';if($null -eq $a){continue}
   if($a['enabled'] -ieq 'false'){if(Set-Cfg $s.Name 'defaultDocument' 'defaultDocument' 'enabled' 'true' 'default document must be enabled'){$c=$true}}
   $text=Get-CfgText $s.Name 'defaultDocument'
   $listed=@([regex]::Matches($text,'value="([^"]+)"')|ForEach-Object{$_.Groups[1].Value.ToLower()})
   foreach($n in 'index.html','index.htm','default.htm','default.aspx','index.aspx','default.html','index.php'){
    if((Test-Path -LiteralPath (Join-Path $s.Path $n)) -and ($listed -notcontains $n)){if(Add-CfgItem $s.Name 'defaultDocument' ('files.[value='''+$n+''']') ($n+' exists but is not a default document')){$c=$true}}
   }
  }
  return $c
 }
 Try-Step '4e. NTFS permissions on the site folder' {Step-Access}
 Try-Step '4f. Handlers and MIME types' {
  $c=$false
  foreach($s in $script:Model|Where-Object{$_.State -eq 'Started'}){
   $h=Get-CfgAttrs $s.Name 'handlers' 'handlers'
   if($h -and $h.ContainsKey('accessPolicy') -and $h['accessPolicy'] -notmatch 'Read'){if(Set-Cfg $s.Name 'handlers' 'handlers' 'accessPolicy' 'Read,Script' 'handlers need Read access'){$c=$true}}
   $ht=Get-CfgText $s.Name 'handlers'
   if($ht -and $ht -notmatch 'name="StaticFile"'){if(Add-CfgItem $s.Name 'handlers' '[name=''StaticFile'',path=''*'',verb=''GET,HEAD,POST,DEBUG'',modules=''StaticFileModule,DefaultDocumentModule,DirectoryListingModule'',resourceType=''Either'',requireAccess=''Read'']' 'the StaticFile handler was missing'){$c=$true}}
   if($sub -eq '3'){
    $mime=@{'.html'='text/html';'.htm'='text/html';'.css'='text/css';'.js'='application/javascript';'.json'='application/json';'.png'='image/png';'.jpg'='image/jpeg';'.gif'='image/gif';'.ico'='image/x-icon';'.txt'='text/plain';'.xml'='text/xml';'.svg'='image/svg+xml'}
    $mt=Get-CfgText $s.Name 'staticContent'
    foreach($ext in $mime.Keys){if($mt -and $mt -notmatch ('fileExtension="'+[regex]::Escape($ext)+'"')){if(Add-CfgItem $s.Name 'staticContent' ('[fileExtension='''+$ext+''',mimeType='''+$mime[$ext]+''']') ('no MIME type for '+$ext)){$c=$true}}}
   }
  }
  return $c
 }
 Try-Step '4g. IP restrictions (403.6) and SSL requirement (403.4)' {
  $c=$false
  foreach($s in $script:Model|Where-Object{$_.State -eq 'Started'}){
   if($sub -eq '6'){$a=Get-CfgAttrs $s.Name 'ipSecurity' 'ipSecurity';if($a -and $a['allowUnlisted'] -ieq 'false'){if(Set-Cfg $s.Name 'ipSecurity' 'ipSecurity' 'allowUnlisted' 'true' 'unlisted addresses were all being refused'){$c=$true}}}
   if($sub -eq '4' -and -not $s.Https){$a=Get-CfgAttrs $s.Name 'access' 'access';if($a -and $a['sslFlags'] -match 'Ssl'){if(Set-Cfg $s.Name 'access' 'access' 'sslFlags' 'None' 'SSL was required but the site has no https binding'){$c=$true}}}
  }
  return $c
 }
 Try-Step '4h. Request filtering limits (400 / 404.14 / 404.15)' {
  $c=$false
  foreach($s in $script:Model|Where-Object{$_.State -eq 'Started'}){
   $a=Get-CfgAttrs $s.Name 'requestFiltering' 'requestLimits';if($null -eq $a){continue}
   $lim=@{maxUrl=4096;maxQueryString=2048;maxAllowedContentLength=30000000}
   foreach($k in $lim.Keys){$v=0.0;if($a.ContainsKey($k) -and [double]::TryParse($a[$k],[ref]$v) -and $v -lt ($lim[$k]/8)){if(Set-Cfg $s.Name 'requestFiltering' 'requestLimits' $k ([string]$lim[$k]) 'limit was far too small'){$c=$true}}}
  }
  return $c
 }
}

# ================= class 5 =================
if($Class -eq 5 -and -not $script:Fixed){
 Try-Step '5a. Services' {Step-Services}
 Try-Step '5b. Broken web.config (500.19)' {Step-WebConfig}
 Try-Step '5c. Stopped sites and pools' {Step-SitesPools}
 Try-Step '5d. Missing site files' {Step-Content}
 Try-Step '5e. Recycle the pools' {
  foreach($s in $script:Model){if($s.Pool){try{Invoke-AppCmd recycle apppool $s.Pool|Out-Null;Say ('  recycled '+$s.Pool) Cyan}catch{}}}
  return $true
 }
 Try-Step '5f. Pool limits that cause 503' {
  $c=$false
  foreach($pn in @($script:Model|Where-Object{$_.Pool}|ForEach-Object{$_.Pool}|Sort-Object -Unique)){
   $lim=0;[void][int]::TryParse((Get-PoolValue $pn 'cpu.limit'),[ref]$lim);if($lim -gt 0){if(Set-PoolValue $pn 'cpu.limit' '0' 'a CPU limit can shut the pool down'){$c=$true}}
   $q=0;[void][int]::TryParse((Get-PoolValue $pn 'queueLength'),[ref]$q);if($q -lt 1000){if(Set-PoolValue $pn 'queueLength' '1000' 'a tiny queue answers 503 under load'){$c=$true}}
   if(($ids -contains 5002) -or ($ids -contains 5057)){if(Set-PoolValue $pn 'failure.rapidFailProtection' 'false' 'stops the pool being shut off after repeated failures'){$c=$true}}
   if((Get-PoolValue $pn 'autoStart') -ieq 'false'){if(Set-PoolValue $pn 'autoStart' 'true' 'pool must start by itself'){$c=$true}}
  }
  if($c){foreach($s in $script:Model){if($s.Pool){try{Invoke-AppCmd recycle apppool $s.Pool|Out-Null}catch{}}}}
  return $c
 }
 Try-Step '5g. .NET version and pipeline errors (500.0 / 500.23 / 500.24)' {
  $c=$false
  foreach($s in $script:Model|Where-Object{$_.State -eq 'Started' -and $_.Path -and (Test-Path -LiteralPath $_.Path)}){
   $rt=Get-PoolValue $s.Pool 'managedRuntimeVersion'
   $asp=@(Get-ChildItem -LiteralPath $s.Path -Recurse -Depth 3 -Include *.aspx,*.asmx,*.ashx -ErrorAction SilentlyContinue|Select-Object -First 1).Count -gt 0
   if(-not $rt -and $asp -and (Test-Path (Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319'))){if(Set-PoolValue $s.Pool 'managedRuntimeVersion' 'v4.0' 'the site has ASP.NET pages but the pool has no .NET'){$c=$true}}
   if($sub -in '23','24'){
    $v=Get-CfgAttrs $s.Name 'system.webServer/validation' 'validation'
    if($v -and $v['validateIntegratedModeConfiguration'] -ine 'false'){if(Set-Cfg $s.Name 'system.webServer/validation' 'validation' 'validateIntegratedModeConfiguration' 'false' 'old-style config in integrated mode'){$c=$true}}
    $i=Get-CfgAttrs $s.Name 'system.web/identity' 'identity'
    if($i -and $i['impersonate'] -ieq 'true'){if(Set-Cfg $s.Name 'system.web/identity' 'identity' 'impersonate' 'false' 'impersonation is not allowed in integrated mode'){$c=$true}}
   }
  }
  if($c){foreach($s in $script:Model){if($s.Pool){try{Invoke-AppCmd recycle apppool $s.Pool|Out-Null}catch{}}}}
  return $c
 }
 Try-Step '5h. Permissions on the site and IIS temp folders' {Step-Access}
 Try-Step '5i. Broken pool identity (5021 / 5059)' {
  $c=$false
  foreach($pn in @($script:Model|Where-Object{$_.Pool}|ForEach-Object{$_.Pool}|Sort-Object -Unique)){
   if((Get-PoolValue $pn 'processModel.identityType') -ine 'SpecificUser'){continue}
   $user=Get-PoolValue $pn 'processModel.userName';$pass=Get-PoolValue $pn 'processModel.password'
   Say ('  pool '+$pn+' runs as '+$user+'; trying ApplicationPoolIdentity') Yellow
   Ensure-Paused
   Invoke-AppCmd set apppool $pn '/processModel.identityType:ApplicationPoolIdentity'|Out-Null;Invoke-AppCmd recycle apppool $pn|Out-Null
   Start-Sleep -Seconds 2
   $r=Invoke-Probe ('http://127.0.0.1:'+(($script:Model|Where-Object{$_.Http}|Select-Object -First 1).Http.Port)+'/') (($script:Model|Where-Object{$_.Http}|Select-Object -First 1).Http.Host)
   if(Test-Bad $r){Invoke-AppCmd set apppool $pn '/processModel.identityType:SpecificUser' ('/processModel.userName:'+$user) ('/processModel.password:'+$pass)|Out-Null;Invoke-AppCmd recycle apppool $pn|Out-Null;Say '  no improvement; identity put back' DarkGray}
   else{Add-Change 'identity-info' $pn 'processModel.identityType' $user 'ApplicationPoolIdentity' '';Say ('  identity changed (was '+$user+'; set it again by hand if the app needs that account)') Cyan;$c=$true}
  }
  return $c
 }
 Try-Step '5j. Restart IIS through BlueOps (short outage)' {Step-W3svcRestart}
 if(-not $script:Fixed -and ($code -in 502,504 -or $sub -like '502*')){
  Say '';Say 'Gateway errors (502/504) come from what IIS forwards to. Checking:' Yellow
  foreach($s in $script:Model|Where-Object{$_.State -eq 'Started'}){
   $t=(Get-CfgText $s.Name 'system.webServer/rewrite/rules')+(Get-CfgText $s.Name 'system.webServer/fastCgi')+(Get-CfgText $s.Name 'system.webServer/proxy')
   foreach($m in [regex]::Matches($t,'(?i)(url|fullPath)="(https?://[^"]+|[A-Za-z]:\\[^"]+)"')){
    $v=$m.Groups[2].Value
    if($v -match '^https?://([^/:]+)(?::(\d+))?'){$h=$Matches[1];$p=if($Matches[2]){[int]$Matches[2]}elseif($v -like 'https*'){443}else{80};$ok=$false;try{$tc=New-Object Net.Sockets.TcpClient;$ar=$tc.BeginConnect($h,$p,$null,$null);$ok=$ar.AsyncWaitHandle.WaitOne(3000)-and $tc.Connected;$tc.Close()}catch{};Say ('  forwards to '+$v+' -> '+$(if($ok){'reachable'}else{'NOT REACHABLE - start that backend'})) $(if($ok){'Gray'}else{'Red'})}
    elseif(-not(Test-Path -LiteralPath $v)){Say ('  FastCGI program missing: '+$v) Red}
   }
  }
 }
}

# ================= class 6 =================
if($Class -eq 6 -and -not $script:Fixed){
 Try-Step '6a. Services' {Step-Services}
 Try-Step '6b. Stopped sites and pools' {Step-SitesPools}
 Try-Step '6c. Missing http binding' {
  $c=$false
  foreach($s in $script:Model){
   if(-not $s.Http -and -not $s.Https){
    $taken=@($script:Model|Where-Object{$_.Http -and $_.Http.Port -eq 80}).Count
    if(-not $taken){Ensure-Paused;Invoke-AppCmd set site $s.Name '/+bindings.[protocol=''http'',bindingInformation=''*:80:'']'|Out-Null;Add-Change 'binding' $s.Name '*:80:' '' '';Say ('  '+$s.Name+' had no bindings; added http *:80') Cyan;$c=$true}
   }
  }
  if($c){$script:Model=@(Get-Model)}
  return $c
 }
 Try-Step '6d. Port used by something else' {
  foreach($s in $script:Model|Where-Object{$_.Http}){
   try{foreach($l in @(Get-NetTCPConnection -State Listen -LocalPort $s.Http.Port -ErrorAction Stop)){
    if($l.OwningProcess -ne 4){$p=Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue;Say ('  PORT '+$s.Http.Port+' is held by '+$(if($p){$p.ProcessName+' (PID '+$p.Id+') '+$p.Path}else{'PID '+$l.OwningProcess})+' - not IIS. Stop it by hand if it is not yours.') Red}
   }}catch{}
  }
  return $false
 }
 Try-Step '6e. Firewall' {
  $c=$false
  $ports=@($script:Model|Where-Object{$_.Http}|ForEach-Object{$_.Http.Port}|Sort-Object -Unique)
  $on=@(Get-NetFirewallProfile -ErrorAction SilentlyContinue|Where-Object{$_.Enabled -eq 'True'}).Count -gt 0
  if(-not $on){Say '  firewall is off' DarkGray;return $false}
  $rules=@(Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction Stop)
  $pf=@{};foreach($f in Get-NetFirewallPortFilter -ErrorAction SilentlyContinue){$pf[$f.InstanceID]=$f}
  $af=@{};foreach($f in Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue){$af[$f.InstanceID]=$f}
  function PortHit($lp,[int]$port){foreach($x in @($lp)){$t=[string]$x;if($t -eq 'Any'){return $true};if($t -match '^(\d+)-(\d+)$'){if($port -ge [int]$Matches[1] -and $port -le [int]$Matches[2]){return $true}}elseif($t -eq [string]$port){return $true}};return $false}
  foreach($port in $ports){
   $allow=$false
   foreach($r in $rules){
    $f=$pf[$r.InstanceID];if(-not $f){continue}
    if($f.Protocol -notin 'TCP','Any'){continue}
    if(-not (PortHit $f.LocalPort $port)){continue}
    if($f.LocalPort -eq 'Any' -and $f.Protocol -eq 'Any'){continue}
    $remote=@($af[$r.InstanceID].RemoteAddress)
    if($r.Action -eq 'Block' -and ($remote -contains 'Any')){
     Ensure-Paused;Disable-NetFirewallRule -Name $r.Name;Add-Change 'fw-disabled' $r.Name '' '' '';Say ('  disabled firewall rule that blocks port '+$port+' for everyone: '+$r.DisplayName) Cyan;$c=$true
    }elseif($r.Action -eq 'Allow'){$allow=$true}
   }
   if(-not $allow){
    Ensure-Paused;$n='Fix-HttpError allow web '+$port
    New-NetFirewallRule -Name $n -DisplayName $n -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any|Out-Null
    Add-Change 'fw-created' $n '' '' '';Say ('  no firewall rule allowed TCP '+$port+'; created one') Cyan;$c=$true
   }
  }
  return $c
 }
 Try-Step '6f. HTTP.sys IP listen list and https certificates' {
  try{$t=((& netsh.exe http show iplisten 2>&1)|Out-String);if($t -match '\d+\.\d+\.\d+\.\d+' -and $t -notmatch '0\.0\.0\.0'){Say '  HTTP.sys only listens on specific addresses (netsh http show iplisten); add 0.0.0.0 and reboot to listen everywhere:  netsh http add iplisten ipaddress=0.0.0.0' Yellow}}catch{}
  foreach($s in $script:Model|Where-Object{$_.Https}){try{$t=((& netsh.exe http show sslcert 2>&1)|Out-String);if($t -notmatch 'Certificate Hash'){Say ('  '+$s.Name+' has an https binding but no certificate is bound (netsh http show sslcert is empty). Bind one in IIS Manager.') Yellow}}catch{}}
  return $false
 }
 Try-Step '6g. Restart IIS through BlueOps (short outage)' {Step-W3svcRestart}
}

# ---------------- stability and result ----------------
Say ''
$script:Model=@(Get-Model)
$pools=@($script:Model|Where-Object{$_.Pool}|ForEach-Object{$_.Pool}|Sort-Object -Unique)
if($pools.Count -and $script:Mutated){
 Say 'Stability watch (15 seconds):'
 $last=@{};$flips=0
 for($i=0;$i -lt 15;$i++){
  foreach($pn in $pools){try{$st=Get-PoolValue $pn 'state'}catch{$st='?'};if($last.ContainsKey($pn) -and $last[$pn] -ne $st){$flips++;Say ('  '+(Get-Date -Format 'HH:mm:ss')+' pool '+$pn+' changed '+$last[$pn]+' -> '+$st) Red};$last[$pn]=$st}
  Start-Sleep -Seconds 1
 }
 if($flips){Say '  a pool changed state: something is stopping or crashing it. Look for a scheduled task or script that stops IIS.' Red}else{Say '  pools stayed up.' Green}
}
Say ''
$final=@(Run-Probes)
if($final.Count){Show-Probes $final}
$still=@($final|Where-Object{Test-Bad $_})
if($final.Count -and -not $still.Count){
 $worst=@($final|Where-Object{$_.Code -ge 300}|Select-Object -First 1)
 if($worst.Count){Say ('RESULT: the '+$(if($Class -eq 6){'no-answer'}else{[string]$Class+'xx'})+' error is gone, but the site now returns '+$worst[0].Code+$(if($worst[0].Sub){'.'+$worst[0].Sub})+' - run .\Fix-HttpError.ps1 '+[math]::Floor($worst[0].Code/100)+' next.') Yellow}
 else{Say 'RESULT: FIXED. The site answers normally.' Green}
}elseif($final.Count){
 Say ('RESULT: NOT FIXED. Still '+(($still|ForEach-Object{[string]$_.Code+$(if($_.Sub){'.'+$_.Sub})}|Select-Object -Unique) -join ', ')+'. Send me the log: the lines under "Evidence" name the cause.') Red
}else{Say 'RESULT: no started site with an http binding was available to test.' Yellow}
Say ('Changes made: '+$script:Changes.Count+$(if($script:Changes.Count){'   (undo: .\Fix-HttpError.ps1 0)'}))
if($script:PausedBy.Count){
 Say ('NOTE: '+($script:PausedBy -join ' + ')+' is still PAUSED. When it resumes it restores its approved copy, which is the version from BEFORE this fix, so it will undo config/file/ACL changes. Resume only after you have decided that is what you want:') Yellow
 if($script:PausedBy -contains 'Remo'){Say ('   '+$script:Env.RemoScript+' -Action Resume') Yellow}
 if($script:PausedBy -contains 'gitat'){Say '   Remove-Item C:\ProgramData\IISCache\paused' Yellow}
}
Say ('Log: '+$Log) DarkGray
