#Requires -Version 5.1
<#
Fix-WrongContent.ps1 - the scoring check says the website is DOWN with "response did not contain expected content". This finds why
and fixes it. Run elevated in 64-bit Windows PowerShell 5.1, no arguments:   .\Fix-WrongContent.ps1
It works out what the home page SHOULD say from the approved backup (the Remo/gitat baseline), fetches the real page from several
addresses (the health URL, 127.0.0.1, this server's IPs) and compares. Then, one fix at a time, re-testing after each:
  1 Remo/gitat paused or stopped -> resume it                       2 site files changed/missing -> put back from the backup (bad copy kept)
  3 NEW files not in the backup (fake home page etc.) -> moved aside   4 IIS serving a different folder than the protected one -> pointed back
  5 site / app pool stopped -> started; ANOTHER site on the same binding -> stopped        6 default document turned off -> turned on
  7 recycle the app pool (drops cached pages)
Nothing is deleted: every file it replaces or moves is kept in C:\BlueLogs\FixContent\<time>. It stops as soon as every address
returns the right page. It does not pause Remo (it only moves things toward the backup, which Remo agrees with).
Log: C:\BlueLogs\fixcontent_<host>_<time>.txt    Moved files + undo notes: C:\BlueLogs\FixContent\<time>
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 as Administrator.'}
if(-not(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Open Windows PowerShell as Administrator.'}
$AppCmd=Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
if(-not(Test-Path -LiteralPath $AppCmd)){throw 'IIS is not installed (appcmd.exe not found).'}
$PD=[string]$env:ProgramData;if(-not $PD){$PD='C:\ProgramData'}
$Stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$LogDir='C:\BlueLogs';$Quar=Join-Path $LogDir ('FixContent\'+$Stamp)
New-Item -ItemType Directory -Path $Quar -Force|Out-Null
$Log=Join-Path $LogDir ('fixcontent_'+$env:COMPUTERNAME+'_'+$Stamp+'.txt')
$script:Undo=New-Object System.Collections.ArrayList
$script:Fixed=$false

function Say([string]$Text,[string]$Color='Gray'){Write-Host $Text -ForegroundColor $Color;try{Add-Content -LiteralPath $Log -Value $Text}catch{}}
function Read-J([string]$p){try{if(Test-Path -LiteralPath $p){return (Get-Content -LiteralPath $p -Raw -ErrorAction Stop|ConvertFrom-Json)}}catch{};return $null}
function Hash-Of([string]$p){try{return (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash}catch{return ''}}
function Note-Undo([string]$t){[void]$script:Undo.Add($t);try{Add-Content -LiteralPath (Join-Path $Quar 'UNDO.txt') -Value $t}catch{}}
function Invoke-AppCmd{$o=@(& $AppCmd @args 2>&1);if($LASTEXITCODE -ne 0){throw ('appcmd '+($args -join ' ')+' failed: '+(($o|Out-String).Trim()))};return $o}
function Invoke-AsSystem([string]$Code){
 $id=[guid]::NewGuid().ToString('N');$dir=Join-Path $PD ('FixContent-'+$id);$name='FixContent-'+$id
 New-Item -ItemType Directory -Path $dir -Force|Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)');Set-Acl -LiteralPath $dir -AclObject $acl
 $run=Join-Path $dir 'run.ps1';$out=Join-Path $dir 'out.txt';$done=Join-Path $dir 'done'
 Set-Content -LiteralPath $run -Encoding UTF8 -Value ('$ErrorActionPreference=''Continue'';& { '+$Code+' } *>&1 | Out-File -LiteralPath '''+$out+''' -Encoding UTF8;''x'' | Set-Content -LiteralPath '''+$done+'''')
 try{
  $act=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$run+'"')
  Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $act -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)) -User SYSTEM -RunLevel Highest|Out-Null
  Start-ScheduledTask -TaskName $name -TaskPath '\'
  $until=(Get-Date).AddSeconds(90)
  while(-not(Test-Path -LiteralPath $done) -and (Get-Date) -lt $until){
   Start-Sleep -Milliseconds 500
   $t=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
   if($t -and $t.State -eq 'Disabled'){try{Enable-ScheduledTask -TaskName $name -TaskPath '\'|Out-Null;Start-ScheduledTask -TaskName $name -TaskPath '\'}catch{}}
  }
  if(Test-Path -LiteralPath $out){return (Get-Content -LiteralPath $out -Raw)};return ''
 }finally{try{Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false -ErrorAction SilentlyContinue}catch{};try{Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue}catch{}}
}
function Run-AppCmd([string[]]$A){
 try{[void](Invoke-AppCmd @A);return $true}catch{
  Say ('   admin was refused ('+$_.Exception.Message.Split("`n")[0]+') - retrying as SYSTEM') 'Yellow'
  $code='& "'+$AppCmd+'" '+(($A|ForEach-Object{'"'+($_ -replace '"','\"')+'"'}) -join ' ')+'; ''exit=''+$LASTEXITCODE'
  $o=Invoke-AsSystem $code;if($o -match 'exit=0'){return $true};Say ('   SYSTEM attempt output: '+($o -replace '\s+',' ')) 'Red';return $false}
}

# ---------------- what is protected / what is right ----------------
$remo=Read-J (Join-Path $PD 'Remo\deployment.json');$Mode='none';$Store=''
if($remo -and $remo.State -eq 'Active'){$Mode='Remo';$Store=[string]$remo.Store}
elseif(Test-Path -LiteralPath (Join-Path $PD 'IISCache\settings.json')){$Mode='gitat';$Store=Join-Path $PD 'IISCache'}
if($Mode -eq 'none'){throw 'Neither Remo nor gitat is installed, so there is no approved backup to compare with. Install Remo first (.\Remo.ps1 -IgnoreHealth).'}
$cfg=Read-J (Join-Path $Store 'settings.json');if(-not $cfg){throw ('Cannot read '+(Join-Path $Store 'settings.json'))}
$expectedText=[string]$cfg.ExpectedText;$healthUrl=[string]$cfg.HealthUrl;$siteName=[string]$cfg.SiteName
$webTargets=@($cfg.Targets|Where-Object{-not $_.IsConfig})
function Norm([string]$s){return (($s -replace '<script[\s\S]*?</script>','' -replace '<style[\s\S]*?</style>','' -replace '<[^>]+>',' ' -replace '&nbsp;',' ' -replace '\s+',' ').Trim())}
function Get-DefaultDocs{try{$t=((Invoke-AppCmd list config $siteName '/section:defaultDocument')|Out-String);return @([regex]::Matches($t,'<add value="([^"]+)"')|ForEach-Object{$_.Groups[1].Value})}catch{return @()}}
function Find-GoodPage{
 $docs=Get-DefaultDocs;$homes=@()
 foreach($t in $webTargets){foreach($f in @($t.Files)){$p=[string]$f.Path;if($p -match '^(index|default|home)\.(html?|aspx?|php)$'){$bp=Join-Path ([string]$t.Repo) $p;if(Test-Path -LiteralPath $bp -PathType Leaf){$homes+=[pscustomobject]@{Rel=$p;Path=$bp;Order=$(if($docs -contains $p){[array]::IndexOf($docs,$p)}else{99})}}}}}
 if(-not $homes.Count){return $null};return ($homes|Sort-Object Order|Select-Object -First 1)
}
$good=Find-GoodPage;$needle='';$title=''
if($good){
 $gt=Get-Content -LiteralPath $good.Path -Raw -ErrorAction SilentlyContinue
 if($gt -match '(?is)<title[^>]*>(.*?)</title>'){$title=(Norm $Matches[1])}
 $nt=Norm $gt;if($title){$needle=$title}elseif($nt.Length -gt 0){$needle=$nt.Substring(0,[math]::Min(70,$nt.Length))}
}
function Get-Page([string]$Url){
 $o=[pscustomobject]@{Url=$Url;Code=0;Body='';Error=''}
 try{$q=[Net.HttpWebRequest]::Create($Url);$q.Timeout=10000;$q.KeepAlive=$false;$q.AllowAutoRedirect=$true;$q.UserAgent='Fix-WrongContent';$r=$null
  try{$r=$q.GetResponse()}catch [Net.WebException]{$r=$_.Exception.Response;if(-not $r){$o.Error=$_.Exception.Message}}
  if($r){$o.Code=[int]$r.StatusCode;$sr=New-Object IO.StreamReader($r.GetResponseStream());$o.Body=$sr.ReadToEnd();$sr.Close();$r.Close()}}catch{$o.Error=$_.Exception.Message}
 return $o
}
function Content-Ok($p){
 if($p.Code -lt 200 -or $p.Code -ge 400){return $false}
 if($expectedText -and -not $p.Body.Contains($expectedText)){return $false}
 if($needle -and ((Norm $p.Body).IndexOf($needle,[StringComparison]::OrdinalIgnoreCase) -lt 0)){return $false}
 return $true
}
function Get-Urls{
 $u=New-Object System.Collections.ArrayList;[void]$u.Add($healthUrl);if(-not $u.Contains('http://127.0.0.1/')){[void]$u.Add('http://127.0.0.1/')}
 try{foreach($a in [Net.Dns]::GetHostAddresses([string]$env:COMPUTERNAME)){if($a.AddressFamily -eq 'InterNetwork' -and -not $a.ToString().StartsWith('169.254') -and -not $a.ToString().StartsWith('127.')){$x='http://'+$a.ToString()+'/';if(-not $u.Contains($x)){[void]$u.Add($x)}}}}catch{}
 return @($u.ToArray())
}
function Test-All([bool]$Show=$true){
 $bad=@();foreach($u in (Get-Urls)){
  $p=Get-Page $u;$ok=Content-Ok $p
  if($Show){Say ('   '+$u.PadRight(34)+' '+$(if($p.Code){[string]$p.Code}else{'no answer'}).PadRight(10)+' '+$(if($ok){'RIGHT PAGE'}elseif($p.Code -ge 200 -and $p.Code -lt 400){'WRONG CONTENT'}else{'ERROR '+$p.Error})) $(if($ok){'Green'}else{'Red'})}
  if(-not $ok){$bad+=$u}}
 return $bad
}
function Check-Fixed([string]$Step){
 Start-Sleep -Seconds 2;Say ('   re-testing after: '+$Step)
 $bad=@(Test-All $true)
 if(-not $bad.Count){$script:Fixed=$true;Say '   >>> every address now returns the right page.' 'Green'}
}
function Try-Step([string]$Title,[scriptblock]$Do){
 if($script:Fixed){return}
 Say '' ;Say ('--- '+$Title) 'Cyan'
 try{& $Do}catch{Say ('   step failed: '+$_.Exception.Message) 'Yellow'}
}

# ---------------- start ----------------
Say ('Fix-WrongContent on '+$env:COMPUTERNAME+'  '+(Get-Date)) 'White'
Say ('Protection in use : '+$Mode+'   site: '+$siteName+'   health URL: '+$healthUrl)
if($good){Say ('Right page comes from the approved backup: '+$good.Rel+'   (must contain: "'+$needle+'"'+$(if($expectedText){'  and  "'+$expectedText+'"'})+')')}
else{Say ('No home page (index/default) found in the backup, so the content check uses only the expected text ('+$(if($expectedText){'"'+$expectedText+'"'}else{'none set'})+') and the status code.') 'Yellow'}
Say '' ;Say '== Where things stand ==' 'Cyan'
$bad0=@(Test-All $true)
if(-not $bad0.Count){Say '' ;Say 'All addresses already return the right page. If the scoreboard still shows DOWN, the scoring engine must be asking for something different (another host name, port, https or path). Check its URL in the scoring page and request that URL.' 'Green';$script:Fixed=$true}

Try-Step '1. Is the backup guard running?' {
 if($Mode -eq 'Remo'){
  $w=Get-ScheduledTask -TaskName ([string]$remo.WorkerTask) -TaskPath '\' -ErrorAction SilentlyContinue
  $paused=[bool]$remo.Paused -or (Test-Path -LiteralPath (Join-Path $Store 'paused'))
  Say ('   Remo paused: '+$paused+'   worker: '+$(if($w){if($w.Settings.Enabled){[string]$w.State}else{'Disabled'}}else{'Missing'}))
  if($paused){Say '   resuming Remo' 'Yellow';& $remo.Supervisor -Action Resume 2>&1|ForEach-Object{Say ('   '+$_)}}
  elseif($w -and ($w.State -ne 'Running' -or -not $w.Settings.Enabled)){Say '   starting the Remo worker' 'Yellow';Enable-ScheduledTask -TaskName ([string]$remo.WorkerTask) -TaskPath '\'|Out-Null;Start-ScheduledTask -TaskName ([string]$remo.WorkerTask) -TaskPath '\'}
  else{Say '   Remo is running.' 'Green';return}
 }else{
  $m=Join-Path $Store 'paused';$w=Get-ScheduledTask -TaskName gitat -TaskPath '\' -ErrorAction SilentlyContinue
  if(Test-Path -LiteralPath $m){Say '   gitat is paused - removing the pause marker' 'Yellow';Remove-Item -LiteralPath $m -Force}
  if($w -and ($w.State -ne 'Running' -or -not $w.Settings.Enabled)){Say '   starting gitat' 'Yellow';Enable-ScheduledTask -TaskName gitat -TaskPath '\'|Out-Null;Start-ScheduledTask -TaskName gitat -TaskPath '\'}
  else{Say '   gitat is running.' 'Green';return}
 }
 Start-Sleep -Seconds 15;Check-Fixed 'resuming the backup guard'
}

function Get-FileDiff{
 $res=@()
 foreach($t in $webTargets){
  $root=[string]$t.Root;$known=@{};$chg=@();$new=@()
  foreach($f in @($t.Files)){$known[[string]$f.Path]=$true;$p=Join-Path $root ([string]$f.Path);if(-not(Test-Path -LiteralPath $p -PathType Leaf)){$chg+=[pscustomobject]@{Rel=[string]$f.Path;Hash=[string]$f.Hash;Why='missing'}}elseif((Hash-Of $p) -ine [string]$f.Hash){$chg+=[pscustomobject]@{Rel=[string]$f.Path;Hash=[string]$f.Hash;Why='changed'}}}
  $ex=@($cfg.Exclude|ForEach-Object{([string]$_).Replace('\','/').Trim('/')})
  if(Test-Path -LiteralPath $root){foreach($i in Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue){
   if($i.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
   $rel=$i.FullName.Substring($root.TrimEnd('\').Length+1).Replace('\','/');$skip=$false
   foreach($e in $ex){if($rel -ieq $e -or $rel.StartsWith($e+'/',[StringComparison]::OrdinalIgnoreCase)){$skip=$true}}
   if(-not $skip -and -not $known.ContainsKey($rel)){$new+=$rel}}}
  $res+=[pscustomobject]@{Target=$t;Root=$root;Changed=$chg;New=$new}
 }
 return $res
}
Try-Step '2. Site files vs the approved backup' {
 $d=@(Get-FileDiff);$n=0;foreach($x in $d){$n+=$x.Changed.Count}
 Say ('   changed or missing files: '+$n)
 if($n){Say '   giving Remo/gitat up to 25 s to put them back by itself...';$t0=Get-Date;while(((Get-Date)-$t0).TotalSeconds -lt 25){Start-Sleep -Seconds 3;$d=@(Get-FileDiff);$n=0;foreach($x in $d){$n+=$x.Changed.Count};if(-not $n){break}}}
 if(-not $n){Say '   all backed-up files match the backup.' 'Green';return}
 foreach($x in $d){foreach($c in $x.Changed){
  $live=Join-Path $x.Root $c.Rel;$src=Join-Path ([string]$x.Target.Repo) $c.Rel
  if((Hash-Of $src) -ine $c.Hash){Say ('   cannot restore '+$c.Rel+': the backup copy itself does not match its recorded hash') 'Red';continue}
  if(Test-Path -LiteralPath $live){$keep=Join-Path $Quar ('changed\'+$c.Rel);New-Item -ItemType Directory -Path (Split-Path $keep) -Force|Out-Null;Move-Item -LiteralPath $live -Destination $keep -Force;Say ('   '+$c.Why.ToUpper()+' '+$c.Rel+' - bad copy kept in '+$keep) 'Yellow'}
  else{Say ('   MISSING '+$c.Rel) 'Yellow'}
  New-Item -ItemType Directory -Path (Split-Path $live) -Force|Out-Null
  Copy-Item -LiteralPath $src -Destination $live -Force
  if((Hash-Of $live) -ieq $c.Hash){Say ('   restored '+$c.Rel+' from the backup') 'Green'}else{Say ('   restored copy of '+$c.Rel+' does not verify') 'Red'}
 }}
 Check-Fixed 'restoring changed/missing files'
}
Try-Step '3. New files that are not in the backup' {
 $d=@(Get-FileDiff);$cnt=0;foreach($x in $d){$cnt+=$x.New.Count}
 Say ('   new files: '+$cnt)
 if(-not $cnt){Say '   none.' 'Green';return}
 foreach($x in $d){foreach($rel in $x.New){
  $live=Join-Path $x.Root $rel;$keep=Join-Path $Quar ('new\'+$rel)
  New-Item -ItemType Directory -Path (Split-Path $keep) -Force|Out-Null
  try{Move-Item -LiteralPath $live -Destination $keep -Force;Say ('   moved aside NEW file '+$rel+' -> '+$keep) 'Yellow';Note-Undo ('Move-Item "'+$keep+'" "'+$live+'"   # puts back '+$rel)}catch{Say ('   could not move '+$rel+': '+$_.Exception.Message) 'Red'}
 }}
 Check-Fixed 'moving new files aside'
}
Try-Step '4. Which folder does IIS serve?' {
 $vd=@{};foreach($l in @(Invoke-AppCmd list vdir)){if("$l" -match '^VDIR "(?<n>[^"]+)" \(physicalPath:(?<p>.+)\)\s*$'){$vd[$Matches.n]=$Matches.p}}
 $key=$siteName+'/';$served=$vd[$key]
 if(-not $served){Say ('   could not find the root folder entry for site "'+$siteName+'".') 'Yellow';return}
 $servedX=[Environment]::ExpandEnvironmentVariables($served);$want=[string]$webTargets[0].Root
 Say ('   IIS serves: '+$servedX);Say ('   protected : '+$want)
 if($servedX.TrimEnd('\') -ieq $want.TrimEnd('\')){Say '   same folder.' 'Green';return}
 Say '   DIFFERENT - pointing IIS back to the protected folder' 'Yellow'
 if(Run-AppCmd @('set','vdir',$key,('/physicalPath:'+$want))){Note-Undo ('& "'+$AppCmd+'" set vdir "'+$key+'" /physicalPath:"'+$served+'"   # was serving this folder');Say '   done' 'Green'}
 Check-Fixed 'pointing IIS at the protected folder'
}
Try-Step '5. Site, app pool and other sites on the same binding' {
 $sites=@(Invoke-AppCmd list site|ForEach-Object{[string]$_});$mine=$null;$others=@()
 foreach($l in $sites){if($l -match '^SITE "(?<n>[^"]+)" \(id:(?<id>\d+),bindings:(?<b>.*),state:(?<s>\w+)\)'){$o=[pscustomobject]@{Name=$Matches.n;Bind=$Matches.b;State=$Matches.s};if($o.Name -eq $siteName){$mine=$o}else{$others+=$o}}}
 if(-not $mine){Say ('   site "'+$siteName+'" not found!') 'Red';return}
 Say ('   '+$mine.Name+' : '+$mine.State+'   '+$mine.Bind)
 if($mine.State -ne 'Started'){Say '   starting the site' 'Yellow';[void](Run-AppCmd @('start','site',$siteName));Note-Undo ('(site '+$siteName+' was Stopped before this script started it)')}
 foreach($p in @($cfg.Pools)){$ps=((Invoke-AppCmd list apppool $p '/text:state')|Out-String).Trim();Say ('   pool '+$p+' : '+$ps);if($ps -ne 'Started'){Say '   starting the pool' 'Yellow';[void](Run-AppCmd @('start','apppool',$p))}}
 $myb=@($mine.Bind -split ',');foreach($o in $others){if($o.State -ne 'Started'){continue};$shared=@($o.Bind -split ','|Where-Object{$myb -contains $_});if($shared.Count){Say ('   ANOTHER site "'+$o.Name+'" is Started on the same binding '+($shared -join ',')+' - stopping it') 'Yellow';if(Run-AppCmd @('stop','site',$o.Name)){Note-Undo ('& "'+$AppCmd+'" start site "'+$o.Name+'"   # was stopped because it shared the binding '+($shared -join ','))}}}
 Check-Fixed 'site/pool/binding changes'
}
Try-Step '6. Default document' {
 $t=((Invoke-AppCmd list config $siteName '/section:defaultDocument')|Out-String)
 $docs=Get-DefaultDocs;Say ('   default documents, in order: '+($docs -join ', '))
 if($t -match 'enabled="false"'){Say '   default documents are switched OFF - turning them on' 'Yellow';if(Run-AppCmd @('set','config',$siteName,'/section:defaultDocument','/enabled:true','/commit:apphost')){Note-Undo ('& "'+$AppCmd+'" set config "'+$siteName+'" /section:defaultDocument /enabled:false /commit:apphost')};Check-Fixed 'enabling default documents'}
 else{Say '   enabled.' 'Green'}
 if($good -and $docs.Count -and ($docs -notcontains $good.Rel)){Say ('   note: the backup home page ('+$good.Rel+') is not in the default document list.') 'Yellow'}
}
Try-Step '7. Recycle the app pool (clears cached pages)' {
 foreach($p in @($cfg.Pools)){[void](Run-AppCmd @('recycle','apppool',$p));Say ('   recycled '+$p)}
 Start-Sleep -Seconds 4;Check-Fixed 'recycling the app pool'
}

# ---------------- verdict ----------------
Say '' ;Say '== Result ==' 'Cyan'
if($script:Fixed){Say 'FIXED - every address returns the right page. Check the scoreboard on its next round.' 'Green'}
else{
 Say 'NOT FIXED. Current state of each address:' 'Red';[void](Test-All $true)
 Say '' ;Say 'What this means:' 'White'
 Say '  - If 127.0.0.1 is right but the server IP or health URL is wrong: a binding / host header / firewall issue, not the files. Run  .\Fix-HttpError.ps1 6  or  .\Remo-Why.ps1.' 'Gray'
 Say '  - If every address returns the same wrong page and the files match the backup: the backup itself may hold the wrong page, or the page comes from outside the files (a rewrite/redirect or reverse-proxy rule). Run  .\Fix-HttpError.ps1 3  and  .\Fix-HttpError.ps1 4.' 'Gray'
 Say '  - The scoring engine may be asking for a different URL/host/port than the ones tested here.' 'Gray'
}
if($script:Undo.Count){Say '' ;Say ('Undo notes (also in '+(Join-Path $Quar 'UNDO.txt')+'):') 'White';foreach($u in $script:Undo){Say ('  '+$u) 'Gray'}}
Say '' ;Say ('Log: '+$Log+'     Files moved aside: '+$Quar)
