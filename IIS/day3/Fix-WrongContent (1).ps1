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
$script:Fixed=$false;$script:HasHome=$false

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
$remoWeb=@($cfg.Targets|Where-Object{-not $_.IsConfig})
# The truth is the INITIAL gitat approval (IISCache\settings.json) when it exists for the same site folder; otherwise Remo's own baseline.
$ref=$cfg;$RefName=$Mode+' baseline';$gitatCfg=Read-J (Join-Path $PD 'IISCache\settings.json');$RefDiffs=@()
if($gitatCfg -and @($gitatCfg.Targets|Where-Object{-not $_.IsConfig}).Count -and $remoWeb.Count){
 $gw=@($gitatCfg.Targets|Where-Object{-not $_.IsConfig})
 if(([string]$gw[0].Root).TrimEnd('\') -ieq ([string]$remoWeb[0].Root).TrimEnd('\')){
  $ref=$gitatCfg;$RefName='initial gitat approval (IISCache)'
  if(-not $expectedText -and [string]$gitatCfg.ExpectedText){$expectedText=[string]$gitatCfg.ExpectedText}
  $rh=@{};foreach($f in @($remoWeb[0].Files)){$rh[[string]$f.Path]=[string]$f.Hash}
  $gh=@{};foreach($f in @($gw[0].Files)){$gh[[string]$f.Path]=[string]$f.Hash}
  foreach($k in $gh.Keys){if(-not $rh.ContainsKey($k) -or $rh[$k] -ine $gh[$k]){$RefDiffs+=$k}}
  foreach($k in $rh.Keys){if(-not $gh.ContainsKey($k)){$RefDiffs+=$k}}
 }
}
$webTargets=@($ref.Targets|Where-Object{-not $_.IsConfig})
function Norm([string]$s){return (($s -replace '<script[\s\S]*?</script>','' -replace '<style[\s\S]*?</style>','' -replace '<[^>]+>',' ' -replace '&nbsp;',' ' -replace '\s+',' ').Trim())}
function Get-DefaultDocs{try{$t=((Invoke-AppCmd list config $siteName '/section:defaultDocument')|Out-String);return @([regex]::Matches($t,'<add value="([^"]+)"')|ForEach-Object{$_.Groups[1].Value})}catch{return @()}}
function Find-GoodPage{
 $docs=Get-DefaultDocs;$homes=@()
 foreach($t in $webTargets){foreach($f in @($t.Files)){$p=[string]$f.Path
  if($p -match '(^|/)(index|default|home)\.(html?|aspx?|php)$'){
   $leaf=Split-Path $p -Leaf;$depth=@($p -split '/').Count;$wr=$(if($p -match '(^|/)wwwroot/[^/]+$'){0}else{1})
   $homes+=[pscustomobject]@{Rel=$p;Target=$t;Hash=[string]$f.Hash;Order=$(if($docs -contains $leaf){[array]::IndexOf($docs,$leaf)}else{99});Wr=$wr;Depth=$depth}}}}
 if(-not $homes.Count){return $null}
 $script:HasHome=$true
 foreach($h in ($homes|Sort-Object Wr,Order,Depth)){
  $path=Get-BackupFile $h.Target $h.Rel $h.Hash
  if(-not $path){$path=Find-RealFile $h.Target $h.Rel $h.Hash}
  if($path){return [pscustomobject]@{Rel=$h.Rel;Path=$path}}
 }
 return $null
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
 if($script:HasHome -and $p.Body -match '(?i)<title>\s*(IIS Windows Server|IIS7|IIS8|Internet Information Services)'){return $false}
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
 $left=0;foreach($x in @(Get-FileDiff)){$left+=$x.Changed.Count+$x.New.Count}
 if($left){Say ('   ('+$left+' protected file(s) still differ from the approved copy)') 'Yellow'}
 if(-not $bad.Count -and -not $left){$script:Fixed=$true;Say '   >>> every address returns the right page and every file matches the approved copy.' 'Green'}
}
function Try-Step([string]$Title,[scriptblock]$Do){
 if($script:Fixed){return}
 Say '' ;Say ('--- '+$Title) 'Cyan'
 try{& $Do}catch{Say ('   step failed: '+$_.Exception.Message) 'Yellow'}
}

$script:SrcCache=@{}
function Get-SourceDirs([string]$Id,[string]$Primary){
 if($script:SrcCache.ContainsKey($Id)){return $script:SrcCache[$Id]}
 $l=New-Object System.Collections.ArrayList
 function Add-Dir([string]$d){if($d -and (Test-Path -LiteralPath $d -PathType Container) -and -not $l.Contains($d)){[void]$l.Add($d)}}
 Add-Dir $Primary
 foreach($c in @($gitatCfg,$cfg)){if($c){foreach($t in @($c.Targets)){if([string]$t.Id -eq $Id){Add-Dir ([string]$t.Repo)}}}}
 foreach($base in @((Join-Path $PD 'IISCache\baselines'),(Join-Path $PD 'watchdogs\baselines'))){foreach($g in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)){Add-Dir (Join-Path $g.FullName $Id)}}
 foreach($g in @(Get-ChildItem -LiteralPath $PD -Directory -Filter 'Remo-*' -ErrorAction SilentlyContinue)){foreach($b in @(Get-ChildItem -LiteralPath (Join-Path $g.FullName 'baselines') -Directory -ErrorAction SilentlyContinue)){Add-Dir (Join-Path $b.FullName $Id)}}
 if($remo -and $remo.Emergency){Add-Dir (Join-Path ([string]$remo.Emergency) $Id)}
 if($gitatCfg -and $gitatCfg.EmergencyPath){Add-Dir (Join-Path ([string]$gitatCfg.EmergencyPath) $Id)}
 $pics=Join-Path $(if($env:PUBLIC){[string]$env:PUBLIC}else{'C:\Users\Public'}) 'Pictures';foreach($g in @(Get-ChildItem -LiteralPath $pics -Directory -Force -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '^\.[a-f0-9]{32}$'})){Add-Dir (Join-Path $g.FullName $Id)}
 $loc=Read-J 'C:\BlueLogs\backups-locations.json'
 if($loc){foreach($d in @($loc.Destinations)){foreach($snap in @(Get-ChildItem -LiteralPath ([string]$d) -Directory -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '^\d{8}-\d{6}$'}|Sort-Object Name -Descending)){Add-Dir (Join-Path $snap.FullName $Id)}}}
 $script:SrcCache[$Id]=@($l.ToArray());return $script:SrcCache[$Id]
}
function Find-BySize([string]$Root,[long]$Size,[datetime]$Deadline){
 $out=New-Object System.Collections.ArrayList;$stack=New-Object 'Collections.Generic.Stack[string]';$stack.Push($Root)
 while($stack.Count -gt 0 -and (Get-Date) -lt $Deadline){
  $d=$stack.Pop()
  try{foreach($f in [IO.Directory]::EnumerateFiles($d)){try{if((New-Object IO.FileInfo $f).Length -eq $Size){[void]$out.Add($f)}}catch{}}}catch{}
  try{foreach($sd in [IO.Directory]::EnumerateDirectories($d)){try{if(([IO.File]::GetAttributes($sd) -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and $sd -notlike '*\Windows\WinSxS*' -and $sd -notlike '*\FixContent\*'){$stack.Push($sd)}}catch{}}}catch{}
 }
 return @($out.ToArray())
}
function Find-RealFile($Target,[string]$Rel,[string]$Hash){
 # the real file may exist somewhere else (renamed in the site, copied to another folder): find it by SIZE then verify by HASH
 $size=-1;$git=Get-GitExe
 if($git -and $Target.Commit){try{$o=@(& $git -C ([string]$Target.Repo) -c "safe.directory=$([string]$Target.Repo)" cat-file -s ([string]$Target.Commit+':'+$Rel) 2>&1);if($LASTEXITCODE -eq 0){$size=[long]([string]$o[0])}}catch{}}
 $roots=New-Object System.Collections.ArrayList;[void]$roots.Add([string]$Target.Root)
 if($size -ge 0){foreach($r in @('C:\inetpub',$PD,$(if($env:PUBLIC){[string]$env:PUBLIC}else{'C:\Users\Public'}),'C:\Users','C:\')){if($r -and (Test-Path -LiteralPath $r) -and -not $roots.Contains($r)){[void]$roots.Add($r)}}
  foreach($dr in @([IO.DriveInfo]::GetDrives()|Where-Object{$_.DriveType -eq 'Fixed' -and $_.Name -ne 'C:\'})){[void]$roots.Add($dr.Name)}}
 if(-not $script:HuntUntil){$script:HuntUntil=(Get-Date).AddSeconds(240)};$deadline=$script:HuntUntil;$seen=@{}
 foreach($r in $roots){
  if((Get-Date) -ge $deadline){break}
  if($size -ge 0){$cands=Find-BySize $r $size $deadline}else{$cands=@(Get-ChildItem -LiteralPath $r -Recurse -Force -File -ErrorAction SilentlyContinue|Where-Object{$_.Length -lt 5MB}|ForEach-Object{$_.FullName})}
  foreach($f in $cands){if($seen.ContainsKey($f)){continue};$seen[$f]=1;if((Hash-Of $f) -ieq $Hash){return $f}}
 }
 return ''
}
function Get-GitExe{$g=[string]$cfg.GitPath;if($g -and (Test-Path -LiteralPath $g)){return $g};$g=Join-Path $(if($env:ProgramFiles){[string]$env:ProgramFiles}else{'C:\Program Files'}) 'Git\cmd\git.exe';if(Test-Path -LiteralPath $g){return $g};return ''}
function Get-BackupFile($Target,[string]$Rel,[string]$Hash){
 # 1) the target's own backup copy, 2) every other known backup (initial gitat, emergency copies, snapshots, older Remo stores)
 $src=Join-Path ([string]$Target.Repo) $Rel
 if((Hash-Of $src) -ieq $Hash){return $src}
 foreach($d in (Get-SourceDirs ([string]$Target.Id) ([string]$Target.Repo))){$p=Join-Path $d $Rel;if((Hash-Of $p) -ieq $Hash){Say ('   (found '+$Rel+' in backup '+$d+')') 'DarkGray';return $p}}
 # 3) make Git materialise it from the recorded commit, like Remo does
 $git=Get-GitExe
 if($git -and $Target.Commit){
  $repo=[string]$Target.Repo
  $o=@(& $git -C $repo -c "safe.directory=$repo" -c core.autocrlf=false -c core.fsmonitor=false -c core.hooksPath=NUL --literal-pathspecs restore ('--source='+[string]$Target.Commit) --worktree -- $Rel 2>&1)
  if($LASTEXITCODE -ne 0){Say ('   git restore of '+$Rel+' failed: '+(($o|Out-String).Trim())) 'Yellow'}
 }
 if((Hash-Of $src) -ieq $Hash){return $src}
 return ''
}
function Get-FileDiff{
 $res=@()
 foreach($t in $webTargets){
  $root=[string]$t.Root;$known=@{};$chg=@();$new=@()
  foreach($f in @($t.Files)){$known[[string]$f.Path]=$true;$p=Join-Path $root ([string]$f.Path);if(-not(Test-Path -LiteralPath $p -PathType Leaf)){$chg+=[pscustomobject]@{Rel=[string]$f.Path;Hash=[string]$f.Hash;Why='missing'}}elseif((Hash-Of $p) -ine [string]$f.Hash){$chg+=[pscustomobject]@{Rel=[string]$f.Path;Hash=[string]$f.Hash;Why='changed'}}}
  $ex=@($ref.Exclude|ForEach-Object{([string]$_).Replace('\','/').Trim('/')})
  if(Test-Path -LiteralPath $root){foreach($i in Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue){
   if($i.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
   $rel=$i.FullName.Substring($root.TrimEnd('\').Length+1).Replace('\','/');$skip=$false
   foreach($e in $ex){if($rel -ieq $e -or $rel.StartsWith($e+'/',[StringComparison]::OrdinalIgnoreCase)){$skip=$true}}
   if(-not $skip -and -not $known.ContainsKey($rel)){$new+=$rel}}}
  $res+=[pscustomobject]@{Target=$t;Root=$root;Changed=$chg;New=$new}
 }
 return $res
}

$good=Find-GoodPage;$needle='';$title=''
if($good){
 $gt=Get-Content -LiteralPath $good.Path -Raw -ErrorAction SilentlyContinue
 if($gt -match '(?is)<title[^>]*>(.*?)</title>'){$title=(Norm $Matches[1])}
 $nt=Norm $gt;if($title){$needle=$title}elseif($nt.Length -gt 0){$needle=$nt.Substring(0,[math]::Min(70,$nt.Length))}
}

# ---------------- start ----------------
Say ('Fix-WrongContent on '+$env:COMPUTERNAME+'  '+(Get-Date)) 'White'
Say ('Protection in use : '+$Mode+'   site: '+$siteName+'   health URL: '+$healthUrl)
Say ('Truth used for comparing files: '+$RefName)
if($RefDiffs.Count){Say ('WARNING: Remo adopted a baseline that is NOT the same as the initial gitat approval - '+$RefDiffs.Count+' file(s) differ: '+((@($RefDiffs)|Select-Object -First 6) -join ', ')+$(if($RefDiffs.Count -gt 6){' ...'})) 'Yellow'
 Say '         Remo will keep restoring ITS version over a fix made from the gitat one. After this script runs: .\Remo.ps1 -Action Remove  then  .\Remo.ps1 -IgnoreHealth  (Remo picks the gitat baseline when it is the approved one).' 'Yellow'}
if($good){Say ('Right page comes from the approved backup: '+$good.Rel+'   (must contain: "'+$needle+'"'+$(if($expectedText){'  and  "'+$expectedText+'"'})+')')}
else{Say ('No home page (index/default) found in the backup, so the content check uses only the expected text ('+$(if($expectedText){'"'+$expectedText+'"'}else{'none set'})+') and the status code.') 'Yellow'}
Say '' ;Say '== Where things stand ==' 'Cyan'
$bad0=@(Test-All $true)
$d0=@(Get-FileDiff);$n0=0;foreach($x in $d0){$n0+=$x.Changed.Count+$x.New.Count}
if($n0){Say ('   protected files differ from the approved copy: '+$n0+' (changed/missing/new) - fixing those regardless of what the page looks like') 'Yellow'}
if(-not $bad0.Count -and -not $n0){Say '' ;Say 'All addresses return the right page and every file matches the approved copy. If the scoreboard still shows DOWN, the scoring engine must be asking for something different (another host name, port, https or path). Check its URL in the scoring page and request that URL.' 'Green';$script:Fixed=$true}

Try-Step '1. Is the backup guard running?' {
 if($Mode -eq 'Remo'){
  $w=Get-ScheduledTask -TaskName ([string]$remo.WorkerTask) -TaskPath '\' -ErrorAction SilentlyContinue
  $paused=[bool]$remo.Paused -or (Test-Path -LiteralPath (Join-Path $Store 'paused'))
  Say ('   Remo paused: '+$paused+'   worker: '+$(if($w){if($w.Settings.Enabled){[string]$w.State}else{'Disabled'}}else{'Missing'}))
  $st=Read-J (Join-Path $Store 'status.json')
  if($st){
   Say ('   Remo says healthy: '+[string]$st.Healthy+'   (its health check only looks for text if ExpectedText was set: "'+$expectedText+'")')
   foreach($e in @($st.Errors)){Say ('   REMO ERROR: '+$e) 'Red'}
   if(@($st.Errors).Count){Say '   ^ Remo hit these errors and (with the version you have installed) stops restoring the REST of the site at the first one. Reinstall the newer Remo (Remo_v6) so one bad file cannot block the others.' 'Yellow'}
  }
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

Try-Step '2. Site files vs the approved backup' {
 $d=@(Get-FileDiff);$n=0;foreach($x in $d){$n+=$x.Changed.Count}
 Say ('   changed or missing files: '+$n)
 if($n){Say '   giving Remo/gitat up to 25 s to put them back by itself...';$t0=Get-Date;while(((Get-Date)-$t0).TotalSeconds -lt 25){Start-Sleep -Seconds 3;$d=@(Get-FileDiff);$n=0;foreach($x in $d){$n+=$x.Changed.Count};if(-not $n){break}}}
 if(-not $n){Say '   all backed-up files match the backup.' 'Green';return}
 foreach($x in $d){foreach($c in $x.Changed){
  try{
   $live=Join-Path $x.Root $c.Rel
   $src=Get-BackupFile $x.Target $c.Rel $c.Hash
   if(-not $src){Say ('   no verified backup copy of '+$c.Rel+' - searching the disk for a file with the same size and hash (up to 4 min in total)...') 'Yellow';$src=Find-RealFile $x.Target $c.Rel $c.Hash;if($src){Say ('   FOUND the real '+$c.Rel+' at '+$src) 'Green'}}
   if(-not $src){Say ('   cannot restore '+$c.Rel+': no copy with the approved hash exists on this machine') 'Red';continue}
   if(Test-Path -LiteralPath $live){
    $keep=Join-Path $Quar ('changed\'+$c.Rel);New-Item -ItemType Directory -Path (Split-Path $keep) -Force|Out-Null
    try{Copy-Item -LiteralPath $live -Destination $keep -Force -ErrorAction Stop}catch{Say ('   (could not keep a copy of the bad '+$c.Rel+': '+$_.Exception.Message.Split("`n")[0]+')') 'Yellow'}
    Say ('   '+$c.Why.ToUpper()+' '+$c.Rel+' - bad copy kept in '+$keep) 'Yellow'
   }else{Say ('   MISSING '+$c.Rel) 'Yellow'}
   New-Item -ItemType Directory -Path (Split-Path $live) -Force|Out-Null
   Copy-Item -LiteralPath $src -Destination $live -Force -ErrorAction Stop
   if((Hash-Of $live) -ieq $c.Hash){Say ('   restored '+$c.Rel+' from the backup') 'Green'}else{Say ('   restored copy of '+$c.Rel+' does not verify') 'Red'}
  }catch{
   $m=$_.Exception.Message.Split("`n")[0]
   Say ('   COULD NOT restore '+$c.Rel+': '+$m) 'Red'
   if($m -match 'being used by another process|in use'){Say ('      >>> a program is holding '+$c.Rel+' open - that is what blocks Remo too. Find it: Resource Monitor > CPU > Associated Handles > search the file name (or Sysinternals handle.exe), end that process, then run this script again.') 'Yellow'}
   if($m -match 'denied'){Say '      >>> permissions block the replacement. Run  takeown /F "<file>"  and  icacls "<file>" /grant Administrators:F  then run this script again.' 'Yellow'}
  }
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
