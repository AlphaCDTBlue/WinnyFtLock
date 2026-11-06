#Requires -Version 5.1
<#
Compare-Backup.ps1 - read-only. Shows how the LIVE site compares with the approved backups, in plain terms. Run elevated, no arguments:
    .\Compare-Backup.ps1
1  Every protected file: same as the backup / CHANGED / MISSING, plus files that are NEW (not in the backup).
2  For each changed text file: the lines that differ (<< only in the backup, >> only in the live site).
3  The home page three ways: the backup copy, the live file, and what the web server actually returns - title, size, hash, and the differing lines.
4  EVERY backup copy that exists (Remo store, emergency copy, old gitat/watchdogs baselines, snapshots in your backup locations) - do they agree
   with each other about the home page? If one backup differs from the rest, that backup is the bad one.
Changes nothing. Log: C:\BlueLogs\comparebackup_<host>_<time>.txt
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Continue'
if(-not(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Write-Host 'Open Windows PowerShell as Administrator.' -ForegroundColor Red;return}
$PD=[string]$env:ProgramData;if(-not $PD){$PD='C:\ProgramData'}
$LogDir='C:\BlueLogs';New-Item -ItemType Directory -Path $LogDir -Force|Out-Null
$Log=Join-Path $LogDir ('comparebackup_'+$env:COMPUTERNAME+'_'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.txt')
function Say([string]$t,[string]$c='Gray'){Write-Host $t -ForegroundColor $c;try{Add-Content -LiteralPath $Log -Value $t}catch{}}
function Title([string]$t){Say '' ;Say ('=== '+$t+' ').PadRight(78,'=') 'Cyan'}
function Read-J([string]$p){try{if(Test-Path -LiteralPath $p){return (Get-Content -LiteralPath $p -Raw -ErrorAction Stop|ConvertFrom-Json)}}catch{};return $null}
function Hash-Of([string]$p){try{return (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash}catch{return ''}}
function Short([string]$h){if($h){return $h.Substring(0,12)};return '(none)'}
function Norm([string]$s){return (($s -replace '\s+',' ').Trim())}
function Get-Title([string]$s){if($s -match '(?is)<title[^>]*>(.*?)</title>'){return (Norm $Matches[1])};return '(no <title>)'}
function Show-LineDiff([string]$A,[string]$B,[string]$NameA,[string]$NameB){
 $la=@($A -split "`r?`n");$lb=@($B -split "`r?`n")
 $d=@(Compare-Object -ReferenceObject $la -DifferenceObject $lb -ErrorAction SilentlyContinue)
 if(-not $d.Count){Say '      (no line differences - only whitespace/line endings differ)' 'Gray';return}
 $shown=0
 foreach($x in $d){if($shown -ge 24){Say ('      ... '+($d.Count-24)+' more differing lines') 'DarkGray';break}
  $txt=[string]$x.InputObject;if($txt.Length -gt 150){$txt=$txt.Substring(0,150)+' ...'}
  if($x.SideIndicator -eq '<='){Say ('      << '+$NameA+': '+$txt) 'Yellow'}else{Say ('      >> '+$NameB+': '+$txt) 'Red'};$shown++}
}
function Get-Page([string]$Url){
 $o=[pscustomobject]@{Code=0;Body='';Error=''}
 try{$q=[Net.HttpWebRequest]::Create($Url);$q.Timeout=10000;$q.KeepAlive=$false;$q.AllowAutoRedirect=$true;$r=$null
  try{$r=$q.GetResponse()}catch [Net.WebException]{$r=$_.Exception.Response;if(-not $r){$o.Error=$_.Exception.Message}}
  if($r){$o.Code=[int]$r.StatusCode;$sr=New-Object IO.StreamReader($r.GetResponseStream());$o.Body=$sr.ReadToEnd();$sr.Close();$r.Close()}}catch{$o.Error=$_.Exception.Message}
 return $o
}

$remo=Read-J (Join-Path $PD 'Remo\deployment.json');$Mode='';$Store=''
if($remo -and $remo.State -eq 'Active'){$Mode='Remo';$Store=[string]$remo.Store}elseif(Test-Path -LiteralPath (Join-Path $PD 'IISCache\settings.json')){$Mode='gitat';$Store=Join-Path $PD 'IISCache'}
if(-not $Mode){Say 'Neither Remo nor gitat is installed, so there is no recorded backup to compare with.' 'Red';return}
$cfg=Read-J (Join-Path $Store 'settings.json');if(-not $cfg){Say ('Cannot read '+(Join-Path $Store 'settings.json')) 'Red';return}
Say ('Compare-Backup on '+$env:COMPUTERNAME+'   '+(Get-Date)+'   (using '+$Mode+': '+$Store+')') 'White'
$targets=@($cfg.Targets|Where-Object{-not $_.IsConfig})

Title '1. EVERY PROTECTED FILE: live site vs the approved backup'
$changed=@()
foreach($t in $targets){
 $root=[string]$t.Root;$repo=[string]$t.Repo;$known=@{};$same=0;$miss=@();$chg=@();$new=@()
 foreach($f in @($t.Files)){
  $rel=[string]$f.Path;$known[$rel]=$true;$live=Join-Path $root $rel
  if(-not(Test-Path -LiteralPath $live -PathType Leaf)){$miss+=$rel;continue}
  if((Hash-Of $live) -ieq [string]$f.Hash){$same++}else{$chg+=$rel;$changed+=[pscustomobject]@{Rel=$rel;Live=$live;Backup=(Join-Path $repo $rel)}}
 }
 $ex=@($cfg.Exclude|ForEach-Object{([string]$_).Replace('\','/').Trim('/')})
 if(Test-Path -LiteralPath $root){foreach($i in Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue){
  $rel=$i.FullName.Substring($root.TrimEnd('\').Length+1).Replace('\','/');$skip=$false
  foreach($e in $ex){if($rel -ieq $e -or $rel.StartsWith($e+'/',[StringComparison]::OrdinalIgnoreCase)){$skip=$true}}
  if(-not $skip -and -not $known.ContainsKey($rel)){$new+=$rel}}}
 Say ('Live folder : '+$root) 'White';Say ('Backup copy : '+$repo) 'White'
 Say ('   same as backup: '+$same+'     CHANGED: '+$chg.Count+'     MISSING: '+$miss.Count+'     NEW (not in backup): '+$new.Count) $(if($chg.Count+$miss.Count+$new.Count){'Red'}else{'Green'})
 foreach($x in $chg){Say ('   CHANGED  '+$x) 'Red'};foreach($x in $miss){Say ('   MISSING  '+$x) 'Red'};foreach($x in ($new|Select-Object -First 20)){Say ('   NEW      '+$x) 'Yellow'}
 if($new.Count -gt 20){Say ('   ... '+($new.Count-20)+' more new files') 'DarkGray'}
}
Say ('Not protected (never compared): '+(@($cfg.Exclude) -join ', ')) 'DarkGray'

Title '2. WHAT DIFFERS INSIDE EACH CHANGED FILE  (<< only in backup   >> only in live)'
if(-not $changed.Count){Say '   no changed files.' 'Green'}
foreach($c in ($changed|Select-Object -First 8)){
 Say ('  '+$c.Rel) 'White'
 $isText=$c.Rel -match '\.(html?|aspx?|php|css|js|json|txt|xml|config|svg|md|ashx|cshtml|inc|asp)$'
 $len=0;try{$len=(Get-Item -LiteralPath $c.Live).Length}catch{}
 if($isText -and $len -lt 400000 -and (Test-Path -LiteralPath $c.Backup)){Show-LineDiff (Get-Content -LiteralPath $c.Backup -Raw) (Get-Content -LiteralPath $c.Live -Raw) 'backup' 'live'}
 else{Say ('      binary or large file ('+$len+' bytes): backup hash '+(Short (Hash-Of $c.Backup))+'  live hash '+(Short (Hash-Of $c.Live))) 'Gray'}
}

Title '3. THE HOME PAGE: backup vs live file vs what the web server returns'
$hp=$null
foreach($t in $targets){foreach($f in @($t.Files)){$p=[string]$f.Path;if($p -match '^(index|default|home)\.(html?|aspx?|php)$'){$bp=Join-Path ([string]$t.Repo) $p;if(Test-Path -LiteralPath $bp -PathType Leaf){if(-not $hp -or $p -match '^index\.'){$hp=[pscustomobject]@{Rel=$p;Backup=$bp;Live=(Join-Path ([string]$t.Root) $p);Id=[string]$t.Id;Hash=[string]$f.Hash}}}}}}
$served=Get-Page ([string]$cfg.HealthUrl)
if(-not $hp){Say '   no index/default page in the backup. Served page only:' 'Yellow'}
$bText='';$lText='';$sText=[string]$served.Body
if($hp){
 $bText=Get-Content -LiteralPath $hp.Backup -Raw;$lText=if(Test-Path -LiteralPath $hp.Live){Get-Content -LiteralPath $hp.Live -Raw}else{''}
 Say ('   file: '+$hp.Rel) 'White'
 Say ('   BACKUP copy   title: '+(Get-Title $bText).PadRight(40)+' '+$bText.Length+' chars   hash '+(Short (Hash-Of $hp.Backup)))
 Say ('   LIVE file     title: '+(Get-Title $lText).PadRight(40)+' '+$lText.Length+' chars   hash '+(Short (Hash-Of $hp.Live))) $(if((Hash-Of $hp.Live) -ieq $hp.Hash){'Green'}else{'Red'})
}
Say ('   SERVED ('+[string]$cfg.HealthUrl+')  '+$(if($served.Code){[string]$served.Code}else{'NO ANSWER '+$served.Error})+'   title: '+(Get-Title $sText).PadRight(30)+' '+$sText.Length+' chars') $(if($served.Code -ge 200 -and $served.Code -lt 400){'Gray'}else{'Red'})
if($cfg.ExpectedText){Say ('   expected text "'+[string]$cfg.ExpectedText+'" in the served page: '+$sText.Contains([string]$cfg.ExpectedText)) $(if($sText.Contains([string]$cfg.ExpectedText)){'Green'}else{'Red'})}
if($hp){
 if((Norm $sText) -eq (Norm $bText)){Say '   >>> The served page is IDENTICAL to the backup copy. The web server is returning the approved page.' 'Green'
  Say '       So if the scoreboard still says "did not contain expected content", the approved page itself is not what the scoring engine looks for' 'Yellow'
  Say '       (or it requests a different URL/host). Look at what the scoring check expects.' 'Yellow'}
 else{Say '   >>> The served page DIFFERS from the backup copy. Differences (<< backup only   >> served only):' 'Red';Show-LineDiff $bText $sText 'backup' 'served'}
}

Title '4. DO ALL THE BACKUP COPIES AGREE ABOUT THE HOME PAGE?'
if($hp){
 $src=New-Object System.Collections.ArrayList
 foreach($t in $targets){if([string]$t.Id -eq $hp.Id){[void]$src.Add([pscustomobject]@{Name=($Mode+' working baseline');Path=(Join-Path ([string]$t.Repo) $hp.Rel)})}}
 $em=$null;if($Mode -eq 'Remo' -and $remo.Emergency){$em=[string]$remo.Emergency}elseif($cfg.EmergencyPath){$em=[string]$cfg.EmergencyPath}
 if($em){[void]$src.Add([pscustomobject]@{Name='emergency copy';Path=(Join-Path (Join-Path $em $hp.Id) $hp.Rel)})}
 foreach($g in @(Get-ChildItem -LiteralPath (Join-Path $PD 'IISCache\baselines') -Directory -ErrorAction SilentlyContinue)){[void]$src.Add([pscustomobject]@{Name=('old gitat baseline '+$g.Name.Substring(0,[math]::Min(8,$g.Name.Length)));Path=(Join-Path (Join-Path $g.FullName $hp.Id) $hp.Rel)})}
 foreach($g in @(Get-ChildItem -LiteralPath (Join-Path $PD 'watchdogs\baselines') -Directory -ErrorAction SilentlyContinue)){[void]$src.Add([pscustomobject]@{Name=('watchdogs baseline '+$g.Name.Substring(0,[math]::Min(8,$g.Name.Length)));Path=(Join-Path (Join-Path $g.FullName $hp.Id) $hp.Rel)})}
 foreach($g in @(Get-ChildItem -LiteralPath $PD -Directory -Filter 'Remo-*' -ErrorAction SilentlyContinue|Where-Object{$_.FullName -ne $Store})){foreach($b in @(Get-ChildItem -LiteralPath (Join-Path $g.FullName 'baselines') -Directory -ErrorAction SilentlyContinue)){[void]$src.Add([pscustomobject]@{Name=('older Remo store '+$g.Name.Substring(5,8));Path=(Join-Path (Join-Path $b.FullName $hp.Id) $hp.Rel)})}}
 $loc=Read-J 'C:\BlueLogs\backups-locations.json'
 if($loc){foreach($d in @($loc.Destinations)){foreach($snap in @(Get-ChildItem -LiteralPath ([string]$d) -Directory -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '^\d{8}-\d{6}$'}|Sort-Object Name -Descending|Select-Object -First 6)){[void]$src.Add([pscustomobject]@{Name=('snapshot '+$snap.Name);Path=(Join-Path (Join-Path $snap.FullName $hp.Id) $hp.Rel)})}}}
 $rows=@();foreach($s in $src){$h=Hash-Of $s.Path;$ti='';if($h){$ti=Get-Title (Get-Content -LiteralPath $s.Path -Raw -ErrorAction SilentlyContinue)};$rows+=[pscustomobject]@{Name=$s.Name;Hash=$h;Title=$ti;Path=$s.Path}}
 $groups=@($rows|Where-Object{$_.Hash}|Group-Object Hash|Sort-Object Count -Descending)
 foreach($r in $rows){
  if(-not $r.Hash){Say ('   '+$r.Name.PadRight(30)+' not found / no copy of this file') 'DarkGray';continue}
  $isLive=($r.Hash -ieq (Hash-Of $hp.Live));$isApproved=($r.Hash -ieq $hp.Hash)
  Say ('   '+$r.Name.PadRight(30)+' '+(Short $r.Hash)+'  title: '+$r.Title.PadRight(28)+$(if($isApproved){' = approved hash'}else{' DIFFERENT from the approved hash'})+$(if($isLive){'  (= live file)'})) $(if($isApproved){'Green'}else{'Red'})
 }
 if($groups.Count -gt 1){Say '' ;Say ('   >>> The backup copies DISAGREE ('+$groups.Count+' different versions of '+$hp.Rel+'). The version with the most copies is usually the real one:') 'Yellow';foreach($g in $groups){Say ('       '+(Short $g.Name)+'  x'+$g.Count+'   '+(@($g.Group|ForEach-Object{$_.Name}) -join ', ')) 'Gray'}}
 elseif($groups.Count -eq 1){Say '' ;Say '   all backup copies agree.' 'Green'}
 else{Say '   no backup copies could be read.' 'Red'}
}else{Say '   no home page identified.' 'Yellow'}
Say '' ;Say ('Log: '+$Log)
