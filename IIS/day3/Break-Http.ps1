#Requires -Version 5.1
<#
Break-Http.ps1 - TEST ONLY. Breaks the website on purpose and checks that it gets fixed. The site is down for a
few seconds to about a minute per break. Everything it breaks is put back at the end, even if nothing fixed it.
Run elevated in 64-bit Windows PowerShell 5.1:
    .\Break-Http.ps1                runs all five breaks one after another with Remo ON and times how fast Remo heals each
    .\Break-Http.ps1 3              one break only
    .\Break-Http.ps1 -TestFixer     turns Remo OFF, breaks the site, runs Fix-HttpError.ps1 (keep it beside this script)
                                    to prove IT can fix it, then turns Remo back ON
Breaks: 1 stop the app pool   2 stop the website   3 delete a site file   4 corrupt web.config   5 stop W3SVC (through BlueOps)
Remo is checked first. If it is paused or its tasks are off, this script resumes/enables it. It always leaves Remo ON.
Log: C:\BlueLogs\breakhttp_<host>_<time>.txt   Safety copies of files: C:\BlueLogs\BreakHttp\<time>
#>
[CmdletBinding()]
param([ValidateRange(0,5)][int]$Scenario=0,[switch]$TestFixer)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 as Administrator.'}
if(-not(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Open Windows PowerShell as Administrator.'}
$AppCmd=Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
if(-not(Test-Path -LiteralPath $AppCmd)){throw 'IIS is not installed (appcmd.exe not found).'}
$Stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$LogDir='C:\BlueLogs';$Work=Join-Path $LogDir ('BreakHttp\'+$Stamp)
New-Item -ItemType Directory -Path $Work -Force|Out-Null
$Log=Join-Path $LogDir ('breakhttp_'+$env:COMPUTERNAME+'_'+$Stamp+'.txt')
$HealSeconds=90

function Say([string]$Text,[string]$Color='Gray'){Write-Host $Text -ForegroundColor $Color;try{Add-Content -LiteralPath $Log -Value $Text}catch{}}
function Invoke-AppCmd{
 $o=@(& $AppCmd @args 2>&1)
 if($LASTEXITCODE -ne 0){throw ('appcmd '+($args -join ' ')+' failed: '+(($o|Out-String).Trim()))}
 return $o
}

# ---------------- the site under test ----------------
function Get-TestSite{
 $apps=@{};foreach($l in @(Invoke-AppCmd list app)){if("$l" -match '^APP "(?<n>.+?)" \(applicationPool:(?<p>.+?)\)\s*$'){$apps[$Matches.n]=$Matches.p}}
 $vd=@{};foreach($l in @(Invoke-AppCmd list vdir)){if("$l" -match '^VDIR "(?<n>.+?)" \(physicalPath:(?<p>.+)\)\s*$'){$vd[$Matches.n]=[Environment]::ExpandEnvironmentVariables($Matches.p)}}
 foreach($l in @(Invoke-AppCmd list site)){
  if("$l" -match '^SITE "(?<n>.+?)" \(id:(?<id>\d+),bindings:(?<b>.*),state:(?<s>\w+)\)\s*$'){
   $n=$Matches.n;$st=$Matches.s;$b=@($Matches.b -split ','|Where-Object{$_})
   if($st -ne 'Started'){continue}
   foreach($x in $b){if($x -match '^http/(?<ip>[^:]*):(?<port>\d+):(?<h>.*)$'){return [pscustomobject]@{Name=$n;Pool=[string]$apps[$n+'/'];Path=[string]$vd[$n+'/'];Port=[int]$Matches.port;Host=[string]$Matches.h}}}
  }
 }
 return $null
}
function Get-Code{
 try{
  $q=[Net.HttpWebRequest]::Create('http://127.0.0.1:'+$script:Site.Port+'/');$q.Timeout=15000;$q.AllowAutoRedirect=$false;$q.KeepAlive=$false;$q.UserAgent='Break-Http'
  if($script:Site.Host){$q.Host=$script:Site.Host}
  $resp=$null
  try{$resp=$q.GetResponse()}catch [Net.WebException]{$resp=$_.Exception.Response;if(-not $resp){return 0}}
  $c=[int]$resp.StatusCode;$resp.Close();return $c
 }catch{return 0}
}
function Test-Ok{$c=Get-Code;return ($c -ge 200 -and $c -lt 400)}
function Get-PoolState{return (((Invoke-AppCmd list apppool $script:Site.Pool '/text:state')|Out-String).Trim())}
function Get-SiteState{foreach($l in @(Invoke-AppCmd list site $script:Site.Name)){if("$l" -match 'state:(\w+)\)'){return $Matches[1]}};return ''}
function Get-W3State{return [string](Get-Service -Name W3SVC).Status}
function Invoke-BlueOpsAction([string]$Action){
 $ctl='C:\BlueOps\Svc-Control.ps1'
 if(-not(Test-Path -LiteralPath $ctl)){throw 'BlueOps controller (C:\BlueOps\Svc-Control.ps1) not found.'}
 $until=(Get-Date).AddSeconds(40);while((Test-Path 'C:\BlueOps\request.json') -and (Get-Date) -lt $until){Start-Sleep -Seconds 2}
 [void](& $ctl -Service IIS -Action $Action)
}
function Start-W3{
 if((Get-W3State) -eq 'Running'){return}
 try{Start-Service -Name W3SVC -ErrorAction Stop}catch{Invoke-BlueOpsAction 'Start'}
}
function Wait-Until([scriptblock]$Cond,[int]$Seconds){
 $n=[math]::Ceiling($Seconds/2)
 for($i=0;$i -le $n;$i++){if(& $Cond){return $i*2};Start-Sleep -Seconds 2}
 return -1
}

# ---------------- Remo ----------------
function Get-RemoInfo{
 $i=[ordered]@{Installed=$false;State='none';Paused=$false;Script='';Store='';Worker='';Supervisor='';WorkerState='';SupervisorState='';Healthy=$false;Age=-1;PassPaused=$false}
 $f='C:\ProgramData\Remo\deployment.json'
 if(Test-Path -LiteralPath $f){
  try{
   $d=Get-Content -LiteralPath $f -Raw|ConvertFrom-Json
   $i.State=[string]$d.State;$i.Paused=[bool]$d.Paused;$i.Script=[string]$d.Supervisor;$i.Store=[string]$d.Store;$i.Worker=[string]$d.WorkerTask;$i.Supervisor=[string]$d.SupervisorTask
   if($d.State -eq 'Active'){$i.Installed=$true}
  }catch{}
 }
 if($i.Installed){
  if(-not $i.Script -or -not (Test-Path -LiteralPath $i.Script)){$alt=Get-ChildItem 'C:\ProgramData' -Directory -Filter 'RemoSupervisor-*' -ErrorAction SilentlyContinue|ForEach-Object{Join-Path $_.FullName 'Remo.ps1'}|Where-Object{Test-Path $_}|Select-Object -First 1;if($alt){$i.Script=$alt}}
  foreach($k in 'Worker','Supervisor'){
   $t=Get-ScheduledTask -TaskName $i[$k] -TaskPath '\' -ErrorAction SilentlyContinue
   $i[$k+'State']=if(-not $t){'Missing'}elseif(-not $t.Settings.Enabled){'Disabled'}else{[string]$t.State}
  }
  try{
   $s=Get-Content -LiteralPath (Join-Path $i.Store 'status.json') -Raw|ConvertFrom-Json
   $i.Healthy=[bool]$s.Healthy;$i.PassPaused=[bool]$s.Paused;$i.Age=[int]((Get-Date)-[datetime]$s.Time).TotalSeconds
  }catch{}
 }
 return [pscustomobject]$i
}
function Show-Remo($r){
 if(-not $r.Installed){Say ('Remo: NOT installed (state: '+$r.State+')') Red;return}
 Say ('Remo: state='+$r.State+' paused='+$r.Paused+' worker='+$r.WorkerState+' supervisor='+$r.SupervisorState+' healthy='+$r.Healthy+' heartbeat='+$r.Age+'s') $(if($r.Healthy -and -not $r.Paused -and $r.WorkerState -eq 'Running'){'Green'}else{'Yellow'})
 Say ('  location: '+$r.Script+'   store: '+$r.Store) DarkGray
}
function Test-RemoOn($r){return ($r.Installed -and -not $r.Paused -and -not $r.PassPaused -and $r.WorkerState -eq 'Running' -and $r.Healthy -and $r.Age -ge 0 -and $r.Age -le 60)}
# Resumes / enables / starts whatever is off, then waits for a fresh healthy heartbeat.
function Enable-Remo{
 $r=Get-RemoInfo
 if(-not $r.Installed){Say 'Remo is not installed, so it cannot be turned on. Run .\Remo.ps1 first.' Red;return $r}
 foreach($k in 'Worker','Supervisor'){
  $n=$r.$k;$st=$r.($k+'State')
  if($st -eq 'Disabled'){Enable-ScheduledTask -TaskName $n -TaskPath '\'|Out-Null;Say ('  enabled task '+$n) Cyan}
 }
 if($r.Paused -or (Test-Path -LiteralPath (Join-Path $r.Store 'paused'))){
  Say '  Remo is paused; resuming it' Cyan
  (& $r.Script -Action Resume *>&1)|ForEach-Object{Say ('    '+$_) DarkGray}
 }
 $r=Get-RemoInfo
 if($r.WorkerState -ne 'Running' -and $r.WorkerState -ne 'Missing'){try{Start-ScheduledTask -TaskName $r.Worker -TaskPath '\';Say ('  started task '+$r.Worker) Cyan}catch{}}
 $ok=Wait-Until {Test-RemoOn (Get-RemoInfo)} 60
 $r=Get-RemoInfo
 if($ok -ge 0){Say '  Remo is ON.' Green}else{Say '  Remo did not report a fresh healthy heartbeat within 60 s - check .\Remo.ps1 -Action Status' Red}
 return $r
}
function Disable-Remo{
 $r=Get-RemoInfo
 if(-not $r.Installed){return $false}
 (& $r.Script -Action Pause *>&1)|ForEach-Object{Say ('    '+$_) DarkGray}
 $ok=Wait-Until {$x=Get-RemoInfo;$x.Paused -and $x.PassPaused} 45
 if($ok -ge 0){Say '  Remo is paused (OFF for the test).' Yellow;return $true}
 Say '  Remo did not confirm the pause within 45 s.' Red;return $false
}
function Invoke-Fixer([int]$Class){
 $fix=Join-Path $PSScriptRoot 'Fix-HttpError.ps1'
 if(-not(Test-Path -LiteralPath $fix)){throw 'Put Fix-HttpError.ps1 in the same folder as Break-Http.ps1.'}
 & $fix $Class
}

# ---------------- the five breaks ----------------
function New-Breaks{
 $site=$script:Site;$root=$site.Path
 $b=@()
 $b+=,[pscustomobject]@{Id=1;Name='stop the app pool ('+$site.Pool+')';
  Do={Invoke-AppCmd stop apppool $script:Site.Pool|Out-Null};
  Ok={(Get-PoolState) -eq 'Started' -and (Test-Ok)};
  Undo={if((Get-PoolState) -ne 'Started'){Invoke-AppCmd start apppool $script:Site.Pool|Out-Null}}}
 $b+=,[pscustomobject]@{Id=2;Name='stop the website ('+$site.Name+')';
  Do={Invoke-AppCmd stop site $script:Site.Name|Out-Null};
  Ok={(Get-SiteState) -eq 'Started' -and (Test-Ok)};
  Undo={if((Get-SiteState) -ne 'Started'){Invoke-AppCmd start site $script:Site.Name|Out-Null}}}
 # 3: a site file. Prefer the home page so the break is visible.
 $file='';foreach($n in 'index.html','index.htm','default.htm','default.html','default.aspx','index.aspx','iisstart.htm'){if(Test-Path -LiteralPath (Join-Path $root $n)){$file=Join-Path $root $n;break}}
 if(-not $file){$f=Get-ChildItem -LiteralPath $root -File -ErrorAction SilentlyContinue|Where-Object{$_.Name -ine 'web.config'}|Select-Object -First 1;if($f){$file=$f.FullName}}
 if($file){
  $copy=Join-Path $Work 'site-file.bak';$script:File=$file;$script:FileCopy=$copy
  $b+=,[pscustomobject]@{Id=3;Name='delete the site file '+(Split-Path $file -Leaf);
   Do={Copy-Item -LiteralPath $script:File -Destination $script:FileCopy -Force;Remove-Item -LiteralPath $script:File -Force};
   Ok={(Test-Path -LiteralPath $script:File) -and (Test-Ok)};
   Undo={if(-not(Test-Path -LiteralPath $script:File) -and (Test-Path -LiteralPath $script:FileCopy)){Copy-Item -LiteralPath $script:FileCopy -Destination $script:File -Force}}}
 }else{$b+=,[pscustomobject]@{Id=3;Name='delete a site file';Skip='the site folder has no files to delete'}}
 # 4: web.config
 $wc=Join-Path $root 'web.config';$script:Wc=$wc;$script:WcCopy=Join-Path $Work 'web.config.bak';$script:WcHad=Test-Path -LiteralPath $wc
 if($script:WcHad){$script:WcHash=(Get-FileHash -LiteralPath $wc -Algorithm SHA256).Hash}
 $b+=,[pscustomobject]@{Id=4;Name='corrupt web.config'+$(if(-not $script:WcHad){' (there is none, so a bad one is created)'});
  Do={if($script:WcHad){Copy-Item -LiteralPath $script:Wc -Destination $script:WcCopy -Force};Set-Content -LiteralPath $script:Wc -Value '<?xml version="1.0"?><configuration><system.webServer><broken-by-Break-Http>' -Encoding UTF8};
  Ok={(Test-Ok) -and $(if($script:WcHad){(Test-Path -LiteralPath $script:Wc) -and ((Get-FileHash -LiteralPath $script:Wc -Algorithm SHA256).Hash -eq $script:WcHash)}else{-not(Test-Path -LiteralPath $script:Wc)})};
  Undo={if($script:WcHad){if(-not(Test-Path -LiteralPath $script:Wc) -or ((Get-FileHash -LiteralPath $script:Wc -Algorithm SHA256).Hash -ne $script:WcHash)){Copy-Item -LiteralPath $script:WcCopy -Destination $script:Wc -Force}}elseif(Test-Path -LiteralPath $script:Wc){Remove-Item -LiteralPath $script:Wc -Force}}}
 # 5: W3SVC through BlueOps
 if(Test-Path 'C:\BlueOps\Svc-Control.ps1'){
  $b+=,[pscustomobject]@{Id=5;Name='stop W3SVC through BlueOps';
   Do={Invoke-BlueOpsAction 'Stop'};
   Ok={(Get-W3State) -eq 'Running' -and (Test-Ok)};
   Undo={Start-W3}}
 }else{$b+=,[pscustomobject]@{Id=5;Name='stop W3SVC through BlueOps';Skip='BlueOps is not installed on this box'}}
 return $b
}

# ---------------- run ----------------
Say ('Break-Http on '+$env:COMPUTERNAME+'  '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+$(if($TestFixer){'   mode: TEST THE FIXER (Remo off)'}else{'   mode: TEST REMO (Remo on)'})) Cyan
Say ('Log: '+$Log) DarkGray
$script:Site=Get-TestSite
if(-not $script:Site){throw 'No started site with an http binding was found.'}
Say ('Site: '+$script:Site.Name+'  pool='+$script:Site.Pool+'  folder='+$script:Site.Path+'  port='+$script:Site.Port)
if(-not (Test-Ok)){throw 'The site is not healthy right now. Fix it first (.\Fix-HttpError.ps1 <number>), then run this test.'}

$remo=Get-RemoInfo
Show-Remo $remo
if(-not $TestFixer){
 if(-not $remo.Installed){throw 'Remo is not installed. Install it first (.\Remo.ps1), or use -TestFixer.'}
 if(-not (Test-RemoOn $remo)){Say 'Remo is off or not healthy - turning it on first.' Yellow;$remo=Enable-Remo;if(-not (Test-RemoOn (Get-RemoInfo))){throw 'Could not turn Remo on; not breaking anything.'}}
}else{
 if(-not(Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Fix-HttpError.ps1'))){throw 'Put Fix-HttpError.ps1 in the same folder as Break-Http.ps1.'}
}

$breaks=@(New-Breaks)
if($Scenario){$breaks=@($breaks|Where-Object{$_.Id -eq $Scenario})}
$rows=@();$pausedByUs=$false
try{
 if($TestFixer -and $remo.Installed){if(-not $remo.Paused){$pausedByUs=Disable-Remo}else{Say '  Remo was already paused.' DarkGray}}
 Say ''
 Say 'Breaking the live site in 5 seconds. Ctrl+C now to cancel.' Yellow
 Start-Sleep -Seconds 5
 foreach($b in $breaks){
  Say ''
  if($b.Skip){Say ('['+$b.Id+'] '+$b.Name+' - skipped: '+$b.Skip) DarkGray;$rows+=,[pscustomobject]@{Id=$b.Id;Name=$b.Name;Broke='-';By='skipped';Sec='-'};continue}
  Say ('['+$b.Id+'] '+$b.Name) Cyan
  try{
   & $b.Do
   Start-Sleep -Seconds 1
   $broke=Get-Code
   $took=-not (& $b.Ok)
   Say ('  broken: HTTP '+$(if($broke){[string]$broke}else{'no answer'})+$(if(-not $took){'  (already healed or the break did not change the page)'}))
   $by='';$sec=-1
   if($TestFixer){
    $stay=Wait-Until {& $b.Ok} 10
    if($stay -ge 0){Say '  it healed by itself while Remo was supposed to be off.' Yellow}
    $cls=if($broke -eq 0){6}else{[int][math]::Floor($broke/100)};if($cls -lt 3){$cls=4}
    Say ('  running Fix-HttpError.ps1 '+$cls) Cyan
    $t0=Get-Date
    try{Invoke-Fixer $cls}catch{Say ('  fixer error: '+$_.Exception.Message) Red}
    $sec=[int]((Get-Date)-$t0).TotalSeconds
    $by=if(& $b.Ok){'Fix-HttpError'}else{'NOT FIXED'}
   }else{
    Say ('  waiting up to '+$HealSeconds+' s for Remo...')
    $sec=Wait-Until $b.Ok $HealSeconds
    $by=if($sec -ge 0){'Remo'}else{'NOT HEALED'}
   }
   if($by -in 'NOT HEALED','NOT FIXED'){Say ('  '+$by+' - restoring it myself') Red}else{Say ('  healed by '+$by+' in about '+$sec+' s') Green}
   $rows+=,[pscustomobject]@{Id=$b.Id;Name=$b.Name;Broke=$(if($broke){[string]$broke}else{'none'});By=$by;Sec=$(if($sec -ge 0){[string]$sec}else{'-'})}
  }catch{
   Say ('  test error: '+$_.Exception.Message) Red
   $rows+=,[pscustomobject]@{Id=$b.Id;Name=$b.Name;Broke='?';By='ERROR';Sec='-'}
  }
  finally{try{& $b.Undo}catch{Say ('  restore error: '+$_.Exception.Message) Red}}
  [void](Wait-Until {Test-Ok} 30)
 }
}finally{
 foreach($b in $breaks){if(-not $b.Skip){try{& $b.Undo}catch{}}}
 Say ''
 Say 'Making sure Remo is ON:' Cyan
 $final=Enable-Remo
}

Say ''
Say 'RESULTS' Cyan
foreach($r in $rows){Say (('['+$r.Id+'] '+$r.Name).PadRight(52)+('HTTP '+$r.Broke).PadRight(14)+$r.By.PadRight(15)+$(if($r.Sec -ne '-'){$r.Sec+' s'}else{''})) $(if($r.By -in 'Remo','Fix-HttpError'){'Green'}elseif($r.By -eq 'skipped'){'DarkGray'}else{'Red'})}
Say ''
$f=Get-RemoInfo;Show-Remo $f
Say ('Site now: HTTP '+(Get-Code)) $(if(Test-Ok){'Green'}else{'Red'})
Say ('Log: '+$Log) DarkGray
