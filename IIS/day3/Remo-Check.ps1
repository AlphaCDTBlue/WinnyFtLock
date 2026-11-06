#Requires -Version 5.1
<#
Remo-Check.ps1 - read-only status check for Remo. Changes nothing. No arguments.
Run elevated:   .\Remo-Check.ps1
Prints a verdict first (WORKING / CHECK / PROBLEM, with the reason and the command to fix it), then: where everything
lives, the two scheduled tasks, the latest health pass, a live test of the website, file integrity, task enforcement,
leftover old tools, BlueOps and old failed-attempt folders.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Continue'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Write-Host 'Open Windows PowerShell as Administrator (Remo''s folders are admin-only).' -ForegroundColor Red;return}

$PD=[string]$env:ProgramData;if(-not $PD){$PD='C:\ProgramData'}
$Control=Join-Path $PD 'Remo';$DepFile=Join-Path $Control 'deployment.json'
$Problems=New-Object System.Collections.ArrayList;$Warnings=New-Object System.Collections.ArrayList;$Fixes=New-Object System.Collections.ArrayList
function Bad([string]$t,[string]$fix=''){[void]$Problems.Add($t);if($fix -and -not $Fixes.Contains($fix)){[void]$Fixes.Add($fix)}}
function Warn([string]$t,[string]$fix=''){[void]$Warnings.Add($t);if($fix -and -not $Fixes.Contains($fix)){[void]$Fixes.Add($fix)}}
function Read-J([string]$p){try{if(Test-Path -LiteralPath $p){return (Get-Content -LiteralPath $p -Raw -ErrorAction Stop|ConvertFrom-Json)}}catch{};return $null}
function Hash-Of([string]$p){try{if(Test-Path -LiteralPath $p -PathType Leaf){return (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash}}catch{};return ''}
function Age-Of($t){try{return [int]((Get-Date).ToUniversalTime()-([datetimeoffset]$t).UtcDateTime).TotalSeconds}catch{return -1}}
function Fmt-Time($t){try{return ([datetimeoffset]$t).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')}catch{return [string]$t}}
function Fmt-Age([int]$s){if($s -lt 0){return 'unknown'};if($s -lt 120){return [string]$s+' s ago'};if($s -lt 7200){return [string][int]($s/60)+' min ago'};return [string][int]($s/3600)+' h ago'}
function Title([string]$t){Write-Host '';Write-Host ('=== '+$t+' ').PadRight(78,'=') -ForegroundColor Cyan}
function Row([string]$k,$v,[string]$c='Gray'){if($k.Length -gt 25){$k=$k.Substring(0,25)};Write-Host ('  '+$k.PadRight(27)) -NoNewline -ForegroundColor DarkGray;Write-Host ([string]$v) -ForegroundColor $c}
function Task-Info([string]$name){
 $o=[ordered]@{Exists=$false;State='Missing';Enabled=$false;LastRun='';LastAge=-1;LastResult='';Next=''}
 if(-not $name){return [pscustomobject]$o}
 $t=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
 if($t){
  $o.Exists=$true;$o.Enabled=[bool]$t.Settings.Enabled;$o.State=if(-not $o.Enabled){'Disabled'}else{[string]$t.State}
  try{$i=Get-ScheduledTaskInfo -TaskName $name -TaskPath '\' -ErrorAction Stop;if($i.LastRunTime -and $i.LastRunTime.Year -gt 2000){$o.LastRun=$i.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss');$o.LastAge=[int]((Get-Date)-$i.LastRunTime).TotalSeconds};$o.LastResult=('0x{0:X}' -f [uint32]$i.LastTaskResult);if($i.NextRunTime -and $i.NextRunTime.Year -gt 2000){$o.Next=$i.NextRunTime.ToString('HH:mm:ss')}}catch{}
 }
 return [pscustomobject]$o
}

# ================= gather =================
$d=Read-J $DepFile
$leftover=@(Get-ChildItem -LiteralPath $PD -Directory -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '^(Remo|RemoSupervisor|RemoOnce)-[0-9a-f]{32}$'})
$legacy=@();foreach($n in 'gitat','watchdogs','watchdogsgit'){$t=Get-ScheduledTask -TaskName $n -TaskPath '\' -ErrorAction SilentlyContinue;if($t){$legacy+=,[pscustomobject]@{Name=$n;State=$(if($t.Settings.Enabled){[string]$t.State}else{'Disabled'})}}}
$installed=($d -and $d.State -eq 'Active')

if(-not $d){Bad 'Remo is not installed (no C:\ProgramData\Remo\deployment.json).' '.\Remo.ps1'}
elseif($d.State -ne 'Active'){Bad ('Remo state is '+$d.State+$(if($d.Error){' - '+$d.Error}else{''})+'.') $(if($d.State -eq 'Failed'){'Fix the site first (.\Fix-HttpError.ps1 <number>), then run .\Remo.ps1 again (add -IgnoreHealth only if the site cannot be fixed).'}else{'.\Remo.ps1'})}

$worker=$null;$super=$null;$status=$null;$settings=$null;$sup=$null;$enf=$null;$http=$null;$healthAge=-1;$integrity=@();$procs=@();$jCount=0;$fCount=0;$targets=@()
if($installed){
 $worker=Task-Info ([string]$d.WorkerTask);$super=Task-Info ([string]$d.SupervisorTask)
 $status=Read-J (Join-Path $d.Store 'status.json');$settings=Read-J (Join-Path $d.Store 'settings.json')
 $sup=Read-J (Join-Path $Control 'supervisor-status.json');$enf=Read-J (Join-Path (Join-Path $Control 'tasks') 'enforcement.json')
 if($status){$healthAge=Age-Of $status.Time}
 try{$j=Read-J (Join-Path (Join-Path $Control 'tasks') 'journal.json');if($j){$jCount=@($j.PSObject.Properties).Count}}catch{}
 try{$f=Read-J (Join-Path (Join-Path $Control 'tasks') 'failures.json');if($f){$fCount=@($f.PSObject.Properties).Count}}catch{}
 # integrity
 $integrity+=,[pscustomobject]@{Name='Worker engine';Path=[string]$d.Engine;Want=[string]$d.EngineHash;Have=(Hash-Of ([string]$d.Engine))}
 $integrity+=,[pscustomobject]@{Name='Rescue engine copy';Path=[string]$d.RescueEngine;Want=[string]$d.EngineHash;Have=(Hash-Of ([string]$d.RescueEngine))}
 $integrity+=,[pscustomobject]@{Name='Supervisor script';Path=[string]$d.Supervisor;Want=[string]$d.SupervisorHash;Have=(Hash-Of ([string]$d.Supervisor))}
 $integrity+=,[pscustomobject]@{Name='Approved settings';Path=(Join-Path $d.Store 'settings.json');Want=[string]$d.SettingsHash;Have=(Hash-Of (Join-Path $d.Store 'settings.json'))}
 if($settings){foreach($t in @($settings.Targets)){$targets+=,[pscustomobject]@{Id=[string]$t.Id;Root=[string]$t.Root;RootOk=(Test-Path -LiteralPath ([string]$t.Root));Repo=[string]$t.Repo;RepoOk=(Test-Path -LiteralPath ([string]$t.Repo));EmergencyOk=(Test-Path -LiteralPath (Join-Path ([string]$d.Emergency) ([string]$t.Id)))}}}
 # live website test
 $url=if($settings){[string]$settings.HealthUrl}else{''}
 if($url){
  $http=[pscustomobject]@{Url=$url;Code=0;Text='';Ms=0}
  try{
   $sw=[Diagnostics.Stopwatch]::StartNew()
   $q=[Net.HttpWebRequest]::Create($url);$q.Timeout=10000;$q.AllowAutoRedirect=$true;$q.KeepAlive=$false;$q.UserAgent='Remo-Check'
   $resp=$null
   try{$resp=$q.GetResponse()}catch [Net.WebException]{$resp=$_.Exception.Response;if(-not $resp){$http.Text=$_.Exception.Message}}
   if($resp){$http.Code=[int]$resp.StatusCode;$http.Text=[string]$resp.StatusDescription;$resp.Close()}
   $sw.Stop();$http.Ms=[int]$sw.ElapsedMilliseconds
  }catch{$http.Text=$_.Exception.Message}
 }
 # worker processes
 try{$procs=@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction Stop|Where-Object{$_.CommandLine -and $_.CommandLine -match [regex]::Escape([string]$d.Engine) -and $_.CommandLine -match '-Action\s+Run'})}catch{}

 # ---- judge ----
 if($d.Paused){Bad 'Remo is PAUSED - it is not protecting anything.' ('& "'+$d.Supervisor+'" -Action Resume')}
 if($worker.State -ne 'Running'){Bad ('Worker task is '+$worker.State+' (should be Running).') $(if($worker.State -eq 'Disabled'){'Enable-ScheduledTask -TaskName '+$d.WorkerTask+'; Start-ScheduledTask -TaskName '+$d.WorkerTask}else{'Start-ScheduledTask -TaskName '+$d.WorkerTask})}
 if(-not $super.Exists){Bad 'Supervisor task is missing (task enforcement and self-repair are off).' ('& "'+$d.Supervisor+'" -Action Resume')}
 elseif($super.State -eq 'Disabled'){Bad 'Supervisor task is disabled.' ('Enable-ScheduledTask -TaskName '+$d.SupervisorTask)}
 elseif($super.LastAge -gt 240){Warn ('Supervisor last ran '+(Fmt-Age $super.LastAge)+' (it should run every minute).')}
 if(-not $status){Bad 'No health pass has been written yet (status.json missing).'}
 else{
  if($healthAge -lt 0 -or $healthAge -gt 180){Bad ('Health pass is stale: last one '+(Fmt-Age $healthAge)+'.') ('Start-ScheduledTask -TaskName '+$d.WorkerTask)}
  elseif($healthAge -gt 30){Warn ('Health pass is '+(Fmt-Age $healthAge)+' (normally under 15 s).')}
  if(-not $status.Healthy){Bad ('Latest pass says NOT healthy. HTTP: '+[string]$status.HTTP.Result+$(if(@($status.Errors).Count){'  Errors: '+(@($status.Errors) -join '; ')}else{''})) '.\Fix-HttpError.ps1 <number>  (5 for 5xx, 4 for 4xx, 3 for redirects, 6 for no answer)'}
  elseif(@($status.Errors).Count){Warn ('Latest pass reported errors: '+(@($status.Errors) -join '; '))}
 }
 if($http -and ($http.Code -lt 200 -or $http.Code -ge 400)){Bad ('Live test of '+$http.Url+' returned '+$(if($http.Code){[string]$http.Code+' '+$http.Text}else{'NO ANSWER ('+$http.Text+')'})+'.') '.\Fix-HttpError.ps1 <number>'}
 foreach($x in $integrity){if(-not $x.Have){Bad ($x.Name+' is missing: '+$x.Path)}elseif($x.Want -and $x.Have -ine $x.Want){Bad ($x.Name+' does not match the recorded hash (it was changed): '+$x.Path)}}
 if(-not (Test-Path -LiteralPath ([string]$d.Emergency))){Bad ('Emergency copy folder is missing: '+$d.Emergency)}
 foreach($t in $targets){if(-not $t.RootOk){Bad ('Protected site folder is missing: '+$t.Root)};if(-not $t.RepoOk){Bad ('Approved baseline copy is missing: '+$t.Repo)}}
 if($procs.Count -gt 1){Warn ([string]$procs.Count+' worker processes are running (should be 1).')}
 elseif($worker.State -eq 'Running' -and -not $procs.Count){Warn 'Worker task says Running but no engine process was found (could not read process list).'}
 foreach($l in $legacy){if($l.State -ne 'Disabled'){Warn ('Old task "'+$l.Name+'" is still '+$l.State+' and could fight Remo.') ('Disable-ScheduledTask -TaskName '+$l.Name)}}
 $reqTasks=@(Get-ScheduledTask -ErrorAction SilentlyContinue|Where-Object{$_.TaskName -match '^Remo-Request-[0-9a-f]{32}$'})
 if($reqTasks.Count){Warn ([string]$reqTasks.Count+' leftover Remo-Request task(s) from an earlier run.')}
 if($enf -and [int]$enf.Failing -gt 0){Warn ([string]$enf.Failing+' scheduled task(s) cannot be disabled by Remo (see failures.json).')}
}

# ================= print =================
Write-Host ''
Write-Host ('Remo check - '+$env:COMPUTERNAME+' - '+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
if($Problems.Count){
 Write-Host ''
 Write-Host '  >>> REMO HAS A PROBLEM <<<' -ForegroundColor White -BackgroundColor DarkRed
 foreach($p in $Problems){Write-Host ('   - '+$p) -ForegroundColor Red}
 foreach($w in $Warnings){Write-Host ('   - '+$w) -ForegroundColor Yellow}
}elseif($Warnings.Count){
 Write-Host ''
 Write-Host '  >>> REMO IS WORKING - but check this <<<' -ForegroundColor Black -BackgroundColor Yellow
 foreach($w in $Warnings){Write-Host ('   - '+$w) -ForegroundColor Yellow}
}else{
 Write-Host ''
 Write-Host '  >>> REMO IS WORKING <<<' -ForegroundColor White -BackgroundColor DarkGreen
 Write-Host ('   healthy, last pass '+(Fmt-Age $healthAge)+', website answers '+$http.Code+', both tasks up, files intact.') -ForegroundColor Green
}
if($Fixes.Count){Write-Host '';Write-Host '  To fix:' -ForegroundColor White;foreach($f in $Fixes){Write-Host ('     '+$f) -ForegroundColor White}}

if($installed){
 Title 'WHERE IT LIVES'
 Row 'Remo control folder' $Control
 Row 'Store (baseline+logs)' $d.Store
 Row 'Worker engine' $d.Engine
 Row 'Supervisor script' $d.Supervisor
 Row 'Emergency copy' $d.Emergency
 Row 'Rollback of old gitat' (Join-Path $Control ('rollback\'+$d.Id))
 Row 'Task enforcement files' (Join-Path $Control 'tasks')
 Row 'Install source' $d.Source
 Row 'Installed' (Fmt-Time $d.Created)
 foreach($t in $targets){Row ('Protected folder '+$t.Id) ($t.Root+$(if(-not $t.RootOk){'   <- MISSING'})) $(if($t.RootOk){'Gray'}else{'Red'});Row ('  approved copy') ($t.Repo+$(if(-not $t.RepoOk){'   <- MISSING'}else{''})) $(if($t.RepoOk){'Gray'}else{'Red'})}

 Title 'STATE AND TASKS'
 Row 'Deployment state' ([string]$d.State) $(if($d.State -eq 'Active'){'Green'}else{'Red'})
 Row 'Paused' ([string]$d.Paused) $(if($d.Paused){'Red'}else{'Green'})
 Row 'Worker task' ($d.WorkerTask+'   '+$worker.State) $(if($worker.State -eq 'Running'){'Green'}else{'Red'})
 Row '  last start' ($worker.LastRun+'   result '+$worker.LastResult) 'Gray'
 Row 'Worker processes' ([string]$procs.Count+$(if($procs.Count){'   (PID '+((@($procs|ForEach-Object{$_.ProcessId})) -join ', ')+')'})) $(if($procs.Count -eq 1){'Green'}else{'Yellow'})
 Row 'Supervisor task' ($d.SupervisorTask+'   '+$super.State) $(if($super.Exists -and $super.State -ne 'Disabled'){'Green'}else{'Red'})
 Row '  last run' ($super.LastRun+'   ('+(Fmt-Age $super.LastAge)+')   result '+$super.LastResult+'   next '+$super.Next) 'Gray'
 if($sup){Row '  supervisor said' ([string]$sup.Result) $(if([string]$sup.Result -match '^(ERROR|STALE)'){'Red'}else{'Gray'});if($sup.Tasks){Row '  task enforcement' ([string]$sup.Tasks) 'Gray'}}

 Title 'LATEST HEALTH PASS (every ~10 s)'
 if($status){
  Row 'Healthy' ([string]$status.Healthy) $(if($status.Healthy){'Green'}else{'Red'})
  Row 'Last pass' ((Fmt-Time $status.Time)+'   ('+(Fmt-Age $healthAge)+')') $(if($healthAge -ge 0 -and $healthAge -le 30){'Green'}elseif($healthAge -le 180 -and $healthAge -ge 0){'Yellow'}else{'Red'})
  Row 'Pass paused' ([string]$status.Paused) $(if($status.Paused){'Red'}else{'Gray'})
  Row 'Website state' ([string]$status.Site) $(if($status.Site -eq 'Started'){'Green'}else{'Red'})
  foreach($p in @($status.Pools)){Row ('App pool '+$p.Name) ([string]$p.State) $(if($p.State -eq 'Started'){'Green'}else{'Red'})}
  foreach($s in @($status.Services)){Row ('Service '+$s.Name) ([string]$s.State) $(if($s.State -eq 'Running'){'Green'}else{'Red'})}
  Row 'HTTP (its own check)' ($(if($status.HTTP.Healthy){'OK - '}else{'FAIL - '})+[string]$status.HTTP.Result) $(if($status.HTTP.Healthy){'Green'}else{'Red'})
  Row 'Last file restore' $(if($status.LastRestore){($status.LastRestore|ConvertTo-Json -Compress -Depth 4)}else{'none - files match the approved copy'}) 'Gray'
  Row 'Last service action' $(if($status.LastServiceAction){($status.LastServiceAction|ConvertTo-Json -Compress -Depth 3)}else{'none'}) 'Gray'
  Row 'Events (last pass)' $(if(@($status.Events).Count){(@($status.Events) -join ' | ')}else{'none'}) 'Gray'
  Row 'Errors (last pass)' $(if(@($status.Errors).Count){(@($status.Errors) -join ' | ')}else{'none'}) $(if(@($status.Errors).Count){'Red'}else{'Gray'})
  Row 'Pass took' ([string]$status.ScanSeconds+' s') 'Gray'
 }else{Row 'status.json' 'not written yet' 'Red'}

 Title 'LIVE WEBSITE TEST (right now, separate from Remo)'
 if($http){Row 'URL' $http.Url;Row 'Answer' ($(if($http.Code){[string]$http.Code+' '+$http.Text}else{'NO ANSWER - '+$http.Text})+'   ('+$http.Ms+' ms)') $(if($http.Code -ge 200 -and $http.Code -lt 400){'Green'}else{'Red'})}else{Row 'URL' 'no health URL recorded' 'Yellow'}

 Title 'FILE INTEGRITY (hash of each Remo file against what was recorded at install)'
 foreach($x in $integrity){$ok=($x.Have -and (-not $x.Want -or $x.Have -ieq $x.Want));Row $x.Name $(if($ok){'OK'}elseif(-not $x.Have){'MISSING'}else{'CHANGED'}) $(if($ok){'Green'}else{'Red'})}
 Row 'Emergency copy' $(if(Test-Path -LiteralPath ([string]$d.Emergency)){'present'}else{'MISSING'}) $(if(Test-Path -LiteralPath ([string]$d.Emergency)){'Green'}else{'Red'})
 foreach($t in $targets){Row ('  emergency '+$t.Id) $(if($t.EmergencyOk){'present'}else{'MISSING'}) $(if($t.EmergencyOk){'Green'}else{'Red'})}

 Title 'TASK ENFORCEMENT (Remo disables every other scheduled task)'
 if($enf){Row 'Last run' ((Fmt-Time $enf.Time)+'   ('+(Fmt-Age (Age-Of $enf.Time))+')');Row 'Disabled by Remo' ([string]$enf.DisabledTotal+' task(s) in total');Row 'Cannot disable' ([string]$enf.Failing) $(if([int]$enf.Failing){'Yellow'}else{'Gray'})}else{Row 'Enforcement' 'has not run yet (first run is about a minute after install)' 'Yellow'}
 Row 'Saved so you can undo' ([string]$jCount+' task(s)   undo: & "'+$d.Supervisor+'" -Action Pause   then   -Action RestoreTasks') 'Gray'

 Title 'OTHER THINGS THAT COULD INTERFERE'
 if($legacy.Count){foreach($l in $legacy){Row ('Old task '+$l.Name) $l.State $(if($l.State -eq 'Disabled'){'Gray'}else{'Yellow'})}}else{Row 'Old gitat/watchdog tasks' 'none (good)' 'Green'}
 Row 'Old IISCache folder' $(if(Test-Path (Join-Path $PD 'IISCache')){'exists'}else{'none'}) 'Gray'
 $bo=Test-Path 'C:\BlueOps\Svc-Control.ps1';$bw=Test-Path 'C:\BlueOps\Svc-Control-Worker.ps1'
 Row 'BlueOps controller' $(if($bo){'present'}else{'MISSING (Remo cannot restart W3SVC)'}) $(if($bo){'Green'}else{'Red'})
 Row 'BlueOps worker' $(if($bw){'present'}else{'MISSING'}) $(if($bw){'Green'}else{'Red'})
 Row 'BlueOps request pending' $(if(Test-Path 'C:\BlueOps\request.json'){'YES (a service action is stuck or running)'}else{'no'}) $(if(Test-Path 'C:\BlueOps\request.json'){'Yellow'}else{'Gray'})
 try{$sd=((& sc.exe sdshow W3SVC 2>&1)|Out-String);Row 'W3SVC lock' $(if($sd -match '\(D;;DCWPDTSD;;;AU\)'){'ON (stop/restart only through BlueOps)'}else{'not detected'}) 'Gray'}catch{}
 foreach($n in 'WAS','W3SVC'){$sv=Get-Service -Name $n -ErrorAction SilentlyContinue;if($sv){Row ('Service '+$n) ([string]$sv.Status) $(if($sv.Status -eq 'Running'){'Green'}else{'Red'})}}
}

$old=@($leftover|Where-Object{$installed -and $d -and $_.Name -notmatch ([regex]::Escape((Split-Path ([string]$d.Store) -Leaf))+'|'+[regex]::Escape((Split-Path (Split-Path ([string]$d.Supervisor) -Parent) -Leaf)))})
if(-not $installed){$old=$leftover}
Title 'OLD FOLDERS FROM EARLIER / FAILED INSTALLS (safe to ignore; recovery data is kept on purpose)'
if($old.Count){foreach($o in $old){Write-Host ('  '+$o.Name+'   modified '+$o.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) -ForegroundColor Gray}}else{Write-Host '  none' -ForegroundColor Gray}
if(-not $installed -and $legacy.Count){Title 'OLD TOOLS STILL INSTALLED';foreach($l in $legacy){Row ('Task '+$l.Name) $l.State}}
Write-Host ''
