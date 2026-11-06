#Requires -Version 5.1
<#
Remo-Unstick.ps1 - use when .\Remo.ps1 hangs or says "Another Remo control operation is running".
Run elevated, no arguments:   .\Remo-Unstick.ps1
It saves the last lines of the stuck install's progress log, stops the stuck install (its request task, its PowerShell
process and any Git it started), removes the leftover request task, then reads Remo's state and prints the exact
command to run next. It does NOT touch the website, gitat, or any installed Remo. It never kills other PowerShell windows.
Report (everything it printed): C:\BlueLogs\remo-unstick_<host>_<time>.txt
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Continue'
if(-not(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){Write-Host 'Open Windows PowerShell as Administrator.' -ForegroundColor Red;return}
$PD=[string]$env:ProgramData;if(-not $PD){$PD='C:\ProgramData'}
$LogDir='C:\BlueLogs';New-Item -ItemType Directory -Path $LogDir -Force|Out-Null
$Report=Join-Path $LogDir ('remo-unstick_'+$env:COMPUTERNAME+'_'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.txt')
function Say([string]$t,[string]$c='Gray'){Write-Host $t -ForegroundColor $c;try{Add-Content -LiteralPath $Report -Value $t}catch{}}

Say '== 1. What the stuck install was doing (last lines of its log) ==' 'Cyan'
$req=Join-Path $PD 'Remo\requests'
$latest=$null;if(Test-Path -LiteralPath $req){$latest=Get-ChildItem -LiteralPath $req -Directory -ErrorAction SilentlyContinue|Sort-Object LastWriteTime -Descending|Select-Object -First 1}
if($latest){
 $pl=Join-Path $latest.FullName 'progress.log'
 if(Test-Path -LiteralPath $pl){
  Say ('log last written: '+(Get-Item -LiteralPath $pl).LastWriteTime+'     now: '+(Get-Date))
  foreach($l in @(Get-Content -LiteralPath $pl -Tail 15 -ErrorAction SilentlyContinue)){Say ('   '+$l)}
 }else{Say '   no progress.log in the newest request folder.'}
}else{Say '   no request folders found.'}

Say '' ;Say '== 2. Stopping the stuck install ==' 'Cyan'
$tasks=@(Get-ScheduledTask -ErrorAction SilentlyContinue|Where-Object{$_.TaskName -match '^Remo-Request-[0-9a-f]{32}$'})
Say ('request tasks found: '+$tasks.Count)
foreach($t in $tasks){try{Stop-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop;Say ('   stopped task '+$t.TaskName)}catch{Say ('   could not stop '+$t.TaskName+': '+$_.Exception.Message) 'Yellow'}}
$killed=New-Object System.Collections.ArrayList
$procs=@();try{$procs=@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction Stop|Where-Object{$_.CommandLine -and $_.CommandLine -match 'Remo\.ps1' -and $_.CommandLine -match 'InternalRequest' -and $_.ProcessId -ne $PID})}catch{Say ('could not list processes: '+$_.Exception.Message) 'Yellow'}
$ids=@($procs|ForEach-Object{[int]$_.ProcessId})
try{foreach($g in @(Get-CimInstance Win32_Process -Filter "Name='git.exe'" -ErrorAction Stop)){if($ids -contains [int]$g.ParentProcessId -or ($g.CommandLine -and $g.CommandLine -match 'ProgramData\\Remo')){[void]$killed.Add(('git.exe '+$g.ProcessId));Stop-Process -Id $g.ProcessId -Force -ErrorAction SilentlyContinue}}}catch{}
foreach($p in $procs){[void]$killed.Add(('powershell.exe '+$p.ProcessId));Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue}
if($killed.Count){foreach($k in $killed){Say ('   killed '+$k)}}else{Say '   no stuck Remo process was running.'}
Start-Sleep -Seconds 2
foreach($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue|Where-Object{$_.TaskName -match '^Remo-Request-[0-9a-f]{32}$'})){try{Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop;Say ('   removed leftover task '+$t.TaskName)}catch{Say ('   could not remove '+$t.TaskName) 'Yellow'}}

Say '' ;Say '== 3. Is the lock free now? ==' 'Cyan'
$free=$true
try{$m=New-Object Threading.Mutex($false,'Global\Remo-Control');$got=$false;try{$got=$m.WaitOne(0)}catch [Threading.AbandonedMutexException]{$got=$true};if($got){$m.ReleaseMutex()}else{$free=$false};$m.Dispose()}catch{Say ('   could not test the lock: '+$_.Exception.Message) 'Yellow'}
if($free){Say '   yes - Remo commands will run again.' 'Green'}else{Say '   NO - something still holds it. Close other PowerShell windows running Remo, or reboot, then run this again.' 'Red'}

Say '' ;Say '== 4. What state it left, and what to run next ==' 'Cyan'
$dep=Join-Path $PD 'Remo\deployment.json';$state='';$d=$null
if(Test-Path -LiteralPath $dep){try{$d=Get-Content -LiteralPath $dep -Raw|ConvertFrom-Json;$state=[string]$d.State}catch{$state='unreadable'}}
if(-not $d){Say '   Remo state: none (no half-finished install).'}else{Say ('   Remo state: '+$state+$(if($d.Error){'   ('+[string]$d.Error+')'}))}
$gitat=Get-ScheduledTask -TaskName gitat -TaskPath '\' -ErrorAction SilentlyContinue
if($gitat){Say ('   old gitat task: '+$(if($gitat.Settings.Enabled){[string]$gitat.State}else{'Disabled'}))}
Say ''
if(-not $d -or $state -in 'Failed','Removed'){
 Say 'NEXT, type:' 'White';Say '     .\Remo.ps1 -IgnoreHealth' 'Green'
 Say '   (-IgnoreHealth lets the install finish even while the site returns the wrong content, so it stops waiting on the site check.)'
}elseif($state -eq 'Active'){
 Say 'Remo is already installed and Active. NEXT, type:' 'White';Say '     .\Remo-Check.ps1' 'Green'
}else{
 Say 'The install died halfway. NEXT, type these two, one after the other:' 'White'
 Say '     .\Remo.ps1 -Action Remove' 'Green';Say '     .\Remo.ps1 -IgnoreHealth' 'Green'
}
Say '' ;Say ('Saved to '+$Report)
