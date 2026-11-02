#Requires -Version 5.1
<#
Remo.ps1 - migrate the existing approved gitat baseline; install one worker and supervisor.
Run elevated in 64-bit Windows PowerShell 5.1: .\Remo.ps1
Controls: -Action Status | Pause | Resume | Remove | RestoreTasks | Once
Remove stops Remo and restores the previous gitat task definitions/engine when available.
No fresh live baseline is ever approved. Accounts and firewall rules are not changed.
Task enforcement: once a minute the SUPERVISOR (never the IIS recovery worker) disables every scheduled task
except Remo's own, BlueOps' one-use task, a live Remo request and anything listed in $KeepTasks (edit that
list BEFORE installing). A task is disabled only after its XML is saved and a journal entry is written.
Pause stops enforcement. -Action RestoreTasks (while paused or removed) re-enables what Remo disabled.
OpenSSH/WinRM are handled by the separate Disable-RemoteAccess.ps1.
.\Remo.ps1 -Action Once = one pass only: restores the IIS files from the approved baseline once and disables
the other scheduled tasks once, then exits. No Remo task or loop is left running (refused while Remo is installed).
The baseline it adopts is kept in C:\ProgramData\RemoOnce-<id> and reused on later Once runs.
-Action RestoreTasks re-enables what Once disabled.
Source engine adapted from AlphaCDTBlue/WinnyFtLock IIS/gitat.ps1, retrieved 2026-10-29.
#>
[CmdletBinding()]
param(
 [ValidateSet('Install','Status','Pause','Resume','Remove','Supervise','RestoreTasks','Once')][string]$Action='Install',
 [ValidatePattern('^$|^[a-f0-9]{32}$')][string]$InternalRequest=''
)
$ErrorActionPreference='Stop'
$Control=Join-Path $env:ProgramData 'Remo'
$StateFile=Join-Path $Control 'deployment.json'
$PowerShellExe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$Self=$PSCommandPath

function Assert-Plain([string]$Path){
 $p=[IO.Path]::GetFullPath($Path)
 while($p){if(Test-Path -LiteralPath $p){if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw "Link/junction refused: $p"}};$p=[IO.Path]::GetDirectoryName($p)}
}
function Protect-Directory([string]$Path){
 Assert-Plain $Path
 New-Item -ItemType Directory -Path $Path -Force|Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
 Set-Acl -LiteralPath $Path -AclObject $acl
}
function Write-State([string]$Path,$Value){
 Assert-Plain $Path;Assert-Plain ($Path+'.tmp')
 $Value|ConvertTo-Json -Depth 32|Set-Content -LiteralPath ($Path+'.tmp') -Encoding UTF8
 Move-Item -LiteralPath ($Path+'.tmp') -Destination $Path -Force
}
function Read-Json([string]$Path){Assert-Plain $Path;Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json}
function Get-Hash([string]$Path){Assert-Plain $Path;(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
function Test-Under([string]$Child,[string]$Parent){
 $c=[IO.Path]::GetFullPath($Child).TrimEnd('\');$p=[IO.Path]::GetFullPath($Parent).TrimEnd('\')
 return ($c -ieq $p -or $c.StartsWith($p+'\',[StringComparison]::OrdinalIgnoreCase))
}
function Assert-Relative([string]$Name,[switch]$Directory){
 if($Directory -and $Name -eq '.'){return}
 if(-not $Name -or $Name -match '(^[\\/]|:|(^|[\\/])\.\.?([\\/]|$)|[\x00-\x1f])' -or $Name -match '(^|[\\/])\.git([\\/]|$)'){throw "Invalid baseline path: $Name"}
 foreach($part in ($Name -split '[\\/]')){if(-not $part -or $part -match '[ .]$'){throw "Ambiguous baseline path: $Name"}}
}
function Assert-Manifest($M){
 if($M.FormatVersion -ne 2 -or -not @($M.Targets).Count){throw 'Expected a gitat format-2 manifest with targets.'}
 if(-not $script:NameWarned -and (-not $M.Computer -or $M.Computer -ine $env:COMPUTERNAME)){$script:NameWarned=$true;if(-not $M.Computer){Write-Warning 'The approved backup manifest records no computer name, so it cannot be tied to this computer. Continuing: its files, hashes and Git commits are still checked.'}else{Write-Warning "The approved backup was recorded on '$($M.Computer)', this computer is '$($env:COMPUTERNAME)'. Continuing: its files, hashes and Git commits are still checked."}}
 if(-not $M.SiteName -or -not $M.HealthUrl -or ([uri]$M.HealthUrl).Scheme -notin @('http','https')){throw 'Baseline lacks a valid site/health URL.'}
 if($M.NewFiles -notin @('Quarantine','Report')){throw 'Invalid unexpected-file policy.'}
 foreach($ex in @($M.Exclude)){Assert-Relative ([string]$ex)}
 $ids=@{};$roots=@{};$web=0;$cfg=0
 foreach($t in $M.Targets){
  if($t.Id -notmatch '^(site\d+|iiscfg)$' -or $ids.ContainsKey($t.Id)){throw 'Invalid/duplicate target ID.'};$ids[$t.Id]=$true
  if($t.Root -notmatch '^[A-Za-z]:\\.+' -or $t.Commit -notmatch '^[a-fA-F0-9]{40}$'){throw 'Invalid target root/approved Git commit.'}
  $root=[IO.Path]::GetFullPath([string]$t.Root).TrimEnd('\');Assert-Plain $root
  if($roots.ContainsKey($root)){throw 'Duplicate target root.'};$roots[$root]=$true
  if($t.IsConfig -isnot [bool]){throw 'IsConfig must be a JSON boolean.'}
  if($t.IsConfig){
   if($root -ine (Join-Path $env:SystemRoot 'System32\inetsrv\config')){throw 'Unexpected IIS configuration root.'};$cfg++
  }else{
   if((Test-Under $root $env:SystemRoot) -or $root -imatch '^[a-z]:\\(users|programdata|program files|program files \(x86\))$'){throw 'Unsafe website root.'};$web++
  }
  if(-not @($t.Files).Count -or -not @($t.Directories).Count){throw "Empty/incomplete manifest: $($t.Id)"}
  $files=@{};$dirs=@{}
  foreach($f in $t.Files){
   Assert-Relative $f.Path
   if($files.ContainsKey($f.Path.Replace('\','/')) -or $f.Hash -notmatch '^[A-Fa-f0-9]{64}$' -or -not $f.AccessSddl){throw 'Invalid/duplicate file record.'};$files[$f.Path.Replace('\','/')]=$true
   $null=New-Object Security.AccessControl.RawSecurityDescriptor($f.AccessSddl)
   if($t.IsConfig -and $f.Path -notin @('applicationHost.config','administration.config','redirection.config')){throw 'Unexpected IIS configuration file.'}
  }
  if($t.IsConfig -and -not $files.ContainsKey('applicationHost.config')){throw 'IIS applicationHost.config is absent from the manifest.'}
  foreach($d in $t.Directories){Assert-Relative $d.Path -Directory;if($dirs.ContainsKey($d.Path)){throw 'Duplicate directory record.'};$dirs[$d.Path]=$true;if(-not $d.AccessSddl){throw 'Missing directory ACL.'};$null=New-Object Security.AccessControl.RawSecurityDescriptor($d.AccessSddl)}
 }
 foreach($t in $M.Targets){if(-not @($t.Directories|Where-Object Path -eq '.').Count){throw 'Target root ACL is missing.'}}
 if($web -lt 1 -or $cfg -ne 1){throw 'A website baseline and one IIS configuration target are required.'}
 $rootList=@($roots.Keys)
 for($i=0;$i -lt $rootList.Count;$i++){for($j=$i+1;$j -lt $rootList.Count;$j++){if((Test-Under $rootList[$i] $rootList[$j]) -or (Test-Under $rootList[$j] $rootList[$i])){throw 'Overlapping protected roots are not supported.'}}}
}
function Get-BaselineIdentity($M){
 # Compare approved contents/scope, independent of where the repositories were copied.
 $identity=[ordered]@{SiteName=$M.SiteName;SiteNames=@($M.SiteNames);Pools=@($M.Pools);HealthUrl=$M.HealthUrl;ExpectedText=$M.ExpectedText;ExpectedFinalUrl=$M.ExpectedFinalUrl;MaxRedirects=$M.MaxRedirects;Exclude=@($M.Exclude);NewFiles=$M.NewFiles;Targets=@()}
 foreach($t in @($M.Targets|Sort-Object Id)){$identity.Targets+=,[ordered]@{Id=$t.Id;Root=$t.Root;Commit=$t.Commit;IsConfig=$t.IsConfig;Files=@($t.Files|Sort-Object Path);Directories=@($t.Directories|Sort-Object Path)}}
 $bytes=[Text.Encoding]::UTF8.GetBytes(($identity|ConvertTo-Json -Depth 32 -Compress))
 $sha=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')}finally{$sha.Dispose()}
}
function Invoke-SafeGit([string]$Repo,[string[]]$Items){
 $previous=$ErrorActionPreference;$ErrorActionPreference='Continue'
 try{$out=@(& $script:GitExe -C $Repo -c "safe.directory=$Repo" -c core.hooksPath=NUL -c core.fsmonitor=false -c core.autocrlf=false --literal-pathspecs @Items 2>&1);$code=$LASTEXITCODE}finally{$ErrorActionPreference=$previous}
 if($code -ne 0){throw "Git failed: $($out -join ' ')"};$out|ForEach-Object {"$_"}
}
function Assert-RepoFiles($Target,[string]$Repo){
 Assert-Plain $Repo
 if(-not(Test-Path -LiteralPath (Join-Path $Repo '.git') -PathType Container)){throw "Missing independent Git repository: $Repo"}
 foreach($x in Get-ChildItem -LiteralPath $Repo -Recurse -Force){Assert-Plain $x.FullName}
 foreach($f in $Target.Files){$path=Join-Path $Repo $f.Path;if(-not(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Hash $path) -ine $f.Hash){throw "Incomplete/changed backup: $($Target.Id)/$($f.Path)"}}
}
function Sort-BackupCandidates($Candidates){
 $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 foreach($c in @($Candidates|Sort-Object Order,@{Expression='Stamp';Descending=$true})){
  if($seen.Add([string]$c.Path)){$c}
 }
}
function Get-BackupCandidates{
 $list=New-Object Collections.ArrayList
 $loc='C:\BlueLogs\backups-locations.json'
 if(Test-Path -LiteralPath $loc){
  try{
   $locations=Read-Json $loc
   foreach($d in @($locations.Destinations)){
    Assert-Plain $d
    if(Test-Path -LiteralPath $d -PathType Container){
     foreach($snap in Get-ChildItem -LiteralPath $d -Directory -Force|Where-Object Name -Match '^\d{8}-\d{6}$'|Sort-Object Name -Descending){
      $manifest=Join-Path $snap.FullName 'manifest.json'
      if(Test-Path -LiteralPath $manifest -PathType Leaf){[void]$list.Add([pscustomobject]@{Kind='Snapshot';Path=$manifest;Base=$snap.FullName;Order=0;Stamp=$snap.Name})}
     }
    }
   }
  }catch{Write-Warning "Backup index could not be read: $($_.Exception.Message)"}
 }
 foreach($root in @((Join-Path $env:ProgramData 'IISCache'),(Join-Path $env:ProgramData 'watchdogs'))){
  $p=Join-Path $root 'settings.json'
  if(Test-Path -LiteralPath $p){
   [void]$list.Add([pscustomobject]@{Kind='Primary';Path=$p;Base=$root;Order=1;Stamp=''})
   try{$m=Read-Json $p;if($m.EmergencyPath){$ep=Join-Path $m.EmergencyPath 'manifest.json';if(Test-Path -LiteralPath $ep){[void]$list.Add([pscustomobject]@{Kind='Emergency';Path=$ep;Base=$m.EmergencyPath;Order=2;Stamp=''})}}}catch{Write-Warning $_.Exception.Message}
  }
 }
 # If settings.json was lost, inspect only the exact legacy emergency naming convention.
 $pictures=Join-Path $env:PUBLIC 'Pictures'
 if(Test-Path $pictures){foreach($d in Get-ChildItem -LiteralPath $pictures -Directory -Force|Where-Object Name -Match '^\.[a-f0-9]{32}$'){
  $p=Join-Path $d.FullName 'manifest.json';if(Test-Path -LiteralPath $p){[void]$list.Add([pscustomobject]@{Kind='Emergency';Path=$p;Base=$d.FullName;Order=2;Stamp=''})}
 }}
 Sort-BackupCandidates @($list.ToArray())
}
function Copy-ValidatedBaseline([string]$Store,[string]$Emergency){
 $reference=$null;$old=Join-Path $env:ProgramData 'IISCache\settings.json'
 if(Test-Path -LiteralPath $old){try{$reference=Read-Json $old;Assert-Manifest $reference}catch{throw "Existing approval manifest is invalid; restore it from a trusted source before migration. $($_.Exception.Message)"}}
 $referenceId=if($reference){Get-BaselineIdentity $reference}else{''}
 $candidates=@(Get-BackupCandidates)
 if(-not $candidates.Count){throw 'No recorded approved backups found. Existing gitat was not changed.'}
 $generation=Join-Path $Store ('baselines\'+[guid]::NewGuid().ToString('N'))
 foreach($candidate in $candidates){
  try{
   $m=Read-Json $candidate.Path;Assert-Manifest $m
   if($referenceId -and (Get-BaselineIdentity $m) -ne $referenceId){throw 'Snapshot differs from the current approved baseline; refusing an automatic rollback to an older generation.'}
   foreach($t in $m.Targets){$source=if($candidate.Kind -eq 'Primary'){$t.Repo}else{Join-Path $candidate.Base $t.Id};Assert-RepoFiles $t $source}
   Protect-Directory $generation
   foreach($t in $m.Targets){
    $source=if($candidate.Kind -eq 'Primary'){$t.Repo}else{Join-Path $candidate.Base $t.Id}
    $dst=Join-Path $generation $t.Id;Protect-Directory $dst
    Get-ChildItem -LiteralPath $source -Force|Copy-Item -Destination $dst -Recurse -Force
    # Strip repository-local executable configuration before invoking Git against the staged copy.
    $gitDir=Join-Path $dst '.git'
    if(Test-Path -LiteralPath (Join-Path $gitDir 'objects\info\alternates')){throw 'Repository uses alternate objects; independent backup required.'}
    [IO.File]::WriteAllText((Join-Path $gitDir 'config'),"[core]`nrepositoryformatversion = 0`nbare = false`nautocrlf = false`n")
    New-Item -ItemType Directory -Path (Join-Path $gitDir 'info') -Force|Out-Null
    [IO.File]::WriteAllText((Join-Path $gitDir 'info\attributes'),"* -text -filter -ident -working-tree-encoding`n")
    Invoke-SafeGit $dst @('fsck','--full','--no-reflogs','--no-progress',$t.Commit)|Out-Null
    Invoke-SafeGit $dst @('restore',('--source='+$t.Commit),'--worktree','--','.')|Out-Null
    Assert-RepoFiles $t $dst
    $t.Repo=$dst
   }
   foreach($t in $m.Targets){foreach($p in @($Store,$Emergency,$Control)){if((Test-Under $p $t.Root) -or (Test-Under $t.Root $p)){throw 'Recovery storage overlaps a protected live root.'}}}
   $m|Add-Member NoteProperty PrimaryPath $Store -Force
   $m|Add-Member NoteProperty EmergencyPath $Emergency -Force
   $m.GitPath=$script:GitExe
   Write-Host "Validated recovery source: $($candidate.Path)"
   return [pscustomobject]@{Settings=$m;Source=$candidate.Path;Kind=$candidate.Kind}
  }catch{
   Write-Warning "Rejected $($candidate.Path): $($_.Exception.Message)"
   if(Test-Path -LiteralPath $generation){Remove-Item -LiteralPath $generation -Recurse -Force}
  }
 }
 throw 'No complete approved recovery copy validated. Existing gitat was not changed.'
}
function Get-LegacyTasks([string]$Archive){
 $items=@()
 foreach($name in @('gitat','watchdogs','watchdogsgit')){
  $t=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue
  if(-not $t){continue}
  $scriptPath=if($name -eq 'gitat'){Join-Path $env:ProgramData 'IISCache\gitat-engine.ps1'}else{Join-Path $env:ProgramData ("watchdogs\$name.ps1")}
  $actions=@($t.Actions)
  if($actions.Count -ne 1 -or $actions[0].Execute -ine $PowerShellExe -or $actions[0].Arguments -notmatch ('(?i)^-NoProfile\s+-NonInteractive\s+-ExecutionPolicy\s+Bypass\s+-File\s+"'+[regex]::Escape($scriptPath)+'"\s+-Action\s+Run\s*$')){throw "Unexpected legacy task definition: $name. Review it before migration."}
  Assert-Plain $scriptPath
  if(-not(Test-Path -LiteralPath $scriptPath -PathType Leaf)){throw "Missing legacy engine: $scriptPath"}
  $saved=Join-Path $Archive ($name+'.ps1');Copy-Item -LiteralPath $scriptPath -Destination $saved
  $paused=Join-Path (Split-Path $scriptPath -Parent) 'paused'
  $items+=,[pscustomobject]@{Name=$name;Path='\';Xml=(Export-ScheduledTask -TaskName $name -TaskPath '\');Enabled=[bool]$t.Settings.Enabled;Running=($t.State -eq 'Running');Script=$scriptPath;SavedScript=$saved;ScriptHash=(Get-Hash $saved);PausePath=$paused;WasPaused=(Test-Path -LiteralPath $paused)}
 }
 return $items
}
function Stop-TaskAndWait([string]$Name){
 $t=Get-ScheduledTask -TaskName $Name -TaskPath '\' -ErrorAction SilentlyContinue
 if(-not $t){return}
 Disable-ScheduledTask -TaskName $Name -TaskPath '\'|Out-Null
 Stop-ScheduledTask -TaskName $Name -TaskPath '\'
 $until=(Get-Date).AddSeconds(45)
 while((Get-ScheduledTask -TaskName $Name -TaskPath '\').State -eq 'Running'){if((Get-Date) -gt $until){throw "Task did not stop: $Name"};Start-Sleep -Seconds 1}
}
function Restore-Legacy($State){
 foreach($o in @($State.Legacy)){
  if($o.Name -notin @('gitat','watchdogs','watchdogsgit') -or $o.Path -cne '\'){throw 'Invalid legacy task record.'}
  $expected=if($o.Name -eq 'gitat'){Join-Path $env:ProgramData 'IISCache\gitat-engine.ps1'}else{Join-Path $env:ProgramData ('watchdogs\'+$o.Name+'.ps1')}
  $saved=Join-Path $Control ('rollback\'+$State.Id+'\'+$o.Name+'.ps1')
  if($o.Script -ine $expected -or $o.SavedScript -ine $saved -or $o.PausePath -ine (Join-Path (Split-Path $expected -Parent) 'paused')){throw 'Legacy rollback paths do not match saved installation.'}
  if((Get-Hash $o.SavedScript) -ine $o.ScriptHash){throw "Saved legacy engine failed validation: $($o.Name)"}
  Assert-Plain $o.Script;Copy-Item -LiteralPath $o.SavedScript -Destination $o.Script -Force
  Register-ScheduledTask -TaskName $o.Name -TaskPath $o.Path -Xml $o.Xml -Force|Out-Null
  if($o.WasPaused){New-Item -ItemType File -Path $o.PausePath -Force|Out-Null}else{Remove-Item -LiteralPath $o.PausePath -Force -ErrorAction SilentlyContinue}
  if($o.Enabled){Enable-ScheduledTask -TaskName $o.Name -TaskPath $o.Path|Out-Null}else{Disable-ScheduledTask -TaskName $o.Name -TaskPath $o.Path|Out-Null}
  if($o.Running -and $o.Enabled -and -not $o.WasPaused){Start-ScheduledTask -TaskName $o.Name -TaskPath $o.Path}
 }
}
function Get-TaskArguments($S,[string]$Kind){
 if($Kind -eq 'Worker'){return ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action Run' -f $S.Engine)}
 return ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action Supervise' -f $S.Supervisor)
}
function Register-RemoTask($S,[string]$Kind){
 $name=if($Kind -eq 'Worker'){$S.WorkerTask}else{$S.SupervisorTask}
 $act=New-ScheduledTaskAction -Execute $PowerShellExe -Argument (Get-TaskArguments $S $Kind)
 $triggers=@((New-ScheduledTaskTrigger -AtStartup),(New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)))
 $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $act -Trigger $triggers -Settings $settings -User SYSTEM -RunLevel Highest -Force|Out-Null
}
function Test-TaskDefinition($T,$S,[string]$Kind){
 if(-not $T){return $false};$a=@($T.Actions)
 $boot=@($T.Triggers|Where-Object {$_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger' -and $_.Enabled}).Count -eq 1
 $repeat=@($T.Triggers|Where-Object {$_.CimClass.CimClassName -eq 'MSFT_TaskTimeTrigger' -and $_.Repetition.Interval -eq 'PT1M' -and $_.Enabled}).Count -eq 1
 return ($a.Count -eq 1 -and $a[0].Execute -ieq $PowerShellExe -and $a[0].Arguments -ceq (Get-TaskArguments $S $Kind) -and $T.Principal.UserId -in @('SYSTEM','S-1-5-18') -and [string]$T.Principal.RunLevel -eq 'Highest' -and [string]$T.Principal.LogonType -eq 'ServiceAccount' -and $boot -and $repeat -and @($T.Triggers).Count -eq 2 -and [string]$T.Settings.MultipleInstances -eq 'IgnoreNew' -and $T.Settings.ExecutionTimeLimit -eq 'PT0S')
}
function Read-Deployment{
 if(-not(Test-Path -LiteralPath $StateFile)){return $null}
 $s=Read-Json $StateFile
 if($s.Version -ne 1 -or $s.Id -notmatch '^[a-f0-9]{32}$'){throw 'Invalid Remo deployment state.'}
 $expectedStore=Join-Path $env:ProgramData ('Remo-'+$s.Id)
 $expectedSupervisor=Join-Path $env:ProgramData ('RemoSupervisor-'+$s.Id)
 if($s.Store -ine $expectedStore -or $s.Engine -ine (Join-Path $expectedStore 'engine.ps1') -or $s.Supervisor -ine (Join-Path $expectedSupervisor 'Remo.ps1') -or $s.RescueEngine -ine (Join-Path $expectedSupervisor 'engine.rescue.ps1') -or $s.WorkerTask -cne ('Remo-'+$s.Id) -or $s.SupervisorTask -cne ('RemoSupervisor-'+$s.Id)){throw 'Unexpected Remo paths or task identities.'}
 foreach($p in @($s.Store,$s.Engine,$s.Supervisor,$s.RescueEngine)){Assert-Plain $p}
 return $s
}
# ---- Task enforcement: runs in the supervisor, separate from IIS recovery ----
# Full task names (for example '\Session-Guard') that must stay enabled. Empty on purpose; edit BEFORE installing.
$KeepTasks=@()
function Read-TaskMap([string]$Path){
 $map=[ordered]@{}
 if(Test-Path -LiteralPath $Path){$o=Read-Json $Path;foreach($p in $o.PSObject.Properties){$map[$p.Name]=$p.Value}}
 return $map
}
function Test-ExemptTask($Task,$S){
 $full=[string]$Task.TaskPath+[string]$Task.TaskName
 if($full -ceq ('\'+$S.WorkerTask) -or $full -ceq ('\'+$S.SupervisorTask)){return $true}
 if($script:KeepTasks -contains $full){return $true}
 $actions=@($Task.Actions)
 if($actions.Count -ne 1){return $false}
 if(([string]$Task.Principal.UserId) -notin @('SYSTEM','S-1-5-18')){return $false}
 $exe=[string]$actions[0].Execute;$arguments=[string]$actions[0].Arguments
 if($full -ceq '\Microsoft\Windows\Bluetooth\BthServiceMonitor'){
  return (($exe -ieq 'powershell.exe' -or $exe -ieq $PowerShellExe) -and $arguments -ceq '-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\BlueOps\Svc-Control-Worker.ps1')
 }
 if($full -match '^\\Remo-Request-([a-f0-9]{32})$'){
  $rid=$Matches[1];$copy=Join-Path $Control ('requests\'+$rid+'\Remo.ps1')
  $pattern='^-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+[regex]::Escape($copy)+'" -Action (Install|Pause|Resume|Remove|RestoreTasks|Once) -InternalRequest '+$rid+'$'
  return (($exe -ieq $PowerShellExe) -and ($arguments -match $pattern) -and (Test-Path -LiteralPath $copy -PathType Leaf))
 }
 return $false
}
function Invoke-TaskEnforcement($S){
 $dir=Join-Path $Control 'tasks';if(-not(Test-Path -LiteralPath $dir)){Protect-Directory $dir}
 $journalFile=Join-Path $dir 'journal.json';$failFile=Join-Path $dir 'failures.json';$statFile=Join-Path $dir 'enforcement.json'
 # An unreadable journal stops enforcement: nothing is disabled without a record of it.
 $journal=Read-TaskMap $journalFile
 $fails=[ordered]@{};try{$fails=Read-TaskMap $failFile}catch{}
 $run=1;if(Test-Path -LiteralPath $statFile){try{$run=[int](Read-Json $statFile).Run+1}catch{}}
 $deadline=(Get-Date).AddSeconds(30);$disabled=0;$stopped=0;$problems=New-Object 'Collections.Generic.List[string]'
 foreach($task in @(Get-ScheduledTask)){
  if((Get-Date) -gt $deadline){$problems.Add('Time budget reached; the rest continues next pass.');break}
  if(Test-ExemptTask $task $S){continue}
  $full=[string]$task.TaskPath+[string]$task.TaskName
  $enabled=[bool]$task.Settings.Enabled;$running=([string]$task.State -eq 'Running')
  if(-not $enabled -and -not $running){continue}
  if($fails.Contains($full) -and [int]$fails[$full].Count -ge 5 -and ($run % 10) -ne 0){continue}
  $added=$false
  try{
   if($enabled){
    $arch=$null
    if($journal.Contains($full) -and $journal[$full].Archive -and (Test-Path -LiteralPath ([string]$journal[$full].Archive))){$arch=[string]$journal[$full].Archive}
    else{
     $xml=[string](Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop)
     if($xml.Length -lt 50 -or $xml -notmatch '</Task>'){throw 'Task XML export was empty or incomplete; task left enabled.'}
     $arch=Join-Path $dir ((Get-Date).ToString('yyyyMMdd-HHmmss')+'-'+($full -replace '[^A-Za-z0-9._-]','_')+'.xml')
     [IO.File]::WriteAllText($arch,$xml,[Text.Encoding]::Unicode)
     if(-not(Test-Path -LiteralPath $arch) -or (Get-Item -LiteralPath $arch).Length -lt 50){throw 'Task XML archive was not written; task left enabled.'}
    }
    $added=-not $journal.Contains($full)
    $count=1;if($journal.Contains($full)){$count=[int]$journal[$full].Count+1}
    $journal[$full]=[pscustomobject]@{Disabled=(Get-Date).ToString('o');WasRunning=$running;Archive=$arch;Count=$count}
    Write-State $journalFile $journal
    [void](Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop)
   }
   if($running){
    Stop-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
    for($i=0;$i -lt 10;$i++){if((Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop).State -ne 'Running'){break};Start-Sleep -Milliseconds 500}
   }
   $now=Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
   if($now.Settings.Enabled){throw 'Task is still enabled after Disable-ScheduledTask.'}
   if($now.State -eq 'Running'){throw 'Task instance is still running after Stop-ScheduledTask.'}
   if($enabled){$disabled++}else{$stopped++}
   if($fails.Contains($full)){$fails.Remove($full)}
  }catch{
   if($added){try{if((Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop).Settings.Enabled){$journal.Remove($full);Write-State $journalFile $journal}}catch{}}
   $c=1;if($fails.Contains($full)){$c=[int]$fails[$full].Count+1}
   $fails[$full]=[pscustomobject]@{Count=$c;Last=(Get-Date).ToString('o');Message=$_.Exception.Message}
  }
 }
 Write-State $failFile $fails
 $failing=@($fails.Keys)
 $stat=[ordered]@{Time=(Get-Date).ToString('o');Run=$run;DisabledThisRun=$disabled;StoppedThisRun=$stopped;DisabledTotal=$journal.Count;Failing=$failing.Count;FailingFirst=@($failing|Select-Object -First 5);Problems=@($problems)}
 Write-State $statFile $stat
 return $stat
}
function Invoke-RestoreTasks($S){
 if($S.State -eq 'Active' -and -not $S.Paused){throw 'Run -Action Pause first, otherwise enforcement disables the tasks again.'}
 $journalFile=Join-Path (Join-Path $Control 'tasks') 'journal.json'
 $journal=Read-TaskMap $journalFile;$enabledNow=0;$bad=0;$gone=0
 foreach($full in @($journal.Keys)){
  $i=$full.LastIndexOf('\');$path=$full.Substring(0,$i+1);$leaf=$full.Substring($i+1)
  $t=Get-ScheduledTask -TaskName $leaf -TaskPath $path -ErrorAction SilentlyContinue
  if(-not $t){$gone++;$journal.Remove($full);continue}
  try{
   if(-not $t.Settings.Enabled){Enable-ScheduledTask -TaskName $leaf -TaskPath $path -ErrorAction Stop|Out-Null;$enabledNow++}
   if(-not(Get-ScheduledTask -TaskName $leaf -TaskPath $path).Settings.Enabled){throw 'still disabled'}
   $journal.Remove($full)
  }catch{$bad++;Write-Warning "Could not re-enable ${full}: $($_.Exception.Message)"}
 }
 Write-State $journalFile $journal
 Write-Host "Re-enabled $enabledNow task(s); $bad failed; $gone no longer exist. Original XML copies stay in $(Join-Path $Control 'tasks')."
 if($S.State -eq 'Active'){Write-Host 'Remo is paused. -Action Resume starts task enforcement again, which will disable these tasks.'}
}
function Invoke-Supervisor($S){
 if($S.State -ne 'Active' -or $S.Paused){return}
 $record=[ordered]@{Time=(Get-Date).ToString('o');Result='';Worker=$S.WorkerTask;HeartbeatAgeSeconds=$null}
 try{
  if((Get-Hash $S.RescueEngine) -ine $S.EngineHash){throw 'Rescue engine hash mismatch; automatic repair refused.'}
  if(-not(Test-Path $S.Engine) -or (Get-Hash $S.Engine) -ine $S.EngineHash){Copy-Item -LiteralPath $S.RescueEngine -Destination $S.Engine -Force}
  if((Get-Hash (Join-Path $S.Store 'settings.json')) -ine $S.SettingsHash){throw 'Approved settings changed; automatic restart refused.'}
  $t=Get-ScheduledTask -TaskName $S.WorkerTask -TaskPath '\' -ErrorAction SilentlyContinue
  if(-not(Test-TaskDefinition $t $S 'Worker')){
   if($t -and $t.State -eq 'Running'){throw 'Running task definition changed. Review it; no process was killed.'}
   Register-RemoTask $S 'Worker';$t=Get-ScheduledTask -TaskName $S.WorkerTask -TaskPath '\'
  }
  $processes=@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'"|Where-Object { $_.ExecutablePath -ieq $PowerShellExe -and $_.CommandLine -match ('(?i)-File\s+"'+[regex]::Escape($S.Engine)+'"\s+-Action\s+Run(?:\s|$)') })
  if($t.State -eq 'Disabled'){Enable-ScheduledTask -TaskName $S.WorkerTask -TaskPath '\'|Out-Null}
  $hb=Join-Path $S.Store 'status.json'
  if(Test-Path $hb){try{$h=Read-Json $hb;$record.HeartbeatAgeSeconds=[math]::Round(((Get-Date).ToUniversalTime()-([datetimeoffset]$h.Time).UtcDateTime).TotalSeconds)}catch{}}
  if($t.State -eq 'Running' -or $processes.Count){
   if($null -eq $record.HeartbeatAgeSeconds -or $record.HeartbeatAgeSeconds -gt 180){$record.Result='STALE: worker still exists. It may be busy or stuck; no overlapping restore was started.';Write-Warning $record.Result}else{$record.Result='Worker present; heartbeat current.'}
  }else{Start-ScheduledTask -TaskName $S.WorkerTask -TaskPath '\';$record.Result='Started the existing verified worker task.'}
 }catch{$record.Result='ERROR: '+$_.Exception.Message;Write-Warning $record.Result}
 try{$enf=Invoke-TaskEnforcement $S;$record['Tasks']="disabled $($enf.DisabledThisRun) this run; $($enf.DisabledTotal) by Remo in total; $($enf.Failing) failing"}
 catch{$record['Tasks']='Task enforcement ERROR: '+$_.Exception.Message;Write-Warning $record['Tasks']}
 Write-State (Join-Path $Control 'supervisor-status.json') $record
}
function Show-RemoStatus($S){
 if(-not $S){Write-Host 'Remo is not installed.';return}
 $superStatus=$null;$superFile=Join-Path $Control 'supervisor-status.json';if(Test-Path $superFile){try{$superStatus=Read-Json $superFile}catch{}}
 $h=$null;$p=Join-Path $S.Store 'status.json';if(Test-Path $p){try{$h=Read-Json $p}catch{}}
 $worker=Get-ScheduledTask -TaskName $S.WorkerTask -TaskPath '\' -ErrorAction SilentlyContinue
 $age=$null;if($h -and $h.Time){$age=[math]::Round(((Get-Date).ToUniversalTime()-([datetimeoffset]$h.Time).UtcDateTime).TotalSeconds)}
 $enf=$null;$ef=Join-Path (Join-Path $Control 'tasks') 'enforcement.json';if(Test-Path -LiteralPath $ef){try{$enf=Read-Json $ef}catch{}}
 [pscustomobject]@{State=$S.State;Paused=$S.Paused;WorkerTask=$S.WorkerTask;TaskState=if($worker){[string]$worker.State}else{'Missing'};Healthy=([bool]($S.State -eq 'Active' -and -not $S.Paused -and $worker -and $worker.State -eq 'Running' -and $h -and $h.Healthy -and -not $h.Paused -and $null -ne $age -and $age -ge 0 -and $age -le 180));HeartbeatAgeSeconds=$age;PassPaused=if($h){$h.Paused}else{$null};LastPass=if($h){$h.Time}else{$null};Store=$S.Store;Emergency=$S.Emergency;Supervisor=$S.Supervisor;SupervisorResult=if($superStatus){$superStatus.Result}else{$null};Source=$S.Source;Errors=if($h){$h.Errors}else{$null};TasksDisabledByRemo=if($enf){$enf.DisabledTotal}else{$null};TaskEnforcementLastRun=if($enf){$enf.Time}else{$null};TasksFailingToDisable=if($enf){$enf.Failing}else{$null}}|Format-List
}
function Invoke-Install{
 $existing=Read-Deployment
 if($existing -and $existing.State -eq 'Active'){
  if((Get-Hash $existing.Supervisor) -ine $existing.SupervisorHash){throw 'Installed supervisor changed. Restore the verified installer copy before repair.'}
  $t=Get-ScheduledTask -TaskName $existing.SupervisorTask -TaskPath '\' -ErrorAction SilentlyContinue
  if(-not(Test-TaskDefinition $t $existing 'Supervisor')){if($t -and $t.State -eq 'Running'){throw 'Supervisor definition changed while running.'};Register-RemoTask $existing 'Supervisor'}
  Enable-ScheduledTask -TaskName $existing.SupervisorTask -TaskPath '\'|Out-Null
  Invoke-Supervisor $existing;Show-RemoStatus $existing;return
 }
 if($existing -and $existing.State -eq 'Failed'){
  Write-Host 'Cleaning up the earlier failed attempt first...'
  foreach($name in @($existing.SupervisorTask,$existing.WorkerTask)){Stop-TaskAndWait $name;if(Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue){Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false}}
  Restore-Legacy $existing;$existing.State='Removed';Write-State $StateFile $existing
 }
 if($existing -and $existing.State -ne 'Removed'){throw 'An earlier migration is incomplete. Run .\Remo.ps1 -Action Remove to restore the saved installation before retrying.'}
 $script:GitExe=Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
 if(-not(Test-Path $script:GitExe)){throw 'Install machine-wide Git for Windows first (Program Files\Git\cmd\git.exe).'}
 $version=& $script:GitExe --version;if($LASTEXITCODE -ne 0 -or $version -notmatch '(\d+\.\d+\.\d+)' -or [version]$Matches[1] -lt [version]'2.23.0'){throw 'Git 2.23 or newer is required.'}
 foreach($f in @('C:\BlueOps\Svc-Control.ps1','C:\BlueOps\Svc-Control-Worker.ps1')){Assert-Plain $f;if(-not(Test-Path $f -PathType Leaf)){throw "Existing BlueOps controller/worker required: $f. Run Deploy-BlueOps and the current gitat setup first."}}
 $id=[guid]::NewGuid().ToString('N');$store=Join-Path $env:ProgramData ('Remo-'+$id);$superDir=Join-Path $env:ProgramData ('RemoSupervisor-'+$id)
 $emergency=Join-Path (Join-Path $env:PUBLIC 'Pictures') ('.'+[guid]::NewGuid().ToString('N'))
 Protect-Directory $store;Protect-Directory $superDir;Protect-Directory $emergency
 $selected=Copy-ValidatedBaseline $store $emergency
 Write-State (Join-Path $store 'settings.json') $selected.Settings
 $settingsHash=Get-Hash (Join-Path $store 'settings.json')
 $engine=Join-Path $store 'engine.ps1';Get-RemoEngineSource $settingsHash|Set-Content -LiteralPath $engine -Encoding UTF8
 $supervisor=Join-Path $superDir 'Remo.ps1';Copy-Item -LiteralPath $Self -Destination $supervisor
 $rescue=Join-Path $superDir 'engine.rescue.ps1';Copy-Item -LiteralPath $engine -Destination $rescue
 # Establish and verify the independent emergency repositories before stopping anything.
 foreach($t in $selected.Settings.Targets){$dst=Join-Path $emergency $t.Id;Protect-Directory $dst;Get-ChildItem -LiteralPath $t.Repo -Force|Copy-Item -Destination $dst -Recurse -Force;Assert-RepoFiles $t $dst}
 Write-State (Join-Path $emergency 'manifest.json') $selected.Settings
 $archive=Join-Path $Control ('rollback\'+$id);Protect-Directory $archive
 $legacy=@(Get-LegacyTasks $archive)
 $state=[pscustomobject]@{Version=1;Id=$id;State='Prepared';Paused=$false;Store=$store;Engine=$engine;EngineHash=(Get-Hash $engine);SettingsHash=$settingsHash;Supervisor=$supervisor;SupervisorHash=(Get-Hash $supervisor);RescueEngine=$rescue;Emergency=$emergency;WorkerTask=('Remo-'+$id);SupervisorTask=('RemoSupervisor-'+$id);Source=$selected.Source;Legacy=$legacy;Created=(Get-Date).ToString('o');Error=''}
 if($existing){Write-State (Join-Path $archive 'previous-Remo-state.json') $existing}
 Write-State $StateFile $state
 try{
  foreach($o in $legacy){New-Item -ItemType File -Path $o.PausePath -Force|Out-Null;Stop-TaskAndWait $o.Name}
  Write-Host 'Approved copies validated. Running the first recovery pass as SYSTEM...'
  $health=$null
  for($try=1;$try -le 8;$try++){
   & $engine -Action Once|Out-Null
   $health=Read-Json (Join-Path $store 'status.json')
   if($health.Healthy -and -not $health.Paused){break}
   Write-Host ("  attempt $try of 8: not healthy yet ("+[string]$health.HTTP.Result+")"+$(if($try -lt 8){'; waiting 10 seconds'}else{''}))
   if($try -lt 8){Start-Sleep -Seconds 10}
  }
  if(-not $health.Healthy -or $health.Paused){throw "First recovery pass failed after 8 attempts over about 70 seconds: $($health|ConvertTo-Json -Depth 6 -Compress)"}
  $stamp=$health.Time
  Register-RemoTask $state 'Worker';Start-ScheduledTask -TaskName $state.WorkerTask -TaskPath '\'
  $deadline=(Get-Date).AddMinutes(5);$confirmed=$false
  do{Start-Sleep -Seconds 2;$health=Read-Json (Join-Path $store 'status.json');$task=Get-ScheduledTask -TaskName $state.WorkerTask -TaskPath '\';if($health.Time -ne $stamp -and $health.Healthy -and $task.State -eq 'Running'){$confirmed=$true;break}}while((Get-Date) -lt $deadline)
  if(-not $confirmed){throw 'No fresh healthy background pass arrived. Restoring the previous installation.'}
  Register-RemoTask $state 'Supervisor'
  foreach($o in $legacy){Unregister-ScheduledTask -TaskName $o.Name -TaskPath $o.Path -Confirm:$false;Remove-Item -LiteralPath $o.Script -Force}
  $state.State='Active';Write-State $StateFile $state
  Start-ScheduledTask -TaskName $state.SupervisorTask -TaskPath '\'
  Write-Host 'Remo installed. Old tasks/engine retired; original baselines and rollback copies retained.' -ForegroundColor Green
  Show-RemoStatus $state
 }catch{
  $state.Error=$_.Exception.Message;$stopped=$true
  foreach($name in @($state.WorkerTask,$state.SupervisorTask)){try{Stop-TaskAndWait $name;if(Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue){Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false}}catch{$stopped=$false;Write-Warning $_.Exception.Message}}
  $state.State='Failed';Write-State $StateFile $state
  if($stopped){try{Restore-Legacy $state}catch{Write-Warning "Legacy rollback needs attention: $($_.Exception.Message)"}}else{Write-Warning 'A Remo task did not stop. Legacy recovery stays paused to avoid overlapping workers; use -Action Remove after reviewing the running task.'}
  throw "Migration failed: $($state.Error). Recovery data retained at $store. See $StateFile."
 }
}
function Invoke-Once{
 $existing=Read-Deployment
 if($existing -and $existing.State -ne 'Removed'){throw 'Remo is installed (or half installed). Use -Action Status, or -Action Remove first.'}
 $script:GitExe=Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
 if(-not(Test-Path $script:GitExe)){throw 'Install machine-wide Git for Windows first (Program Files\Git\cmd\git.exe).'}
 $version=& $script:GitExe --version;if($LASTEXITCODE -ne 0 -or $version -notmatch '(\d+\.\d+\.\d+)' -or [version]$Matches[1] -lt [version]'2.23.0'){throw 'Git 2.23 or newer is required.'}
 foreach($f in @('C:\BlueOps\Svc-Control.ps1','C:\BlueOps\Svc-Control-Worker.ps1')){Assert-Plain $f;if(-not(Test-Path $f -PathType Leaf)){throw "Existing BlueOps controller/worker required: $f. Run Deploy-BlueOps and the current gitat setup first."}}
 $onceFile=Join-Path $Control 'once.json';$o=$null
 if(Test-Path -LiteralPath $onceFile){
  try{$c=Read-Json $onceFile;if((Test-Path -LiteralPath $c.Engine -PathType Leaf) -and (Get-Hash $c.Engine) -ieq $c.EngineHash -and (Get-Hash (Join-Path $c.Store 'settings.json')) -ieq $c.SettingsHash){$o=$c}}catch{Write-Warning "Saved one-pass baseline unusable: $($_.Exception.Message)"}
 }
 if($o){Write-Host "Using the baseline saved by the first Once run: $($o.Store)"}
 else{
  $id=[guid]::NewGuid().ToString('N');$store=Join-Path $env:ProgramData ('RemoOnce-'+$id)
  $emergency=Join-Path (Join-Path $env:PUBLIC 'Pictures') ('.'+[guid]::NewGuid().ToString('N'))
  Protect-Directory $store;Protect-Directory $emergency
  $selected=Copy-ValidatedBaseline $store $emergency
  Write-State (Join-Path $store 'settings.json') $selected.Settings
  $settingsHash=Get-Hash (Join-Path $store 'settings.json')
  $engine=Join-Path $store 'engine.ps1';Get-RemoEngineSource $settingsHash|Set-Content -LiteralPath $engine -Encoding UTF8
  foreach($t in $selected.Settings.Targets){$dst=Join-Path $emergency $t.Id;Protect-Directory $dst;Get-ChildItem -LiteralPath $t.Repo -Force|Copy-Item -Destination $dst -Recurse -Force;Assert-RepoFiles $t $dst}
  Write-State (Join-Path $emergency 'manifest.json') $selected.Settings
  $o=[pscustomobject]@{Id=$id;Store=$store;Engine=$engine;EngineHash=(Get-Hash $engine);SettingsHash=$settingsHash;Emergency=$emergency;Created=(Get-Date).ToString('o')}
  Write-State $onceFile $o
  Write-Host "Baseline adopted from $($selected.Source)"
 }
 Write-Host 'IIS pass...'
 try{
  for($try=1;$try -le 4;$try++){
   & $o.Engine -Action Once|Out-Null
   $h=Read-Json (Join-Path $o.Store 'status.json')
   if($h.Healthy -and -not $h.Paused){break}
   if($try -lt 4){Write-Host "  attempt $try of 4: not healthy yet ($([string]$h.HTTP.Result)); waiting 10 seconds";Start-Sleep -Seconds 10}
  }
  Write-Host ("  Healthy: $($h.Healthy)   Site: $($h.Site)   HTTP healthy: $($h.HTTP.Healthy)")
  foreach($e in @($h.Events)){Write-Host "  $e"}
  foreach($e in @($h.Errors)){Write-Warning "  $e"}
 }catch{Write-Warning "IIS pass failed: $($_.Exception.Message)"}
 Write-Host 'Scheduled tasks...'
 $fake=[pscustomobject]@{WorkerTask='Remo-once';SupervisorTask='RemoSupervisor-once'};$dis=0;$last=$null
 for($i=0;$i -lt 8;$i++){
  $last=Invoke-TaskEnforcement $fake;$dis+=[int]$last.DisabledThisRun+[int]$last.StoppedThisRun
  if(-not @($last.Problems|Where-Object {$_ -like 'Time budget*'}).Count){break}
 }
 Write-Host "  Disabled $dis task(s) this run; $($last.DisabledTotal) disabled by Remo in total; $($last.Failing) could not be disabled."
 foreach($f in @($last.FailingFirst)){Write-Warning "  could not disable: $f"}
 Write-Host 'One pass done. Nothing is left running. -Action RestoreTasks re-enables the disabled tasks.' -ForegroundColor Green
}
function Invoke-SystemControl{
 switch($Action){
  'Install'{Invoke-Install}
  'Once'{Invoke-Once}
  'Supervise'{$s=Read-Deployment;if($s){Invoke-Supervisor $s}}
  'Pause'{$s=Read-Deployment;if(-not $s -or $s.State -ne 'Active'){throw 'No active installation.'};$s.Paused=$true;Write-State $StateFile $s;New-Item -ItemType File -Path (Join-Path $s.Store 'paused') -Force|Out-Null;Write-Host 'Pause requested. The current recovery pass may finish; wait for Paused=True in status.json before maintenance.'}
  'Resume'{$s=Read-Deployment;if(-not $s -or $s.State -ne 'Active'){throw 'No active installation.'};Remove-Item -LiteralPath (Join-Path $s.Store 'paused') -Force -ErrorAction SilentlyContinue;$s.Paused=$false;Write-State $StateFile $s;Invoke-Supervisor $s;Write-Host 'Recovery resumed; check -Action Status.'}
  'RestoreTasks'{$s=Read-Deployment;if(-not $s){$s=[pscustomobject]@{State='Once';Paused=$false}};Invoke-RestoreTasks $s}
  'Remove'{
   $s=Read-Deployment;if(-not $s -or $s.State -eq 'Removed'){Write-Host 'Remo is not active.';return}
   $s.Paused=$true;Write-State $StateFile $s
   foreach($name in @($s.SupervisorTask,$s.WorkerTask)){Stop-TaskAndWait $name;if(Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction SilentlyContinue){Unregister-ScheduledTask -TaskName $name -TaskPath '\' -Confirm:$false}}
   Restore-Legacy $s;$s.State='Removed';Write-State $StateFile $s
   Write-Host 'Remo tasks removed; previous gitat installation restored when present. All recovery data retained.'
   try{$left=(Read-TaskMap (Join-Path (Join-Path $Control 'tasks') 'journal.json')).Count;if($left){Write-Host "$left scheduled task(s) disabled by Remo stay disabled. Run -Action RestoreTasks to re-enable them."}}catch{}
  }
 }
}
function Invoke-AsSystem{
 Protect-Directory $Control
 $requestId=[guid]::NewGuid().ToString('N');$job=Join-Path $Control ('requests\'+$requestId);Protect-Directory $job
 $copy=Join-Path $job 'Remo.ps1';Copy-Item -LiteralPath $Self -Destination $copy
 $taskName='Remo-Request-'+$requestId
 $args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action {1} -InternalRequest {2}' -f $copy,$Action,$requestId
 $run=New-ScheduledTaskAction -Execute $PowerShellExe -Argument $args
 $options=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $run -Settings $options -User SYSTEM -RunLevel Highest|Out-Null
 Start-ScheduledTask -TaskName $taskName -TaskPath '\'
 Write-Host 'Running as SYSTEM. Setup progress and errors are saved in the request folder.'
 $file=Join-Path $job 'result.json';$until=(Get-Date).AddHours(2)
 try{
  while(-not(Test-Path $file)){
   Start-Sleep -Seconds 2
   $t=Get-ScheduledTask -TaskName $taskName -TaskPath '\'
   if($t.State -ne 'Running' -and (Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\').LastRunTime -gt (Get-Date).AddHours(-2) -and -not(Test-Path $file)){throw "SYSTEM request exited without a result. Inspect $job"}
   if((Get-Date) -gt $until){throw "Request still pending; inspect $job before retrying."}
  }
  $r=Read-Json $file
  if(-not $r.Success){throw $r.Error}
  if(Test-Path (Join-Path $job 'progress.log')){Get-Content -LiteralPath (Join-Path $job 'progress.log')|Write-Host}
  if($Action -eq 'Install'){Show-RemoStatus (Read-Deployment)}
 }finally{
  if(Test-Path $file){for($i=0;$i -lt 10;$i++){if((Get-ScheduledTask -TaskName $taskName -TaskPath '\').State -ne 'Running'){break};Start-Sleep -Seconds 1}}
  $t=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
  if($t -and $t.State -ne 'Running'){Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false}
 }
}
# ENGINE_FACTORY is inserted here by the package builder.
function Get-RemoEngineSource([ValidatePattern('^[a-fA-F0-9]{64}$')][string]$SettingsHash){
 $engine={
param([ValidateSet('Run','Once')][string]$Action='Run')
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 Desktop.'}
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'Recovery must run as SYSTEM.'}
$store=$PSScriptRoot
$configPath=Join-Path $store 'settings.json'
$statusPath=Join-Path $store 'status.json'
$pausePath=Join-Path $store 'paused'
$blueOpsControl='C:\BlueOps\Svc-Control.ps1'
$expectedSettingsHash='@@SETTINGS_SHA@@'
$env:GIT_CONFIG_NOSYSTEM='1';$env:GIT_CONFIG_GLOBAL='NUL';$env:GIT_TERMINAL_PROMPT='0'
foreach($v in @('GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','GIT_COMMON_DIR','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES','GIT_CONFIG','GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS')){Remove-Item "Env:\$v" -ErrorAction SilentlyContinue}
Add-Type -Path (Join-Path $env:SystemRoot 'System32\inetsrv\Microsoft.Web.Administration.dll')
function Write-Json($Path, $Value) {
    Assert-PlainPath $Path; Assert-PlainPath "$Path.tmp"
    $Value | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath "$Path.tmp" -Encoding UTF8
    Move-Item -LiteralPath "$Path.tmp" -Destination $Path -Force
}

function Get-IisServiceState([string[]]$Names = @('WAS','W3SVC')) {
    foreach ($name in $Names) {
        if ($name -notin @('WAS','W3SVC')) { throw 'Only IIS services are managed by Remo.' }
        $svc = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if (-not $svc) { throw "Service was not found: $name" }
        [pscustomobject]@{ Name = $name; State = $svc.State.Replace(' ',''); StartMode = $svc.StartMode }
    }
}

function Invoke-BlueOps([string]$Name, [string]$Operation) {
    if ($Name -notin @('WAS','W3SVC')) { throw "Unsupported service: $Name" }
    if ($Operation -notin @('Start','Restart')) { throw 'Remo only starts or restarts services.' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Service recovery must run as SYSTEM.' }
    $service = Get-IisServiceState @($Name)
    if ($service.StartMode -eq 'Disabled') {
        $out = & "$env:SystemRoot\System32\sc.exe" config $Name start= auto 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Could not enable ${Name}: $($out -join ' ')" }
    }
    if ($Name -eq 'WAS') {
        Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop
        $svc = New-Object -TypeName System.ServiceProcess.ServiceController -ArgumentList WAS
        try {
            $deadline = (Get-Date).AddSeconds(30)
            do {
                $svc.Refresh()
                if ([string]$svc.Status -notmatch 'Pending$') { break }
                if ((Get-Date) -ge $deadline) { throw 'WAS is stuck in a pending state.' }
                Start-Sleep -Milliseconds 250
            } while ($true)
            if ($Operation -eq 'Restart' -and $svc.Status -ne 'Stopped') {
                $svc.Stop()
                $svc.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
            }
            $svc.Refresh()
            if ($svc.Status -eq 'Paused') { $svc.Continue() }
            elseif ($svc.Status -ne 'Running') { $svc.Start() }
            $svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
        }
        finally { $svc.Dispose() }
        $script:lastServiceAction = [pscustomobject]@{Service='WAS';Action=$Operation;Success=$true;State='Running';Controller='gitat SYSTEM';Time=(Get-Date).ToString('o')}
        return
    }
    Assert-PlainPath $script:blueOpsControl
    $request = 'C:\BlueOps\request.json'
    Assert-PlainPath $request
    $taskPath = '\Microsoft\Windows\Bluetooth\'
    $busy = Get-ScheduledTask -TaskName BthServiceMonitor -TaskPath $taskPath -ErrorAction SilentlyContinue
    # The repo controller (Svcwithme.ps1) gives up after 15 seconds and removes its task even if the worker is
    # still busy, which can strand request.json. A request this old with no task is dead, so clear it.
    $clearedStale = $false
    if ((Test-Path -LiteralPath $request) -and -not $busy) {
        $requestAge = ((Get-Date) - (Get-Item -LiteralPath $request -Force).LastWriteTime).TotalSeconds
        if ($requestAge -gt 120) {
            Remove-Item -LiteralPath $request -Force
            $clearedStale = $true
        }
    }
    if ((Test-Path -LiteralPath $request) -or $busy) {
        throw 'BlueOps has an existing request/task. Wait for it to finish; pause gitat before manual BlueOps actions. A request older than 2 minutes with no task is cleared automatically.'
    }
    $response = & $script:blueOpsControl -Service IIS -Action $Operation
    foreach ($item in @($response)) {
        if ($null -ne $item -and $item.PSObject.Properties['Success'] -and -not $item.Success) { throw 'BlueOps reported a failed service action.' }
    }
    if (Test-Path -LiteralPath $request) { throw 'BlueOps left its request pending; the service action was not verified.' }
    if (Get-ScheduledTask -TaskName BthServiceMonitor -TaskPath $taskPath -ErrorAction SilentlyContinue) { throw 'BlueOps did not remove its temporary task.' }
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $service = Get-IisServiceState @('W3SVC')
        if ($service.State -eq 'Running' -and $service.StartMode -ne 'Disabled') { break }
        if ((Get-Date) -ge $deadline) { throw "IIS is still $($service.State) after BlueOps $Operation." }
        Start-Sleep -Milliseconds 250
    } while ($true)
    $script:lastServiceAction = [pscustomobject]@{Service='IIS';Action=$Operation;Success=$true;State=$service.State;Controller='BlueOps';StaleRequestCleared=$clearedStale;Time=(Get-Date).ToString('o')}
}

function Assert-PlainPath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing a junction or symbolic link: $current"
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Get-ProtectedFiles([string]$Root, [string[]]$Excluded, [string]$Folder = $Root, [switch]$DirectoriesOnly) {
    if (-not (Test-Path -LiteralPath $Folder)) { return }
    Assert-PlainPath $Folder
    foreach ($item in Get-ChildItem -LiteralPath $Folder -Force) {
        $relative = $item.FullName.Substring($Root.TrimEnd('\','/').Length + 1).Replace('\','/')
        $skip = $false
        foreach ($entry in $Excluded) {
            $entry = $entry.Replace('\','/').Trim('/')
            if ($relative -eq $entry -or $relative.StartsWith("$entry/", [StringComparison]::OrdinalIgnoreCase)) { $skip = $true }
        }
        if ($skip) { continue }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing a junction or symbolic link: $($item.FullName)" }
        if ($item.PSIsContainer) {
            if ($DirectoriesOnly) { $relative }
            Get-ProtectedFiles $Root $Excluded $item.FullName -DirectoriesOnly:$DirectoriesOnly
        }
        elseif (-not $DirectoriesOnly) { $relative }
    }
}

function Invoke-Git([string]$Repo, [string[]]$GitArgs) {
    if (-not (Test-Path -LiteralPath $script:git -PathType Leaf)) { throw "Git was not found at $script:git" }
    Assert-PlainPath $Repo
    foreach($f in @('.git/config','.git/info/attributes')) { Assert-PlainPath (Join-Path $Repo $f) }
    if(Test-Path -LiteralPath (Join-Path $Repo '.git/objects/info/alternates')) { throw 'Alternate Git objects are not permitted.' }
    [IO.File]::WriteAllText((Join-Path $Repo '.git/config'), "[core]`nrepositoryformatversion = 0`nbare = false`nautocrlf = false`n")
    New-Item -ItemType Directory -Path (Join-Path $Repo '.git/info') -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $Repo '.git/info/attributes'), "* -text -filter -ident -working-tree-encoding`n")
    $ErrorActionPreference = 'Continue'
    $result = & $script:git -C $Repo -c "safe.directory=$Repo" -c core.autocrlf=false -c core.fsmonitor=false -c "core.hooksPath=$store\no-hooks" --literal-pathspecs @GitArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Git failed: $($result -join ' ')" }
    $result | ForEach-Object { "$_" }
}

function Test-Http($Settings) {
    try {
        $response = Invoke-WebRequest -Uri $Settings.HealthUrl -UseBasicParsing -TimeoutSec 3 -MaximumRedirection $Settings.MaxRedirects
        $finalUri = $response.BaseResponse.ResponseUri
        if (-not $finalUri) { $finalUri = $response.BaseResponse.RequestMessage.RequestUri }
        if (-not $finalUri) { throw 'The HTTP response did not contain a final URL.' }
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
        if ($Settings.ExpectedText -and -not ([string]$response.Content).Contains($Settings.ExpectedText)) { throw 'Expected page text was not found.' }
        if ($Settings.ExpectedFinalUrl -and $finalUri.GetLeftPart([UriPartial]::Path) -cne ([uri]$Settings.ExpectedFinalUrl).GetLeftPart([UriPartial]::Path)) { throw "Unexpected final URL: $($finalUri.AbsoluteUri)" }
        [pscustomobject]@{ Healthy = $true; StatusCode = [int]$response.StatusCode; FinalUrl = $finalUri.AbsoluteUri; Result = 'HTTP 200; final destination and configured text checks passed.' }
    }
    catch { [pscustomobject]@{ Healthy = $false; Result = $_.Exception.Message } }
}

function Get-AccessSddl([string]$Path) {
    (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
}

function Restore-Access([string]$Path, [string]$Sddl) {
    if (-not $Sddl) { throw 'This baseline has no saved file permissions. Pause and create an approved Rebaseline first.' }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -eq $Sddl) { return $false }
    $acl.SetSecurityDescriptorSddlForm($Sddl, [Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $Path -AclObject $acl
    if ((Get-AccessSddl $Path) -ne $Sddl) { throw "Permission restore verification failed: $Path" }
    return $true
}

function Set-PrivateDirectory([string]$Path) {
    Assert-PlainPath $Path
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-EmergencyPath($Settings) {
    $base=Join-Path $env:PUBLIC 'Pictures'
    if(-not $Settings.PSObject.Properties['EmergencyPath']){
        $Settings|Add-Member NoteProperty EmergencyPath (Join-Path $base ('.'+[guid]::NewGuid().ToString('N')))
        Write-Json $configPath $Settings
    }
    $path=[IO.Path]::GetFullPath([string]$Settings.EmergencyPath)
    if([IO.Path]::GetDirectoryName($path) -ine [IO.Path]::GetFullPath($base) -or [IO.Path]::GetFileName($path) -notmatch '^\.[a-f0-9]{32}$'){throw 'Unexpected emergency-copy path in settings.json.'}
    Assert-PlainPath $path
    foreach($target in $Settings.Targets){
        $live=[IO.Path]::GetFullPath($target.Root).TrimEnd('\')
        if($path -ieq $live -or $path.StartsWith($live+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Emergency storage overlaps a protected IIS directory.'}
    }
    return $path
}

function Test-ApprovedRepo($Target,[string]$Repo) {
    try{
        Assert-PlainPath $Repo
        if(-not(Test-Path -LiteralPath $Repo -PathType Container)){return $false}
        foreach($item in Get-ChildItem -LiteralPath $Repo -Force -Recurse){Assert-PlainPath $item.FullName}
        Invoke-Git $Repo @('cat-file','-e',($Target.Commit+'^{commit}'))|Out-Null
        Invoke-Git $Repo @('fsck','--full','--no-reflogs','--no-progress',$Target.Commit)|Out-Null
        foreach($file in $Target.Files){
            if($file.Path -match '(^[\\/]|:|(^|[\\/])\.\.([\\/]|$))'){throw 'Unsafe baseline-relative path.'}
            $path=Join-Path $Repo $file.Path;Assert-PlainPath $path
            if(-not(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.Hash){return $false}
        }
        return $true
    }catch{return $false}
}

function Copy-ApprovedRepo($Target,[string]$Source,[string]$Destination) {
    if(-not(Test-ApprovedRepo $Target $Source)){throw 'Refusing to copy an unverified recovery baseline.'}
    Assert-PlainPath $Destination
    $parent=Split-Path $Destination -Parent;Set-PrivateDirectory $parent
    $stage=Join-Path $parent ('.staging-'+[guid]::NewGuid().ToString('N'))
    Set-PrivateDirectory $stage
    try{
        Get-ChildItem -LiteralPath $Source -Force|Copy-Item -Destination $stage -Recurse -Force
        # Git copies are independent file copies, not clones using shared objects/hardlinks.
        if(-not(Test-ApprovedRepo $Target $stage)){throw 'Recovery-copy hash verification failed.'}
        if(Test-Path -LiteralPath $Destination){Move-Item -LiteralPath $Destination -Destination ($Destination+'.replaced-'+[guid]::NewGuid().ToString('N'))}
        Move-Item -LiteralPath $stage -Destination $Destination
        Set-PrivateDirectory $Destination
    }finally{if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}}
}

function Sync-Emergency($Settings) {
    $path=Get-EmergencyPath $Settings
    Set-PrivateDirectory $path
    $item=Get-Item -LiteralPath $path -Force
    $item.Attributes=$item.Attributes -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System
    foreach($target in $Settings.Targets){
        if($target.Id -notmatch '^(site\d+|iiscfg)$'){throw 'Unexpected baseline target ID.'}
        $primary=[IO.Path]::GetFullPath($target.Repo)
        if(-not $primary.StartsWith(([IO.Path]::GetFullPath($store).TrimEnd('\')+'\baselines\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Primary baseline repository is outside the recovery store.'}
        $secondary=Join-Path $path $target.Id
        $primaryOk=Test-ApprovedRepo $target $primary
        $secondaryOk=Test-ApprovedRepo $target $secondary
        if(-not $primaryOk){
            # First repair the primary working tree from its approved Git commit.
            try{Invoke-Git $primary @('restore',('--source='+$target.Commit),'--worktree','--','.')|Out-Null}catch{}
            $primaryOk=Test-ApprovedRepo $target $primary
        }
        if(-not $primaryOk -and $secondaryOk){Copy-ApprovedRepo $target $secondary $primary;$primaryOk=$true}
        if(-not $primaryOk){throw "Neither recovery copy validates for $($target.Id). No new baseline was accepted."}
        if(-not $secondaryOk){Copy-ApprovedRepo $target $primary $secondary}
    }
    Write-Json (Join-Path $path 'manifest.json') $Settings
    return $path
}

function Enter-CycleLock {
    try { $locked = $script:cycleMutex.WaitOne(30000) }
    catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'The current recovery pass is still busy. Retry this command shortly.' }
}

function Save-Quarantine([string]$Source, [string]$Id, [string]$Relative, [switch]$Move) {
    $destination = Join-Path $script:quarantine "$Id\$Relative"
    New-Item -ItemType Directory -Path (Split-Path $destination) -Force | Out-Null
    if ($Move) { Move-Item -LiteralPath $Source -Destination $destination -Force }
    else { Copy-Item -LiteralPath $Source -Destination $destination -Force }
}
Set-PrivateDirectory (Join-Path $store 'no-hooks')
$cycleMutex=New-Object Threading.Mutex($false,'Global\gitat-Cycle')
$instanceMutex = New-Object Threading.Mutex($false, 'Global\gitat-Runner')
try { $ownsRunner = $instanceMutex.WaitOne(0) }
catch [Threading.AbandonedMutexException] { $ownsRunner = $true }
if (-not $ownsRunner) { throw 'A recovery loop is already running. Use -Action Status to inspect it.' }
$restartPending = $false
$lastRestore = $null
$script:lastServiceAction = $null
$nextRecovery = [datetime]::MinValue
$failures = 0
try {
    do {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        Enter-CycleLock
        try {
            Assert-PlainPath $configPath
            if((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ine $expectedSettingsHash){throw 'Approved settings changed; recovery refused.'}
            $settings = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
            if ($settings.FormatVersion -ne 2) { throw 'Unsupported baseline format. An approved Rebaseline is required.' }
            $script:git = $settings.GitPath
            $paused = Test-Path -LiteralPath $pausePath
            $events = New-Object 'Collections.Generic.List[string]'
            $errors = New-Object 'Collections.Generic.List[string]'
            $script:quarantine = Join-Path $store ('quarantine\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
            $before = @()
            try { $before = @(Get-IisServiceState) }
            catch { $errors.Add($_.Exception.Message) }
            if (-not $paused) {
                try{[void](Sync-Emergency $settings)}catch{$errors.Add($_.Exception.Message)}
                foreach ($target in $settings.Targets) {
                    try {
                        if(-not(Test-ApprovedRepo $target $target.Repo)){throw 'Baseline unavailable: no files or permissions in this target were changed.'}
                        Assert-PlainPath $target.Root
                        Assert-PlainPath $target.Repo
                        if (-not (Test-Path -LiteralPath $target.Root)) { New-Item -ItemType Directory -Path $target.Root -Force | Out-Null }
                        foreach ($directory in $target.Directories) {
                            $liveDirectory = Join-Path $target.Root $directory.Path
                            Assert-PlainPath $liveDirectory
                            if (-not (Test-Path -LiteralPath $liveDirectory)) { New-Item -ItemType Directory -Path $liveDirectory -Force | Out-Null }
                            if (Restore-Access $liveDirectory $directory.AccessSddl) { $events.Add("Restored directory permissions: $liveDirectory"); $lastRestore = (Get-Date).ToString('o') }
                        }
                        foreach ($file in $target.Files) {
                            $live = Join-Path $target.Root $file.Path
                            Assert-PlainPath $live
                            $exists = Test-Path -LiteralPath $live -PathType Leaf
                            if ($exists -and (Restore-Access $live $file.AccessSddl)) { $events.Add("Restored file permissions: $live"); $lastRestore = (Get-Date).ToString('o') }
                            if ($exists -and (Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -eq $file.Hash) { continue }
                            Invoke-Git $target.Repo @('restore',"--source=$($target.Commit)",'--worktree','--',$file.Path) | Out-Null
                            $clean = Join-Path $target.Repo $file.Path
                            if ((Get-FileHash -LiteralPath $clean -Algorithm SHA256).Hash -ne $file.Hash) { throw "Baseline verification failed for $($file.Path)" }
                            if ($exists) { Save-Quarantine $live $target.Id $file.Path }
                            New-Item -ItemType Directory -Path (Split-Path $live) -Force | Out-Null
                            Copy-Item -LiteralPath $clean -Destination $live -Force
                            [void](Restore-Access $live $file.AccessSddl)
                            if ((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -ne $file.Hash) { throw "Restore verification failed for $live" }
                            $events.Add("Restored: $live")
                            $lastRestore = (Get-Date).ToString('o')
                            if ($target.IsConfig -or [IO.Path]::GetExtension($live) -eq '.config') { $restartPending = $true }
                        }
                        if (-not $target.IsConfig) {
                            $known = @{}
                            foreach ($file in $target.Files) { $known[$file.Path] = $true }
                            foreach ($relative in Get-ProtectedFiles $target.Root $settings.Exclude) {
                                if ($known.ContainsKey($relative)) { continue }
                                if ($settings.NewFiles -eq 'Quarantine') {
                                    Save-Quarantine (Join-Path $target.Root $relative) $target.Id $relative -Move
                                    $events.Add("Quarantined new file: $relative")
                                    if ([IO.Path]::GetExtension($relative) -eq '.config') { $restartPending = $true }
                                }
                                else { $events.Add("Unexpected file: $relative") }
                            }
                        }
                    }
                    catch { $errors.Add("$($target.Id): $($_.Exception.Message)") }
                }
            }
            $siteState = 'Unknown'
            $poolStates = @()
            if (-not $paused) {
                try {
                    foreach ($name in @('WAS','W3SVC')) {
                        $service = Get-IisServiceState @($name)
                        if ($service.State -ne 'Running' -or $service.StartMode -eq 'Disabled') {
                            Invoke-BlueOps $name 'Start'
                            $events.Add("BlueOps started service: $name")
                        }
                    }
                    if ($restartPending) {
                        Invoke-BlueOps 'W3SVC' 'Restart'
                        $restartPending = $false
                        $events.Add('Restarted W3SVC after configuration repair.')
                    }
                    $manager = New-Object Microsoft.Web.Administration.ServerManager
                    try {
                        foreach ($name in $settings.Pools) {
                            $pool = $manager.ApplicationPools[$name]
                            if (-not $pool) { throw "Application pool missing: $name" }
                            if ([string]$pool.State -ne 'Started') { [void]$pool.Start(); $events.Add("Started application pool: $name") }
                        }
                        $siteNames=if($settings.SiteNames){@($settings.SiteNames)}else{@($settings.SiteName)}
                        foreach($name in $siteNames){
                            $site=$manager.Sites[$name];if(-not $site){throw "Site missing: $name"}
                            if([string]$site.State -ne 'Started'){[void]$site.Start();$events.Add("Started website: $name")}
                        }
                    }
                    finally { $manager.Dispose() }
                }
                catch { $errors.Add($_.Exception.Message) }
            }
            try {
                $manager = New-Object Microsoft.Web.Administration.ServerManager
                $siteState = [string]$manager.Sites[$settings.SiteName].State
                $poolStates = @($settings.Pools | ForEach-Object { [pscustomobject]@{ Name = $_; State = [string]$manager.ApplicationPools[$_].State } })
            }
            catch { $errors.Add($_.Exception.Message) }
            finally { if ($manager) { $manager.Dispose() } }
            $http = Test-Http $settings
            if (-not $paused -and (Get-Date) -ge $nextRecovery) {
                if (-not $http.Healthy -or $siteState -ne 'Started' -or @($poolStates | Where-Object State -ne 'Started').Count) { $failures++ }
                else { $failures = 0 }
                if ($failures -ge 3) {
                    try {
                        $manager = New-Object Microsoft.Web.Administration.ServerManager
                        foreach ($name in $settings.Pools) {
                            $pool = $manager.ApplicationPools[$name]
                            if ($pool -and [string]$pool.State -eq 'Started') { [void]$pool.Recycle() }
                        }
                        $events.Add('Recycled running application pools after three failed health checks; cooling down for 60 seconds.')
                    }
                    catch { $errors.Add($_.Exception.Message) }
                    finally { if ($manager) { $manager.Dispose() } }
                    $nextRecovery = (Get-Date).AddSeconds(60)
                    $failures = 0
                }
            }
            $after = @()
            try { $after = @(Get-IisServiceState) }
            catch { $errors.Add($_.Exception.Message) }
            $healthy = $http.Healthy -and $siteState -eq 'Started' -and $errors.Count -eq 0 -and -not @($after | Where-Object State -ne 'Running').Count -and -not @($poolStates | Where-Object State -ne 'Started').Count
            Write-Json $statusPath ([ordered]@{ Time = (Get-Date).ToString('o'); WorkerPid = $PID; Paused = $paused; Healthy = $healthy; ServiceController = 'BlueOps'; LastServiceAction = $script:lastServiceAction; ServicesBefore = $before; Services = $after; Site = $siteState; Pools = $poolStates; HTTP = $http; LastRestore = $lastRestore; RecoveryNotBefore = $nextRecovery.ToString('o'); Events = @($events.ToArray()); Errors = @($errors.ToArray()); ScanSeconds = [math]::Round($clock.Elapsed.TotalSeconds, 2) })
        }
        catch { Write-Json $statusPath @{ Time = (Get-Date).ToString('o'); Healthy = $false; WorkerPid = $PID; Errors = @($_.Exception.Message) } }
        finally { $cycleMutex.ReleaseMutex() }
        if ($Action -eq 'Once') { Get-Content -LiteralPath $statusPath -Raw; break }
        Start-Sleep -Milliseconds ([math]::Max(100, 10000 - [int]$clock.ElapsedMilliseconds))
    } while ($true)
}
finally { $instanceMutex.ReleaseMutex(); $instanceMutex.Dispose(); $cycleMutex.Dispose() }


 }
 return $engine.ToString().Replace('@@SETTINGS_SHA@@',$SettingsHash)
}

# ---------------- entry point ----------------
if($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [version]'5.1' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 Desktop.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Open Windows PowerShell as Administrator.'}
$env:GIT_CONFIG_NOSYSTEM='1';$env:GIT_CONFIG_GLOBAL='NUL';$env:GIT_TERMINAL_PROMPT='0'
foreach($v in @('GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','GIT_COMMON_DIR','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES','GIT_CONFIG','GIT_CONFIG_COUNT','GIT_CONFIG_PARAMETERS')){Remove-Item "Env:\$v" -ErrorAction SilentlyContinue}
if($Action -eq 'Status'){Show-RemoStatus (Read-Deployment);return}
if($InternalRequest){
 if($identity.User.Value -ne 'S-1-5-18' -or $Action -eq 'Supervise'){throw 'Invalid internal request.'}
 $job=Join-Path $Control ('requests\'+$InternalRequest);Assert-Plain $job
 if([IO.Path]::GetFullPath($Self) -ine (Join-Path $job 'Remo.ps1')){throw 'Request script path mismatch.'}
 $result=@{Success=$false;Error='';Time=''};$gate=$null;$held=$false
 try{
  $gate=New-Object Threading.Mutex($false,'Global\Remo-Control')
  try{$held=$gate.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true}
  if(-not $held){throw 'Another Remo control operation is running.'}
  Invoke-SystemControl *>&1|Out-File -LiteralPath (Join-Path $job 'progress.log') -Encoding UTF8
  $result.Success=$true
 }catch{$result.Error=$_.Exception.Message}finally{if($held){$gate.ReleaseMutex()};if($gate){$gate.Dispose()};$result.Time=(Get-Date).ToString('o');Write-State (Join-Path $job 'result.json') $result}
 return
}
if($identity.User.Value -eq 'S-1-5-18'){
 Protect-Directory $Control
 $gate=New-Object Threading.Mutex($false,'Global\Remo-Control');$held=$false
 try{try{$held=$gate.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true};if($held){Invoke-SystemControl}}finally{if($held){$gate.ReleaseMutex()};$gate.Dispose()}
}else{if($Action -eq 'Supervise'){throw 'Supervisor runs as SYSTEM through its scheduled task.'};Invoke-AsSystem}
