#Requires -Version 5.1
<#
  End-Schedule.ps1 - disables every scheduled task that is not Remo's, then lists what it disabled and what it did not.
  Run elevated:
      .\End-Schedule.ps1             disable them now and print the two lists
      .\End-Schedule.ps1 -Restore    undo: re-enable everything this script disabled
  Never touched: Remo's own tasks, a live Remo request, BlueOps' one-use task (BthServiceMonitor, checked by its
  action), anything in $KeepTasks below, and - only while Remo is NOT installed - the old gitat tasks that are
  still protecting IIS (gitat, watchdogs, watchdogsgit).
  Before each task is disabled its XML is saved and a journal entry is written; if either fails the task is left alone.
  -Restore re-enables tasks and cannot restart anything that was stopped. A task that was deleted is re-created
  from its saved XML when possible (tasks that run as a user with a saved password may need credentials).
  Saved XML and journal: C:\ProgramData\EndSchedule
  Report: C:\BlueLogs\endschedule_<host>_<time>.txt
#>
[CmdletBinding()]
param([switch]$Restore)
$ErrorActionPreference = 'Stop'

# Full task names (for example '\Session-Guard') that must stay enabled. Empty on purpose.
$KeepTasks = @()

$Root = Join-Path $env:ProgramData 'EndSchedule'
$JournalFile = Join-Path $Root 'journal.json'
$LogDir = 'C:\BlueLogs'
$RemoState = Join-Path $env:ProgramData 'Remo\deployment.json'
$RemoRequests = Join-Path $env:ProgramData 'Remo\requests'
$PowerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$LegacyGitat = @('\gitat','\watchdogs','\watchdogsgit')

function Protect-Folder([string]$Path){
  New-Item -ItemType Directory -Path $Path -Force | Out-Null
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Read-Journal{
  $map = [ordered]@{}
  if(Test-Path -LiteralPath $JournalFile){
    $o = Get-Content -LiteralPath $JournalFile -Raw | ConvertFrom-Json
    foreach($p in $o.PSObject.Properties){ $map[$p.Name] = $p.Value }
  }
  return $map
}

function Save-Journal($Map){
  $tmp = $JournalFile + '.tmp'
  ($Map | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $tmp -Encoding UTF8
  Move-Item -LiteralPath $tmp -Destination $JournalFile -Force
}

function Get-RemoInfo{
  $info = [pscustomobject]@{ Active = $false; Names = @() }
  if(Test-Path -LiteralPath $RemoState){
    try{
      $s = Get-Content -LiteralPath $RemoState -Raw | ConvertFrom-Json
      $info.Active = ([string]$s.State -eq 'Active')
      $info.Names = @(('\' + [string]$s.WorkerTask), ('\' + [string]$s.SupervisorTask))
    } catch { }
  }
  return $info
}

# Returns the reason a task must not be disabled, or '' if it can be.
function Get-ExemptReason($Task,$Remo){
  $full = [string]$Task.TaskPath + [string]$Task.TaskName
  if($Remo.Names -contains $full){ return 'Remo task' }
  if($full -match '^\\Remo(Supervisor)?-[a-f0-9]{32}$'){ return 'Remo task' }
  if($script:KeepTasks -contains $full){ return 'in $KeepTasks' }
  if(-not $Remo.Active -and ($script:LegacyGitat -contains $full)){ return 'old gitat protection (Remo is not installed yet)' }
  $actions = @($Task.Actions)
  if($actions.Count -ne 1){ return '' }
  if(([string]$Task.Principal.UserId) -notin @('SYSTEM','S-1-5-18')){ return '' }
  $exe = [string]$actions[0].Execute
  $arguments = [string]$actions[0].Arguments
  if($full -ceq '\Microsoft\Windows\Bluetooth\BthServiceMonitor'){
    if(($exe -ieq 'powershell.exe' -or $exe -ieq $script:PowerShellExe) -and $arguments -ceq '-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\BlueOps\Svc-Control-Worker.ps1'){ return 'BlueOps one-use task' }
    return ''
  }
  if($full -match '^\\Remo-Request-([a-f0-9]{32})$'){
    $rid = $Matches[1]
    $copy = Join-Path $script:RemoRequests ($rid + '\Remo.ps1')
    $pattern = '^-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + [regex]::Escape($copy) + '" -Action (Install|Pause|Resume|Remove|RestoreTasks) -InternalRequest ' + $rid + '$'
    if(($exe -ieq $script:PowerShellExe) -and ($arguments -match $pattern) -and (Test-Path -LiteralPath $copy -PathType Leaf)){ return 'live Remo request' }
  }
  return ''
}

function Split-TaskName([string]$Full){
  $i = $Full.LastIndexOf('\')
  return @($Full.Substring(0,$i + 1), $Full.Substring($i + 1))
}

function Invoke-Disable{
  Protect-Folder $Root
  $journal = Read-Journal          # unreadable journal -> stop here, nothing gets disabled
  $remo = Get-RemoInfo
  $disabled = New-Object System.Collections.ArrayList
  $notDisabled = New-Object System.Collections.ArrayList
  $already = New-Object System.Collections.ArrayList
  $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')

  foreach($task in @(Get-ScheduledTask)){
    $full = [string]$task.TaskPath + [string]$task.TaskName
    $reason = Get-ExemptReason $task $remo
    if($reason){ [void]$notDisabled.Add([pscustomobject]@{ Task = $full; Why = $reason }); continue }
    $enabled = [bool]$task.Settings.Enabled
    $running = ([string]$task.State -eq 'Running')
    if(-not $enabled -and -not $running){
      $note = 'already disabled'
      if($journal.Contains($full)){ $note = 'already disabled (by an earlier End-Schedule run)' }
      [void]$already.Add([pscustomobject]@{ Task = $full; Why = $note }); continue
    }
    $added = $false
    try{
      if($enabled){
        $arch = $null
        if($journal.Contains($full) -and $journal[$full].Archive -and (Test-Path -LiteralPath ([string]$journal[$full].Archive))){ $arch = [string]$journal[$full].Archive }
        else{
          $xml = [string](Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop)
          if($xml.Length -lt 50 -or $xml -notmatch '</Task>'){ throw 'could not save the task XML; left enabled' }
          $arch = Join-Path $Root ($stamp + '-' + ($full -replace '[^A-Za-z0-9._-]','_') + '.xml')
          [IO.File]::WriteAllText($arch,$xml,[Text.Encoding]::Unicode)
          if(-not (Test-Path -LiteralPath $arch) -or (Get-Item -LiteralPath $arch).Length -lt 50){ throw 'task XML file was not written; left enabled' }
        }
        $added = -not $journal.Contains($full)
        $journal[$full] = [pscustomobject]@{ Disabled = (Get-Date).ToString('o'); WasRunning = $running; Archive = $arch }
        Save-Journal $journal
        [void](Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop)
      }
      if($running){
        Stop-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
        for($i = 0; $i -lt 10; $i++){
          if((Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop).State -ne 'Running'){ break }
          Start-Sleep -Milliseconds 500
        }
      }
      $now = Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
      if($now.Settings.Enabled){ throw 'still enabled after Disable-ScheduledTask' }
      if($now.State -eq 'Running'){ throw 'still running after Stop-ScheduledTask' }
      $what = 'disabled'
      if($running){ $what = 'disabled and stopped' }
      [void]$disabled.Add([pscustomobject]@{ Task = $full; Why = $what })
    } catch {
      if($added){
        try{
          if((Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop).Settings.Enabled){ $journal.Remove($full); Save-Journal $journal }
        } catch { }
      }
      [void]$notDisabled.Add([pscustomobject]@{ Task = $full; Why = ('FAILED: ' + $_.Exception.Message) })
    }
  }
  return [pscustomobject]@{ Disabled = $disabled; NotDisabled = $notDisabled; Already = $already; RemoActive = $remo.Active }
}

function Invoke-RestoreAll{
  $journal = Read-Journal
  $restored = New-Object System.Collections.ArrayList
  $failed = New-Object System.Collections.ArrayList
  foreach($full in @($journal.Keys)){
    $parts = Split-TaskName $full
    $path = $parts[0]; $leaf = $parts[1]
    try{
      $t = Get-ScheduledTask -TaskName $leaf -TaskPath $path -ErrorAction SilentlyContinue
      if(-not $t){
        $arch = [string]$journal[$full].Archive
        if(-not $arch -or -not (Test-Path -LiteralPath $arch)){ throw 'task no longer exists and its saved XML is missing' }
        [void](Register-ScheduledTask -TaskName $leaf -TaskPath $path -Xml (Get-Content -LiteralPath $arch -Raw) -ErrorAction Stop)
        [void]$restored.Add([pscustomobject]@{ Task = $full; Why = 're-created from saved XML' })
      }
      else{
        if(-not $t.Settings.Enabled){ Enable-ScheduledTask -TaskName $leaf -TaskPath $path -ErrorAction Stop | Out-Null }
        if(-not (Get-ScheduledTask -TaskName $leaf -TaskPath $path -ErrorAction Stop).Settings.Enabled){ throw 'still disabled' }
        [void]$restored.Add([pscustomobject]@{ Task = $full; Why = 're-enabled' })
      }
      $journal.Remove($full)
    } catch {
      [void]$failed.Add([pscustomobject]@{ Task = $full; Why = ('FAILED: ' + $_.Exception.Message) })
    }
  }
  Save-Journal $journal
  return [pscustomobject]@{ Restored = $restored; Failed = $failed }
}

function Write-List([string]$Title,$Items,[string]$Color,[switch]$ConsoleSummaryOnly){
  Write-Host ''
  Write-Host ($Title + ' (' + @($Items).Count + ')') -ForegroundColor $Color
  if($ConsoleSummaryOnly){ Write-Host '  (full list is in the report file)'; return }
  foreach($i in $Items){ Write-Host ('  ' + $i.Task + '   - ' + $i.Why) }
}

# ---- main ----
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ Write-Host 'Run as Administrator.'; return }
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$report = Join-Path $LogDir ('endschedule_' + $env:COMPUTERNAME + '_' + (Get-Date).ToString('yyyyMMdd_HHmmss') + '.txt')
$lines = New-Object System.Collections.ArrayList

if($Restore){
  $r = Invoke-RestoreAll
  Write-List 'RE-ENABLED' $r.Restored 'Green'
  Write-List 'COULD NOT BE RESTORED' $r.Failed 'Yellow'
  [void]$lines.Add('End-Schedule -Restore on ' + $env:COMPUTERNAME + ' at ' + (Get-Date).ToString('s'))
  foreach($i in $r.Restored){ [void]$lines.Add('RE-ENABLED  ' + $i.Task + '  - ' + $i.Why) }
  foreach($i in $r.Failed){ [void]$lines.Add('NOT RESTORED  ' + $i.Task + '  - ' + $i.Why) }
}
else{
  $r = Invoke-Disable
  if(-not $r.RemoActive){ Write-Host 'Note: Remo is not installed/active on this box, so the old gitat tasks were left enabled.' -ForegroundColor Yellow }
  Write-List 'DISABLED' $r.Disabled 'Green'
  Write-List 'NOT DISABLED (kept on purpose or failed)' $r.NotDisabled 'Yellow'
  Write-List 'ALREADY DISABLED, nothing to do' $r.Already 'DarkGray' -ConsoleSummaryOnly
  [void]$lines.Add('End-Schedule on ' + $env:COMPUTERNAME + ' at ' + (Get-Date).ToString('s'))
  [void]$lines.Add('')
  [void]$lines.Add('DISABLED (' + $r.Disabled.Count + ')')
  foreach($i in $r.Disabled){ [void]$lines.Add('  ' + $i.Task + '  - ' + $i.Why) }
  [void]$lines.Add('')
  [void]$lines.Add('NOT DISABLED (' + $r.NotDisabled.Count + ')')
  foreach($i in $r.NotDisabled){ [void]$lines.Add('  ' + $i.Task + '  - ' + $i.Why) }
  [void]$lines.Add('')
  [void]$lines.Add('ALREADY DISABLED (' + $r.Already.Count + ')')
  foreach($i in $r.Already){ [void]$lines.Add('  ' + $i.Task + '  - ' + $i.Why) }
  Write-Host ''
  Write-Host 'Undo with: .\End-Schedule.ps1 -Restore' -ForegroundColor Cyan
}
[IO.File]::WriteAllLines($report,[string[]]$lines.ToArray())
Write-Host ('Report: ' + $report)
