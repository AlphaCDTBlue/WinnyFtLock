#Requires -Version 5.1
<#
  Disable-RemoteAccess.ps1 - one-time, run by hand. Not automatic, nothing stays running.
  Run elevated, from RDP or the console:
      .\Disable-RemoteAccess.ps1           sets OpenSSH (sshd) and WinRM to Disabled and stops them
      .\Disable-RemoteAccess.ps1 -Undo     puts both back exactly as the first run found them
                                           (startup type AND running/stopped)
  The original settings are saved and re-read BEFORE anything is changed; if that save fails, the
  service is left alone. Refuses to run inside a WinRM/SSH session (it would cut itself off).
  Saved original settings: C:\BlueLogs\remote-access-before.json
  Log: C:\BlueLogs\remote-access_<host>_<time>.txt
#>
[CmdletBinding()]
param([switch]$Undo)
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ Write-Host 'Run as Administrator.'; return }
if((Test-Path variable:PSSenderInfo) -or $env:SSH_CONNECTION){ Write-Host 'This is a remote (WinRM/SSH) session. Run it from RDP or the console instead.'; return }

$services = @('sshd','WinRM')
$logDir = 'C:\BlueLogs'
$beforeFile = Join-Path $logDir 'remote-access-before.json'
$logFile = Join-Path $logDir ('remote-access_' + $env:COMPUTERNAME + '_' + (Get-Date).ToString('yyyyMMdd_HHmmss') + '.txt')
$scExe = Join-Path $env:SystemRoot 'System32\sc.exe'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$lines = New-Object System.Collections.ArrayList
function Say([string]$Text){ Write-Host $Text; [void]$lines.Add($Text) }

function Get-Svc([string]$Name){ Get-CimInstance Win32_Service -Filter ("Name='" + $Name + "'") }
function Set-StartMode([string]$Name,[string]$Mode){
  $out = & $scExe config $Name 'start=' $Mode 2>&1
  if($LASTEXITCODE -ne 0){ throw ('sc.exe config failed: ' + ($out -join ' ')) }
}

# Saved original state: name -> @{StartMode; State; Saved}. Written to a temp file, moved into place, then re-read.
$before = [ordered]@{}
function Save-Before{
  $tmp = $beforeFile + '.tmp'
  if($before.Count -eq 0){
    if(Test-Path -LiteralPath $beforeFile){ Remove-Item -LiteralPath $beforeFile -Force }
    return
  }
  ($before | ConvertTo-Json) | Set-Content -LiteralPath $tmp -Encoding UTF8
  Move-Item -LiteralPath $tmp -Destination $beforeFile -Force
  $check = Get-Content -LiteralPath $beforeFile -Raw | ConvertFrom-Json
  foreach($k in $before.Keys){
    if(-not $check.PSObject.Properties[$k] -or $check.$k.StartMode -ne $before[$k].StartMode){ throw 'Saved state did not read back correctly.' }
  }
}

if(Test-Path -LiteralPath $beforeFile){
  try{
    $obj = Get-Content -LiteralPath $beforeFile -Raw | ConvertFrom-Json
    foreach($p in $obj.PSObject.Properties){ $before[$p.Name] = $p.Value }
  } catch {
    $bad = $beforeFile + '.corrupt-' + (Get-Date).ToString('yyyyMMdd_HHmmss')
    Move-Item -LiteralPath $beforeFile -Destination $bad -Force
    Say ('WARNING: saved state file was unreadable and was set aside as ' + $bad + '. Originals recorded in it are lost; current settings will be recorded instead.')
  }
}

Say ('Disable-RemoteAccess on ' + $env:COMPUTERNAME + ' at ' + (Get-Date).ToString('s') + $(if($Undo){'  (UNDO)'}else{''}))
foreach($name in $services){
  try{
    $svc = Get-Svc $name
    if(-not $svc){ Say ('  ' + $name + ': not installed'); continue }
    if($Undo){
      if(-not $before.Contains($name)){ Say ('  ' + $name + ': no saved original settings, left alone'); continue }
      $orig = $before[$name]
      $mode = switch([string]$orig.StartMode){ 'Auto' {'auto'} 'Manual' {'demand'} 'Disabled' {'disabled'} default {''} }
      if(-not $mode){ Say ('  ' + $name + ': cannot restore start mode ' + $orig.StartMode); continue }
      Set-StartMode $name $mode
      if([string]$orig.State -eq 'Running'){
        if($svc.State -ne 'Running'){ Start-Service -Name $name }
      } else {
        if($svc.State -ne 'Stopped'){ Stop-Service -Name $name -Force }
      }
      $now = Get-Svc $name
      Say ('  ' + $name + ': ' + $now.StartMode + ' / ' + $now.State + '   (was ' + $orig.StartMode + ' / ' + $orig.State + ' before the first run)')
      if($now.StartMode -eq [string]$orig.StartMode -and $now.State -eq [string]$orig.State){ $before.Remove($name); Save-Before }
      else { Say ('  WARNING: ' + $name + ' does not match its original settings yet; the saved record was kept.') }
    } else {
      $needsChange = ($svc.StartMode -ne 'Disabled' -or $svc.State -ne 'Stopped')
      if($needsChange -and -not $before.Contains($name)){
        $before[$name] = [pscustomobject]@{ StartMode = [string]$svc.StartMode; State = [string]$svc.State; Saved = (Get-Date).ToString('s') }
        try{ Save-Before } catch { $before.Remove($name); throw ('could not save the original settings first (' + $_.Exception.Message + '); ' + $name + ' was NOT changed') }
      }
      if($svc.StartMode -ne 'Disabled'){ Set-StartMode $name 'disabled' }
      if($svc.State -ne 'Stopped'){ Stop-Service -Name $name -Force }
      $now = Get-Svc $name
      Say ('  ' + $name + ': ' + $now.StartMode + ' / ' + $now.State)
      if($now.StartMode -ne 'Disabled' -or $now.State -ne 'Stopped'){ Say ('  WARNING: ' + $name + ' is not Disabled/Stopped. Check it by hand.') }
    }
  } catch {
    Say ('  ' + $name + ': ERROR ' + $_.Exception.Message)
  }
}
[IO.File]::WriteAllLines($logFile,[string[]]$lines.ToArray())
Write-Host ('Log: ' + $logFile)
