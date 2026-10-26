#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$RepositoryUrl = '',
    [string]$RepositoryRef = '',
    [string]$Root = 'C:\BlueTeam',
    [switch]$SkipBackup
)
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$run = Join-Path $Root "Runs\$stamp"
$logs = Join-Path $run 'Logs'
$backup = Join-Path $run 'CABackup'
$repoDir = Join-Path $Root 'Repo'
New-Item -ItemType Directory -Force -Path $logs,$backup | Out-Null
$transcript = Join-Path $logs 'Session.log'
Start-Transcript -Path $transcript -Force | Out-Null
$summary = Join-Path $logs 'Summary.log'
function Record([string]$message) { "$(Get-Date -Format o) $message" | Tee-Object -FilePath $summary -Append }
function Stage([string]$name,[scriptblock]$action) {
  Record "BEGIN $name"
  try { & $action 2>&1 | Out-File -FilePath (Join-Path $logs "$name.log") -Width 240; Record "OK $name" }
  catch { Record "ERROR $name : $($_.Exception.Message)" }
}
try {
  Record "Server=$env:COMPUTERNAME User=$env:USERNAME Run=$run"
  Stage '01_Baseline' {
    Get-ComputerInfo | Select-Object WindowsProductName,OsVersion
    Get-Service -Name CertSvc -ErrorAction Stop | Format-List *
    sc.exe qc CertSvc
    certutil.exe -getconfig
    certutil.exe -getreg CA\CAName
    Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
  }
  Stage '02_Repository' {
    if (-not $RepositoryUrl) { 'No repository URL provided; clone skipped'; return }
    if ($RepositoryUrl -notmatch '^https://') { throw 'Repository URL must use HTTPS' }
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if (-not $git) { throw 'Git is not installed; repository clone skipped' }
    if (Test-Path $repoDir) { 'Repository directory already exists; no automatic pull'; return }
    & $git.Source clone -- $RepositoryUrl $repoDir
    if ($LASTEXITCODE -ne 0) { throw "git clone failed with exit code $LASTEXITCODE" }
    if ($RepositoryRef) {
      & $git.Source -C $repoDir checkout --detach $RepositoryRef
      if ($LASTEXITCODE -ne 0) { throw "git checkout failed with exit code $LASTEXITCODE" }
    }
    'Repository cloned. Review scripts before executing them.'
  }
  Stage '03_CA_Backup' {
    if ($SkipBackup) { 'Backup skipped by request'; return }
    $svc = Get-Service CertSvc -ErrorAction Stop
    if ($svc.Status -ne 'Running') { throw 'CertSvc is not running; check service before backup' }
    & certutil.exe -backupdb $backup
    if ($LASTEXITCODE -ne 0) { throw "certutil -backupdb failed: $LASTEXITCODE" }
    & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' (Join-Path $backup 'CA_Configuration.reg') /y
    if ($LASTEXITCODE -ne 0) { throw "CA registry export failed: $LASTEXITCODE" }
    'CA database and configuration exported. CA signing private key NOT exported.'
  }
  Stage '04_Service_Recovery' {
    Get-Service CertSvc | Format-List Name,Status,StartType
    sc.exe qc CertSvc
    sc.exe queryex CertSvc
    'Recovery command after investigation: Start-Service CertSvc'
    'Coordinated restart only: Restart-Service CertSvc'
    'Do not restore CA database or private key without a validated recovery plan.'
  }
  Stage '05_Firewall_Logging' {
    $fwlog = Join-Path $logs 'pfirewall.log'
    Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked,LogFileName | Format-List
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogAllowed True -LogMaxSizeKilobytes 16384 -LogFileName $fwlog
    Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked,LogFileName | Format-List
    'Firewall default inbound/outbound policies and allow/block rules were NOT changed.'
  }
  Stage '06_Event_Auditing' {
    wevtutil.exe gl Security
    wevtutil.exe sl Security /ms:134217728
    auditpol.exe /get /subcategory:'Certification Services'
    auditpol.exe /set /subcategory:'Certification Services' /success:enable /failure:enable
    auditpol.exe /get /subcategory:'Certification Services'
    certutil.exe -getreg CA\AuditFilter
    'CA AuditFilter was not changed automatically (may require CertSvc restart).'
    'Security event log retained on server; export or forward to trusted location.'
  }
  Record 'COMPLETE. No user passwords, groups, or Grey Team resources modified.'
  Record 'Inspect stage logs for command-level failures; OK means the stage did not throw a PowerShell exception.'
} finally { Stop-Transcript | Out-Null }
