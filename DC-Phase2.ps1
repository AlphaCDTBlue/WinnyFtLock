#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([switch]$Check)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess) { throw 'Use elevated 64-bit Windows PowerShell 5.1.' }
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { throw 'This launcher is for the DC only.' }
Import-Module ActiveDirectory
$domain = Get-ADDomain -Server $env:COMPUTERNAME
$repo = $PSScriptRoot
$store = Join-Path $env:ProgramData 'CDT-DC-Start'
$stateFile = Join-Path $store 'phase1.xml'
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
function RepoFile([string]$Relative) {
    $path = Join-Path $repo $Relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing $path. Put BOTH launchers at the extracted repo root." }
    return $path
}
function Run([string]$Relative, [string]$Arguments = '') {
    $path = RepoFile $Relative
    Write-Host "`nRUNNING: $Relative. Waiting for this script to exit." -ForegroundColor Cyan
    # Separate process prevents child 'exit', types and variables from breaking the launcher.
    $quoted = "'" + $path.Replace("'", "''") + "'"
    $command = "`$ErrorActionPreference='Stop'; try { & $quoted $Arguments } catch { Write-Host (`$_ | Out-String) -ForegroundColor Red; Read-Host 'Failed - press Enter to return to launcher'; exit 1 }"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $child = Start-Process -FilePath $ps -ArgumentList "-NoLogo -NoProfile -STA -ExecutionPolicy Bypass -EncodedCommand $encoded" -WorkingDirectory $repo -Wait -PassThru
    if ($child.ExitCode -ne 0) { throw "$Relative exited with code $($child.ExitCode). Stopped; review its output." }
    Write-Host "RETURNED: $Relative (exit 0; verify any tool-reported errors)." -ForegroundColor Cyan
}
function Read-State {
    if (-not (Test-Path $stateFile)) { throw 'Run DC-Phase1.ps1 first.' }
    $s = Import-Clixml $stateFile
    if ($s.Computer -ine $env:COMPUTERNAME -or $s.DomainSID -ne $domain.DomainSID.Value) { throw 'Phase state belongs to another host/domain.' }
    return $s
}
function Check-Baselines {
    $ad = Join-Path $env:ProgramData 'AD-DisabledWatch\baseline.xml'
    $dns = Join-Path $env:ProgramData 'DNS-Guard\active.xml'
    if (-not (Test-Path $ad) -or -not (Test-Path $dns)) { throw 'Both accepted baselines are required; a cancelled dialog does not count.' }
    $a=Import-Clixml $ad; $d=Import-Clixml $dns
    if ($a.DomainSID -ne $domain.DomainSID.Value -or $a.DC -ine $env:COMPUTERNAME -or $d.Server -ine $env:COMPUTERNAME) { throw 'Baseline identity mismatch.' }
    if (-not (Test-Path (Join-Path $d.Folder 'snapshot.xml'))) { throw 'DNS inventory snapshot is missing.' }
}
$required = @('general\toolkit.ps1','IIS\session.ps1','IIS\SessionKill.ps1','general\terminal_sessions\logging.ps1','general\IP-Firewall.ps1','AD_DNS\AD-Guard.ps1','AD_DNS\DNS-Guard.ps1')
foreach ($relative in $required) {
    $path=RepoFile $relative
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw "Syntax error in ${relative}: $($errors[0].Message)" }
}
if ($Check) { Write-Host 'DC identity, required paths and PowerShell syntax checked. No changes made.'; return }

$state=Read-State
if (-not $state.PasswordsConfirmed) { throw 'Finish Phase 1 password reset and confirm DONE first.' }
Check-Baselines
if ((Read-Host 'Confirm domain passwords were reset and you have logged back in: type READY') -cne 'READY') { return }
Write-Host 'SessionKill: signs out OTHER local interactive sessions, including team/Grey. Your session stays.' -ForegroundColor Yellow
if ((Read-Host 'Type KICK for the one-time sweep, or Enter if already done') -ceq 'KICK') { Run 'IIS\SessionKill.ps1' }
Write-Host 'Installing current repo terminal protection: RDP/SSH verification, no Grey exemptions; WinRM will be disabled where possible.' -ForegroundColor Yellow
Write-Host 'Run from console/RDP with SSH/WinRM sessions closed. Enter a separate verification password in the next window.'
Run 'IIS\session.ps1' '-Ask'
$task=Get-ScheduledTask -TaskName 'Session-Guard' -ErrorAction Stop
$heartbeat=Get-Content "$env:ProgramData\Session\status.json" -Raw | ConvertFrom-Json
$age=((Get-Date).ToUniversalTime()-([datetimeoffset]$heartbeat.Time).UtcDateTime).TotalSeconds
if ($task.State -ne 'Running' -or -not $heartbeat.Healthy -or $age -lt 0 -or $age -gt 15) { throw 'Session guard did not report a healthy running task and fresh heartbeat.' }
$sessionState=Get-Content "$env:ProgramData\Session\rollback.json" -Raw | ConvertFrom-Json
Write-Host "Session guard ready. WinRM mode: $($sessionState.WinRmMode)"
if ($sessionState.WinRmMode -ne 'Disabled') { Write-Warning 'WinRM was not fully disabled; the session tool is using its fallback. Review its output.' }
# Service-stop restriction was installed in phase 1; verify, do not overwrite the baseline.
foreach ($name in @('NTDS','DNS')) {
    $sddl=(& sc.exe sdshow $name) -join ''
    if ($LASTEXITCODE -or -not $sddl.Contains('(D;;DCWPDTSD;;;AU)')) { throw "BlueOps ACL changed for $name; review before continuing." }
    if ((Get-Service $name).Status -ne 'Running') { throw "$name is not running." }
}
Run 'general\terminal_sessions\logging.ps1'
$policy=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
if ($policy.EnableTranscripting -ne 1) { throw 'Transcript policy did not verify.' }
Write-Host 'Transcription applies to NEW PowerShell sessions, not CMD/all terminals or old history.'
# No standalone IP finder exists at d0da088. Read-only native snapshot instead.
Write-Host '`nConnections: remote addresses are leads, not proof of hostile activity.' -ForegroundColor Cyan
Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Format-Table -AutoSize | Out-Host
Write-Host 'Recent successful logons (up to 100 events from the last 30 minutes):' -ForegroundColor Cyan
try {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 100 -ErrorAction Stop | ForEach-Object {
        $xml=[xml]$_.ToXml(); $fields=@{}
        foreach ($d in $xml.Event.EventData.Data) { $fields[[string]$d.Name]=[string]$d.'#text' }
        [pscustomobject]@{Time=$_.TimeCreated;User=$fields.TargetUserName;Domain=$fields.TargetDomainName;Type=$fields.LogonType;IP=$fields.IpAddress}
    } | Format-Table -AutoSize | Out-Host
} catch { Write-Warning "Logon query unavailable or no matching events: $($_.Exception.Message)" }
Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table | Out-Host
Write-Host 'IP blocking requires the applicable firewall profile to be enabled. No profile is enabled automatically.' -ForegroundColor Yellow
while ($true) {
    $ip=Read-Host 'IP to manage (Enter finishes IP review)'
    if ([string]::IsNullOrWhiteSpace($ip)) { break }
    $parsed=$null
    if (-not [Net.IPAddress]::TryParse($ip,[ref]$parsed)) { Write-Warning 'Enter a single valid IP.'; continue }
    $ip=$parsed.ToString()
    $action=Read-Host 'Block, Unblock, Status, or Enter to skip'
    if ($action -notin @('Block','Unblock','Status')) { continue }
    Run 'general\IP-Firewall.ps1' "-Action $action -IP $ip"
}
function Start-Guard([string]$Relative) {
    $path=RepoFile $Relative
    $quoted="'"+$path.Replace("'","''")+"'"
    $command="try { & $quoted } catch { Write-Host (`$_ | Out-String) -ForegroundColor Red }; Write-Host 'Guard has exited. This window is no longer monitoring.' -ForegroundColor Yellow"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $child=Start-Process -FilePath $ps -ArgumentList "-NoLogo -NoProfile -NoExit -STA -ExecutionPolicy Bypass -EncodedCommand $encoded" -WorkingDirectory $repo -PassThru
    Write-Host "Launched $Relative in a separate window (PID $($child.Id)). Check that window for watcher status."
}
Write-Host 'Starting both guards. Leave their windows running; Q stops that guard. B deliberately updates its baseline.' -ForegroundColor Cyan
Start-Guard 'AD_DNS\AD-Guard.ps1'
Start-Guard 'AD_DNS\DNS-Guard.ps1'
Write-Host 'Downloading/installing toolkit while AD and DNS guards run. Installer prompts may need attention.' -ForegroundColor Cyan
Run 'general\toolkit.ps1'
$missing=@()
if (-not (Get-Service npcap -ErrorAction SilentlyContinue)) { $missing+='Npcap service' }
if (-not (Test-Path 'C:\Program Files\Wireshark\Wireshark.exe')) { $missing+='Wireshark' }
if (-not (Get-ChildItem 'C:\Tools\Sysinternals' -Filter '*.exe' -ErrorAction SilentlyContinue)) { $missing+='Sysinternals executables' }
if ($missing.Count) { Write-Warning "Toolkit returned but these were not found: $($missing -join ', '). Review installer output; guards were not stopped." }
Write-Host 'Phase 2 setup finished. Keep both guard windows open and confirm each says it is watching. Q stops an individual guard.' -ForegroundColor Cyan
