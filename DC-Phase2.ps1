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
$required = @('IIS\new_session (1).ps1','IIS\SessionKill.ps1','general\terminal_sessions\logging.ps1','general\IP-Firewall.ps1','AD_DNS\AD-Guard.ps1','AD_DNS\DNS-Guard.ps1')
foreach ($relative in $required) {
    $path=RepoFile $relative
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw "Syntax error in ${relative}: $($errors[0].Message)" }
}
if ($Check) { Write-Host 'DC identity, required paths and PowerShell syntax checked. No changes made.'; return }

$state=Read-State
Check-Baselines
if ((Read-Host 'Confirm domain passwords were reset and you have logged back in: type READY') -cne 'READY') { return }
Write-Host @'
Terminal tools:
KICK = SessionKill.ps1: one-time sign-out of OTHER local RDP/console sessions (including team/Grey).
GATE = new_session (1).ps1: persistent verification gate for new RDP/SSH/WinRM sessions.
       Review its GreyAccounts defaults first (kingneptune, paintythepirate).
       Installation may restart SSH/WinRM; use the console/RDP, not SSH/WinRM.
Enter = already done / skip. To use both, choose KICK, then GATE at the next prompt.
'@ -ForegroundColor Yellow
while ($true) {
    $choice=Read-Host 'KICK, GATE, or Enter to continue'
    if ([string]::IsNullOrWhiteSpace($choice)) { break }
    if ($choice -ceq 'KICK') { Run 'IIS\SessionKill.ps1' }
    elseif ($choice -ceq 'GATE') {
        if (Get-ScheduledTask -TaskName 'NewSession-Guard' -ErrorAction SilentlyContinue) {
            Run 'IIS\new_session (1).ps1' '-Action Status'
        } else {
            Run 'IIS\new_session (1).ps1' '-Action Install'
        }
        $task=Get-ScheduledTask -TaskName 'NewSession-Guard' -ErrorAction Stop
        $heartbeat=Get-Content "$env:ProgramData\NewSession\status.json" -Raw | ConvertFrom-Json
        $age=((Get-Date).ToUniversalTime()-([datetimeoffset]$heartbeat.Time).UtcDateTime).TotalSeconds
        if ($task.State -ne 'Running' -or -not $heartbeat.Healthy -or $age -lt 0 -or $age -gt 15) { throw 'Session gate did not report a healthy running task and fresh heartbeat.' }
    }
}
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
Write-Host @'
Account/logon review: IIS\UserChecker.ps1 cannot run on a DC and deletes local users.
AD-Guard is the DC-appropriate new-account/disabled-account watcher; K is manual containment.
It does not prove a logon is illegal. Review the account and IP evidence yourself.
Strict sequential monitoring follows: AD runs until Q, THEN DNS runs until Q.
Only one guard runs at a time. To keep both active together requires separate manual windows.
Do not press B unless you intend to approve changed state as a new baseline.
'@ -ForegroundColor Yellow
Run 'AD_DNS\AD-Guard.ps1'
Run 'AD_DNS\DNS-Guard.ps1'
Write-Host 'Phase 2 finished. Both guards have exited; neither is monitoring now.' -ForegroundColor Yellow
