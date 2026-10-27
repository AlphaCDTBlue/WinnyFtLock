#Requires -RunAsAdministrator
#CMDWATCH-SELF
<#
.SYNOPSIS
  cmdwatch.ps1 - standalone, always-on logging for the Blue Team Windows host.
  It does not depend on any other script. Run elevated, no arguments. Leave it
  running (Ctrl+C to stop).

.DESCRIPTION
  Polls the event logs every couple of seconds and prints + logs one line for:
    PROC   every process creation: full command line, user, parent process
    PS     PowerShell script blocks (4104), skips this script's own blocks
    TASK   scheduled task created/updated (4698/4702) and the command it runs
    SVC    service installed (7045)
    ACCT   account created/enabled/password reset/added to a group
    LOGON  interactive/RDP logons (types 2,9,10) and failed logons
    WMI    permanent WMI event subscription created (5861)
    AV     Defender detection or real-time protection turned off
    TAMPER log cleared, audit policy changed, audit settings switched back off

  Colors: RED = alert, YELLOW = shell/LOLBin/odd path/logon, GRAY = everything else.

  SOURCE IP: PROC, PS, TASK, ACCT and LOGON lines show from=<ip> (<how>), e.g.
    from=10.1.1.5 (RDP)      RDP logon from that machine
    from=10.1.1.9 (net)      WinRM / PSRP / SMB / remote task logon from that machine
    from=local (console)     typed at the server's own console
    from=local (system/service)   started by a service, SYSTEM, or a scheduled task
  How: every process carries the ID of the logon session that started it, and
  each logon event (4624) records the source IP of that session. cmdwatch joins
  the two. It reads the last $LogonBackfillHours hours of logons at startup and
  looks up older sessions in the Security log on demand.
  Limits: the IP is where the SESSION logged in from. Behind a jumpbox it is the
  jumpbox's IP. Commands run by a service, an implant, or PsExec/SYSTEM show
  "local (system/service)"; trace those with the earlier network LOGON line and
  the SVC/TASK lines. "unknown" means the logon event is no longer in the log.
  Set $TrustedSourceIps to your jumpbox IPs to get a red UNTRUSTED-SRC alert for
  any remote session from another address.

  Alert rules (RED) include:
    - postgres/w3wp/httpd/sqlservr/java/office spawning a shell or recon tool
    - encoded PowerShell (-enc), decoded and shown inline
    - net user /add, localgroup administrators, schtasks /create, sc create,
      Run-key edits, log clearing, shadow copy deletion, credential dumping,
      download cradles, firewall/Defender tampering, remote exec tools

  It turns on the logging it needs (process command-line auditing, PowerShell
  script block logging, PowerShell transcription of every PowerShell session,
  task/account/group auditing, bigger Security log) and re-applies those
  settings every minute. If someone turns them back off, you get a TAMPER line.
  It also turns off QuickEdit so clicking in the window cannot freeze the loop.
  Identical repeating non-alert commands collapse into one line plus a repeat
  count, so loops do not bury real activity.

  Files (C:\BlueLogs):
    cmdwatch.log          everything
    cmdwatch-alerts.log   red lines only
    Transcripts\          full input/output of every PowerShell session
  Watch alerts from a second window:
    Get-Content C:\BlueLogs\cmdwatch-alerts.log -Wait -Tail 20

  Run:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\cmdwatch.ps1
  Disconnect RDP instead of signing out, or run it as a startup task:
    schtasks /create /sc onstart /ru SYSTEM /tn BlueCmdWatch /tr "powershell -NoProfile -ExecutionPolicy Bypass -File C:\BlueTools\cmdwatch.ps1"

  Uses Sysmon event 1 instead of Security 4688 if Sysmon is installed.
#>

$ErrorActionPreference = 'Continue'
$SelfPath = $MyInvocation.MyCommand.Path

# ============================== CONFIG ==============================
$LogDir        = 'C:\BlueLogs'
$PollSeconds   = 2
$MaxLogMB      = 25        # rotates to .old when a log passes this size
$AuditRefreshS = 60        # how often audit settings are re-applied
$SecLogSizeMB  = 256       # Security log size (4688 is chatty)
$MaxCmdChars   = 1500      # longest command line printed
$DedupSeconds  = 60        # identical non-alert lines inside this window are collapsed
$TranscriptDir = 'C:\BlueLogs\Transcripts'
$LogonBackfillHours = 24    # at startup, read this much logon history so running sessions have an IP
$ShowNetworkLogons  = $true # also print remote network logons (type 3: WinRM, SMB, remote tasks) with IP
# Your expected source IPs (jumpboxes, teammates). Empty = feature off. A remote
# session from any other address raises a red UNTRUSTED-SRC alert.
$TrustedSourceIps   = @()

# Noise you do not want to see (image file names, lowercase)
$IgnoreImages  = @('conhost.exe', 'backgroundtaskhost.exe', 'taskhostw.exe',
                   'searchprotocolhost.exe', 'searchfilterhost.exe', 'smartscreen.exe')

# Regexes matched against the command line to hide it (your own tooling).
# Careful: red team can imitate anything that matches here. Keep it narrow.
$IgnoreCmdRegex = @()

# Parents that should never be spawning shells or recon tools
$SuspectParentRx = '^(postgres|w3wp|httpd|apache|tomcat\d*|sqlservr|java|javaw|winword|excel|outlook|powerpnt|mshta|wscript|cscript)\.exe$'

$Shells  = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
             'mshta.exe', 'wsl.exe', 'bash.exe')
$Lolbins = @('whoami.exe', 'net.exe', 'net1.exe', 'nltest.exe', 'quser.exe', 'query.exe',
             'systeminfo.exe', 'tasklist.exe', 'taskkill.exe', 'schtasks.exe', 'sc.exe',
             'reg.exe', 'certutil.exe', 'bitsadmin.exe', 'rundll32.exe', 'regsvr32.exe',
             'wmic.exe', 'curl.exe', 'netsh.exe', 'arp.exe', 'nslookup.exe', 'ipconfig.exe',
             'route.exe', 'netstat.exe', 'icacls.exe', 'cacls.exe', 'takeown.exe',
             'vssadmin.exe', 'wevtutil.exe', 'auditpol.exe', 'psexec.exe', 'psexesvc.exe',
             'installutil.exe', 'msbuild.exe', 'forfiles.exe', 'ftp.exe', 'tftp.exe',
             'attrib.exe', 'cmstp.exe', 'wmiprvse.exe', 'at.exe', 'nbtstat.exe')

$UserPathRx = '\\(Users|ProgramData|PerfLogs|AppData)\\|\\Windows\\(Temp|Tasks)\\|\\Recycle'
$EncRx      = '\s-(?:e|ec|en|enc\w*)\s+([A-Za-z0-9+/=]{16,})'
$PsNoiseRx  = '^\s*(prompt|PSConsoleHostReadLine|Clear-Host|exit)\s*$|PSMessageDetails|ErrorCategory_Message|ErrorDetails_ScriptStackTrace|^\s*\{?\s*Set-StrictMode'

# Patterns that turn a line RED (matched against command line / script text)
$HighPatterns = [ordered]@{
    'NEW-USER'       = 'net1?(\.exe)?\s+user\s+\S+\s+\S+.*/add'
    'ADMIN-GROUP'    = 'net1?(\.exe)?\s+localgroup\s+"?administrators'
    'SCHTASK-CREATE' = 'schtasks(\.exe)?\s+.*/create'
    'SVC-CREATE'     = '\bsc(\.exe)?\s+(\\\\\S+\s+)?(create|config)\b'
    'RUN-KEY'        = 'reg(\.exe)?\s+add\s+.*(\\Run\b|\\RunOnce\b|Image File Execution|\\Services\\)'
    'LOG-CLEAR'      = 'wevtutil(\.exe)?\s+(cl|clear-log)|Clear-EventLog|Remove-EventLog'
    'SHADOW-DEL'     = 'vssadmin.*delete|wmic.*shadowcopy.*delete|bcdedit.*recoveryenabled'
    'CRED-DUMP'      = 'comsvcs.*minidump|procdump|mimikatz|sekurlsa|lsass|ntdsutil|lazagne|rubeus|secretsdump|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)'
    'DOWNLOAD'       = 'downloadstring|downloadfile|invoke-webrequest|\biwr\b|\biex\b|invoke-expression|urlcache|bitsadmin.*/transfer|start-bitstransfer|net\.webclient|frombase64string'
    'FW-OFF'         = 'netsh\s+(adv)?firewall.*(state\s+off|disable)|set-netfirewallprofile.*enabled\s+false'
    'DEFENDER-OFF'   = 'set-mppreference.*disable|add-mppreference.*exclusion|sc\s+(stop|config)\s+windefend'
    'REMOTE-EXEC'    = 'psexec|winrs\b|invoke-command|enter-pssession|new-pssession|wmic.*/node'
    'AUDIT-OFF'      = 'auditpol.*(/clear|/remove|:disable)'
    'WMI-PERSIST'    = '__eventfilter|commandlineeventconsumer|register-wmievent'
}

# Audit subcategories (GUIDs so it works on any language)
$AuditGuids = @(
    '{0CCE922B-69AE-11D9-BED3-505054503030}',   # Process Creation
    '{0CCE9227-69AE-11D9-BED3-505054503030}',   # Other Object Access (task scheduler)
    '{0CCE9215-69AE-11D9-BED3-505054503030}',   # Logon
    '{0CCE9235-69AE-11D9-BED3-505054503030}',   # User Account Management
    '{0CCE9237-69AE-11D9-BED3-505054503030}'    # Security Group Management
)
$RegChecks = @(
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Value = 1; Type = 'DWord' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Value = 1; Type = 'DWord' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableTranscripting'; Value = 1; Type = 'DWord' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableInvocationHeader'; Value = 1; Type = 'DWord' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'OutputDirectory'; Value = $TranscriptDir; Type = 'String' }
)
# ====================================================================

$null = New-Item -ItemType Directory -Path $LogDir -Force
$AllLog   = Join-Path $LogDir 'cmdwatch.log'
$AlertLog = Join-Path $LogDir 'cmdwatch-alerts.log'
$script:AuditStart = Get-Date
$script:AuditEnd   = Get-Date
$sidCache = @{}
$Seen = @{}
$LogonMap  = @{}   # logon session ID -> @{ From; Ip; User; Time }
$PidMap    = @{}   # process ID -> "from" label (used to tag PowerShell script blocks)
$LogonMiss = @{}   # logon IDs we could not find, retried after 5 minutes
$LogonTypeName = @{ '2' = 'console'; '3' = 'net'; '4' = 'batch'; '5' = 'service'; '7' = 'unlock'; '8' = 'net-clear'; '9' = 'newcreds'; '10' = 'RDP'; '11' = 'cached' }

function Save-Line([string]$File, [string]$Line) {
    try {
        if ((Test-Path $File) -and ((Get-Item $File).Length -gt ($MaxLogMB * 1MB))) {
            Move-Item $File ($File + '.old') -Force
        }
        Add-Content -Path $File -Value $Line -Encoding UTF8
    } catch {}
}

function Emit {
    param([datetime]$Time, [string]$Tag, [string]$Text, [string]$Level = 'info')
    $mark = '  '
    $color = 'Gray'
    if ($Level -eq 'high') { $mark = '!!'; $color = 'Red' }
    elseif ($Level -eq 'warn') { $mark = '* '; $color = 'Yellow' }
    $line = '{0} {1} [{2,-5}] {3}' -f $Time.ToString('yyyy-MM-dd HH:mm:ss'), $mark, $Tag, $Text
    Write-Host $line -ForegroundColor $color
    Save-Line $AllLog $line
    if ($Level -eq 'high') { Save-Line $AlertLog $line }
}

function Clean([string]$s, [int]$max = 0) {
    if ($max -le 0) { $max = $MaxCmdChars }
    if (-not $s) { return '' }
    $s = ($s -replace '[\r\n]+', ' | ' -replace '\s{2,}', ' ').Trim()
    if ($s.Length -gt $max) { $s = $s.Substring(0, $max) + '...(+' + ($s.Length - $max) + ' chars)' }
    return $s
}

function Leaf([string]$p) {
    if (-not $p) { return '' }
    return (($p -split '\\')[-1]).ToLower()
}

function HexToInt($s) {
    try { return [Convert]::ToInt32([string]$s, 16) } catch { return 0 }
}

function Get-EvData($ev) {
    $h = @{}
    try {
        $x = [xml]$ev.ToXml()
        foreach ($n in $x.Event.EventData.Data) {
            $k = $n.GetAttribute('Name')
            if ($k) { $h[$k] = [string]$n.InnerText }
        }
    } catch {}
    return $h
}

function Resolve-Sid($sid) {
    if (-not $sid) { return '?' }
    $k = $sid.Value
    if (-not $sidCache.ContainsKey($k)) {
        try { $sidCache[$k] = $sid.Translate([Security.Principal.NTAccount]).Value }
        catch { $sidCache[$k] = $k }
    }
    return $sidCache[$k]
}

function Logon-Key($s) {
    try { return [Convert]::ToInt64(([string]$s).Trim(), 16) } catch { return [int64]-1 }
}

function Get-SrcIp($d) {
    $ip = ([string]$d['IpAddress']) -replace '^::ffff:', ''
    if ((-not $ip) -or ($ip -eq '-')) { return '' }
    return $ip
}

function Format-From($d) {
    $type = [string]$d['LogonType']
    $tn = $LogonTypeName[$type]
    if (-not $tn) { $tn = 'type' + $type }
    $ip = Get-SrcIp $d
    if (-not $ip) {
        $w = [string]$d['WorkstationName']
        if (($type -eq '3') -and $w -and ($w -ne '-')) { return $w + ' (' + $tn + ')' }
        return 'local (' + $tn + ')'
    }
    if ($ip -in @('127.0.0.1', '::1')) { return 'localhost (' + $tn + ')' }
    return $ip + ' (' + $tn + ')'
}

function Test-Untrusted([string]$ip) {
    if ($TrustedSourceIps.Count -eq 0) { return $false }
    if ((-not $ip) -or ($ip -in @('127.0.0.1', '::1'))) { return $false }
    return ($TrustedSourceIps -notcontains $ip)
}

function Add-Logon($d, $time) {
    $info = @{
        From = (Format-From $d)
        Ip   = (Get-SrcIp $d)
        User = ($d['TargetDomainName'] + '\' + $d['TargetUserName'])
        Time = $time
    }
    # an elevated (UAC) session has its own ID linked to the filtered one; map both
    foreach ($f in @('TargetLogonId', 'TargetLinkedLogonId')) {
        $k = Logon-Key $d[$f]
        if ($k -gt 0) { $LogonMap[$k] = $info }
    }
}

function Find-LogonInLog([int64]$key) {
    # session started before cmdwatch (or outside the backfill window): ask the Security log
    try {
        $hex = '0x' + $key.ToString('x')
        $xp = "*[System[EventID=4624] and EventData[Data[@Name='TargetLogonId']='$hex']]"
        $ev = Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 1 -ErrorAction Stop
        if ($ev) { Add-Logon (Get-EvData $ev) $ev.TimeCreated }
    } catch {}
}

function Get-LogonInfo($logonId) {
    $key = Logon-Key $logonId
    if ($key -le 0) { return @{ From = '?'; Ip = '' } }
    # 0x3e7 SYSTEM, 0x3e5 LOCAL SERVICE, 0x3e4 NETWORK SERVICE
    if ($key -in @(999, 997, 996)) { return @{ From = 'local (system/service)'; Ip = '' } }
    if (-not $LogonMap.ContainsKey($key)) {
        $miss = $LogonMiss[$key]
        if ((-not $miss) -or (((Get-Date) - $miss).TotalMinutes -gt 5)) {
            Find-LogonInLog $key
            if (-not $LogonMap.ContainsKey($key)) { $LogonMiss[$key] = Get-Date }
        }
    }
    if ($LogonMap.ContainsKey($key)) { return $LogonMap[$key] }
    return @{ From = 'unknown'; Ip = '' }
}

function Prune-Logons {
    if ($LogonMap.Count -gt 6000) {
        $old = @($LogonMap.Keys | Sort-Object { $LogonMap[$_].Time } | Select-Object -First 2000)
        foreach ($k in $old) { $LogonMap.Remove($k) }
    }
    if ($PidMap.Count -gt 6000) { $PidMap.Clear() }
    $oldMiss = @($LogonMiss.Keys | Where-Object { ((Get-Date) - $LogonMiss[$_]).TotalMinutes -gt 10 })
    foreach ($k in $oldMiss) { $LogonMiss.Remove($k) }
}

function Get-HighHits([string]$text) {
    $hits = @()
    if (-not $text) { return $hits }
    foreach ($k in $HighPatterns.Keys) {
        if ($text -match $HighPatterns[$k]) { $hits += $k }
    }
    return $hits
}

function Handle-Process($t, $user, $image, $cmd, $parent, $procId, $parentId, $logonId) {
    $img = Leaf $image
    if ($IgnoreImages -contains $img) { return }
    if (-not $cmd) { $cmd = $image }
    foreach ($rx in $IgnoreCmdRegex) { if ($cmd -match $rx) { return } }

    $par = Leaf $parent
    $high = @()
    $warn = @()

    $li = Get-LogonInfo $logonId
    $from = $li.From
    try { $PidMap[[int]$procId] = $from } catch {}

    $isTool = ($Shells -contains $img) -or ($Lolbins -contains $img)
    if (($par -match $SuspectParentRx) -and $isTool) { $high += ('PARENT-SPAWN:' + $par + '>' + $img) }
    $high += @(Get-HighHits $cmd)
    if (Test-Untrusted $li.Ip) { $high += ('UNTRUSTED-SRC:' + $li.Ip) }

    $decoded = ''
    $m = [regex]::Match($cmd, $EncRx)
    if ($m.Success) {
        try { $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($m.Groups[1].Value)) } catch {}
        $high += 'ENCODED'
        if ($decoded) { $high += @(Get-HighHits $decoded) }
    }

    if ($isTool) { $warn += 'shell/lolbin' }
    if ($image -match $UserPathRx) { $warn += 'user-path' }

    $high = @($high | Where-Object { $_ } | Select-Object -Unique)
    $level = 'info'
    if ($warn.Count) { $level = 'warn' }
    if ($high.Count) { $level = 'high' }

    $text = '{0} from={1} :: {2} :: parent={3} pid={4}<-{5}' -f $user, $from, (Clean $cmd), $parent, $procId, $parentId
    if ($decoded) { $text += ' :: DECODED=' + (Clean $decoded 800) }
    if ($high.Count) { $text += ' :: ALERT[' + ($high -join ',') + ']' }

    # collapse identical repeating non-alert commands; alerts are never collapsed
    if ($level -ne 'high') {
        $dk = $user + '|' + $from + '|' + $cmd
        $now = Get-Date
        if ($Seen.ContainsKey($dk)) {
            $e = $Seen[$dk]
            if (($now - $e.Time).TotalSeconds -lt $DedupSeconds) { $e.Hits++; return }
            if ($e.Hits -gt 0) { $text += ' :: (+' + $e.Hits + ' identical since last shown)' }
        }
        $Seen[$dk] = @{ Time = $now; Hits = 0 }
    }
    Emit $t 'PROC' $text $level
}

function Handle-Task($ev, $verb) {
    $d = Get-EvData $ev
    $c = $d['TaskContent']
    $actions = @()
    foreach ($m in [regex]::Matches($c, '<Exec>(.*?)</Exec>', 'Singleline')) {
        $inner = $m.Groups[1].Value
        $cm = [regex]::Match($inner, '<Command>(.*?)</Command>', 'Singleline').Groups[1].Value
        $ar = [regex]::Match($inner, '<Arguments>(.*?)</Arguments>', 'Singleline').Groups[1].Value
        $actions += [Net.WebUtility]::HtmlDecode(($cm + ' ' + $ar).Trim())
    }
    $runas  = [regex]::Match($c, '<Principal[^>]*>.*?<UserId>(.*?)</UserId>', 'Singleline').Groups[1].Value
    $author = [Net.WebUtility]::HtmlDecode([regex]::Match($c, '<Author>(.*?)</Author>', 'Singleline').Groups[1].Value)
    $text = '{0}\{1} {2} task {3} -> {4} (runas={5} author={6})' -f $d['SubjectDomainName'], $d['SubjectUserName'], $verb, $d['TaskName'], (Clean ($actions -join ' ; ')), $runas, $author
    $text += ' :: from=' + (Get-LogonInfo $d['SubjectLogonId']).From
    Emit $ev.TimeCreated 'TASK' $text 'high'
}

$AcctText = @{
    4720 = 'account CREATED'
    4722 = 'account ENABLED'
    4724 = 'PASSWORD RESET attempt on'
    4728 = 'member added to global group'
    4732 = 'member added to local group'
}

function Handle-Event($ev) {
    $t = $ev.TimeCreated
    $id = $ev.Id
    switch ($id) {
        4688 {
            $d = Get-EvData $ev
            $creator = HexToInt $d['ProcessId']
            if ($creator -eq $PID) { return }
            $u = $d['SubjectDomainName'] + '\' + $d['SubjectUserName']
            Handle-Process $t $u $d['NewProcessName'] $d['CommandLine'] $d['ParentProcessName'] (HexToInt $d['NewProcessId']) $creator $d['SubjectLogonId']
        }
        1 {
            if ($ev.LogName -notlike '*Sysmon*') { return }
            $d = Get-EvData $ev
            $ppid = [int]$d['ParentProcessId']
            if ($ppid -eq $PID) { return }
            Handle-Process $t $d['User'] $d['Image'] $d['CommandLine'] $d['ParentImage'] ([int]$d['ProcessId']) $ppid $d['LogonId']
        }
        4104 {
            $d = Get-EvData $ev
            if ($SelfPath -and ($d['Path'] -eq $SelfPath)) { return }
            $txt = $d['ScriptBlockText']
            if ((-not $txt) -or ($txt.Trim().Length -lt 6)) { return }
            if ($txt -match $PsNoiseRx) { return }
            $part = ''
            if ($d['MessageTotal'] -and ([int]$d['MessageTotal'] -gt 1)) {
                if ([int]$d['MessageNumber'] -ne 1) { return }
                $part = ' (part 1 of ' + $d['MessageTotal'] + ')'
            }
            $hits = @(Get-HighHits $txt)
            $lvl = 'info'
            if ($ev.Level -eq 3) { $lvl = 'warn' }
            if ($hits.Count) { $lvl = 'high' }
            $src = ''
            if ($d['Path']) { $src = ' file=' + $d['Path'] }
            $from = 'n/a'
            try { if ($PidMap.ContainsKey([int]$ev.ProcessId)) { $from = $PidMap[[int]$ev.ProcessId] } } catch {}
            $text = '{0} from={1} :: {2}{3}{4}' -f (Resolve-Sid $ev.UserId), $from, (Clean $txt), $src, $part
            if ($hits.Count) { $text += ' :: ALERT[' + ($hits -join ',') + ']' }
            Emit $t 'PS' $text $lvl
        }
        4698 { Handle-Task $ev 'CREATED' }
        4702 { Handle-Task $ev 'UPDATED' }
        7045 {
            $d = Get-EvData $ev
            $text = 'service installed: {0} -> {1} (type={2} start={3} account={4})' -f $d['ServiceName'], (Clean $d['ImagePath']), $d['ServiceType'], $d['StartType'], $d['AccountName']
            Emit $t 'SVC' $text 'high'
        }
        { $_ -eq 1102 -or $_ -eq 104 } {
            $who = [regex]::Match($ev.ToXml(), '<SubjectUserName>(.*?)</SubjectUserName>').Groups[1].Value
            Emit $t 'TAMPER' ('{0} log CLEARED by {1}' -f $ev.LogName, $who) 'high'
        }
        { $_ -in 4720, 4722, 4724, 4728, 4732 } {
            $d = Get-EvData $ev
            $by = $d['SubjectDomainName'] + '\' + $d['SubjectUserName']
            $member = ''
            if ($d['MemberSid']) { $member = ' member=' + $d['MemberName'] + ' ' + $d['MemberSid'] }
            $text = '{0}: {1}{2} (by {3})' -f $AcctText[$id], $d['TargetUserName'], $member, $by
            $text += ' :: from=' + (Get-LogonInfo $d['SubjectLogonId']).From
            Emit $t 'ACCT' $text 'high'
        }
        4624 {
            $d = Get-EvData $ev
            Add-Logon $d $t                       # remember session -> IP for every logon, shown or not
            $type = $d['LogonType']
            $n = $d['TargetUserName']
            if ($n -match '\$$|^(UMFD-|DWM-)|^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON)$') { return }
            $ip = Get-SrcIp $d
            $show = @('2', '9', '10') -contains $type
            if ((-not $show) -and ($type -eq '3') -and $ShowNetworkLogons -and $ip -and ($ip -notin @('127.0.0.1', '::1'))) {
                $dk = 'L|' + $n + '|' + $ip
                $now = Get-Date
                if ($Seen.ContainsKey($dk) -and (($now - $Seen[$dk].Time).TotalSeconds -lt $DedupSeconds)) { $Seen[$dk].Hits++; return }
                $Seen[$dk] = @{ Time = $now; Hits = 0 }
                $show = $true
            }
            if (-not $show) { return }
            $text = '{0}\{1} logon type {2} from {3} ({4})' -f $d['TargetDomainName'], $n, $type, $ip, $d['WorkstationName']
            $lvl = 'warn'
            if (($type -ne '2') -and (Test-Untrusted $ip)) { $lvl = 'high'; $text += ' :: ALERT[UNTRUSTED-SRC:' + $ip + ']' }
            Emit $t 'LOGON' $text $lvl
        }
        4625 {
            $d = Get-EvData $ev
            $text = 'FAILED logon {0}\{1} type {2} from {3} (status {4})' -f $d['TargetDomainName'], $d['TargetUserName'], $d['LogonType'], $d['IpAddress'], $d['Status']
            Emit $t 'LOGON' $text 'warn'
        }
        5861 {
            Emit $t 'WMI' ('permanent WMI event subscription: ' + (Clean $ev.Message 600)) 'high'
        }
        { $_ -in 1116, 1117 } {
            Emit $t 'AV' ('Defender: ' + (Clean $ev.Message 400)) 'high'
        }
        5001 {
            Emit $t 'AV' 'Defender real-time protection was DISABLED' 'high'
        }
        4719 {
            if (($t -ge $script:AuditStart.AddSeconds(-2)) -and ($t -le $script:AuditEnd.AddSeconds(5))) { return }
            $d = Get-EvData $ev
            $text = 'audit policy changed by {0}\{1}: subcategory={2} change={3}' -f $d['SubjectDomainName'], $d['SubjectUserName'], $d['SubcategoryGuid'], $d['AuditPolicyChanges']
            Emit $t 'TAMPER' $text 'high'
        }
    }
}

function Ensure-Audit([bool]$FirstRun) {
    $script:AuditStart = Get-Date
    $null = New-Item -ItemType Directory -Path $TranscriptDir -Force -ErrorAction SilentlyContinue
    foreach ($g in $AuditGuids) {
        & auditpol.exe /set "/subcategory:$g" /success:enable /failure:enable 2>&1 | Out-Null
    }
    foreach ($r in $RegChecks) {
        try {
            if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
            $cur = (Get-ItemProperty -Path $r.Path -Name $r.Name -ErrorAction SilentlyContinue).($r.Name)
            if ($cur -ne $r.Value) {
                New-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Value -PropertyType $r.Type -Force | Out-Null
                if (-not $FirstRun) {
                    Emit (Get-Date) 'TAMPER' ('logging setting was changed, reset: ' + $r.Name + ' (was ' + $cur + ')') 'high'
                }
            }
        } catch {}
    }
    $script:AuditEnd = Get-Date
}

function Disable-QuickEdit {
    # A click in the console would otherwise pause the loop (QuickEdit).
    try {
        if (-not ('CmdWatchConsole' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CmdWatchConsole {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr GetStdHandle(int n);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetConsoleMode(IntPtr h, out uint mode);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleMode(IntPtr h, uint mode);
}
'@
        }
        $h = [CmdWatchConsole]::GetStdHandle(-10)
        [uint32]$mode = 0
        if ([CmdWatchConsole]::GetConsoleMode($h, [ref]$mode)) {
            [uint32]$new = ($mode -bor 0x0080) -band (-bnot 0x0040)
            [void][CmdWatchConsole]::SetConsoleMode($h, $new)
        }
    } catch {}
}

function Get-LastId([string]$log) {
    try { return [int64](Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction Stop).RecordId }
    catch { return $null }
}

function New-Source([string]$log, $ids) {
    return @{ Log = $log; Ids = $ids; Last = [int64]0; Err = $false }
}

function Poll-Source($s) {
    $clause = ($s.Ids | ForEach-Object { 'EventID=' + $_ }) -join ' or '
    $xp = '*[System[(' + $clause + ') and EventRecordID>' + $s.Last + ']]'
    try {
        $evs = Get-WinEvent -LogName $s.Log -FilterXPath $xp -ErrorAction Stop
    } catch {
        $noMatch = ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') -or ($_.Exception.Message -match 'No events were found')
        if ((-not $noMatch) -and (-not $s.Err)) {
            Emit (Get-Date) 'TAMPER' ('cannot read log ' + $s.Log + ': ' + $_.Exception.Message) 'high'
            $s.Err = $true
        }
        return
    }
    $s.Err = $false
    foreach ($ev in ($evs | Sort-Object -Property RecordId)) {
        $s.Last = [int64]$ev.RecordId
        try { Handle-Event $ev }
        catch { Emit (Get-Date) 'ERROR' ('event ' + $ev.Id + ' in ' + $s.Log + ': ' + $_.Exception.Message) 'info' }
    }
}

# ------------------------------ startup ------------------------------
Disable-QuickEdit
Ensure-Audit $true
& wevtutil.exe sl Security "/ms:$($SecLogSizeMB * 1MB)" 2>&1 | Out-Null
& wevtutil.exe sl 'Microsoft-Windows-PowerShell/Operational' "/ms:$(128 * 1MB)" 2>&1 | Out-Null

$useSysmon = $false
try {
    $sl = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    if ($sl.IsEnabled) { $useSysmon = $true }
} catch {}

$secIds = @(4698, 4702, 4720, 4722, 4724, 4728, 4732, 4624, 4625, 4719, 1102)
if (-not $useSysmon) { $secIds += 4688 }
# order matters: logons (Security) first, then process creation, then PowerShell script
# blocks, so each script block can be tagged with the source of its process
$sources = @((New-Source 'Security' $secIds))
if ($useSysmon) { $sources += , (New-Source 'Microsoft-Windows-Sysmon/Operational' @(1)) }
$sources += , (New-Source 'System' @(7045, 104))
$sources += , (New-Source 'Microsoft-Windows-PowerShell/Operational' @(4104))

# optional logs: only watched if they exist on this host
function Add-Source([string]$log, $ids) {
    try {
        $null = Get-WinEvent -ListLog $log -ErrorAction Stop
        $script:sources += , (New-Source $log $ids)
    } catch {}
}
Add-Source 'Microsoft-Windows-WMI-Activity/Operational' @(5861)
Add-Source 'Microsoft-Windows-Windows Defender/Operational' @(1116, 1117, 5001)

# start from "now" so old history is not replayed
foreach ($s in $sources) {
    $last = Get-LastId $s.Log
    if ($null -eq $last) { $last = 0 }
    $s.Last = [int64]$last
}

# prime the logon table so sessions that began before cmdwatch already have an IP
try {
    $bf = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddHours(-$LogonBackfillHours) } -MaxEvents 4000 -ErrorAction Stop
    foreach ($e in ($bf | Sort-Object TimeCreated)) { Add-Logon (Get-EvData $e) $e.TimeCreated }
} catch {}

$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
Emit (Get-Date) 'START' ("cmdwatch running as $me on $env:COMPUTERNAME | sysmon=$useSysmon | known logon sessions=$($LogonMap.Count) | logs in $LogDir") 'info'

# ------------------------------- main loop ------------------------------
$cycle = 0
$lastAudit = Get-Date
while ($true) {
    foreach ($s in $sources) { Poll-Source $s }
    $cycle++

    if (((Get-Date) - $lastAudit).TotalSeconds -ge $AuditRefreshS) {
        Ensure-Audit $false
        $lastAudit = Get-Date
    }

    # forget old de-dup entries
    if (($cycle % 150) -eq 0) {
        $stale = @($Seen.Keys | Where-Object { ((Get-Date) - $Seen[$_].Time).TotalMinutes -gt 10 })
        foreach ($k in $stale) { $Seen.Remove($k) }
        Prune-Logons
    }

    # detect a log that was cleared/reset (record numbers going backwards)
    if (($cycle % 15) -eq 0) {
        foreach ($s in $sources) {
            $latest = Get-LastId $s.Log
            if (($null -ne $latest) -and ($latest -lt $s.Last)) {
                Emit (Get-Date) 'TAMPER' ('record numbers went backwards in ' + $s.Log + ' (log cleared or reset), resyncing') 'high'
                $s.Last = 0
            }
        }
    }
    Start-Sleep -Seconds $PollSeconds
}
