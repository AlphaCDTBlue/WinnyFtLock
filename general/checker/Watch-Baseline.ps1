#requires -Version 5.1
# v5.1: 10-second inventory, 30-second persistent summaries; independent readable copies.
[CmdletBinding()]
param(
    [string]$ProcessBaseline,
    [string]$ServiceBaseline,
    [Alias('IntervalSeconds')][ValidateRange(1,86400)][int]$PollIntervalSeconds = 10,
    [ValidateRange(1,86400)][int]$WriteIntervalSeconds = 30,
    [string]$OutputDirectory,
    [switch]$Once,
    [switch]$IncludeStoppedServices,
    [switch]$AllowBaselineMissingPaths
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$baselineRoot = $PSScriptRoot
if (-not $baselineRoot) { $baselineRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $ProcessBaseline) { $ProcessBaseline = Join-Path $baselineRoot 'baseline-processes.csv' }
if (-not $ServiceBaseline) { $ServiceBaseline = Join-Path $baselineRoot 'baseline-services.csv' }

function Disable-QuickEdit {
    # Current attached console only; no registry or persistent defaults changed.
    # Microsoft Learn: windows/console/setconsolemode
    if (-not ('BaselineWatchV3.ConsoleMode' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace BaselineWatchV3 {
    public static class ConsoleMode {
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr GetStdHandle(int nStdHandle);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool GetConsoleMode(IntPtr h, out uint mode);
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool SetConsoleMode(IntPtr h, uint mode);
    }
}
'@
    }
    $handle = [BaselineWatchV3.ConsoleMode]::GetStdHandle(-10)
    [uint32]$mode = 0
    if (-not [BaselineWatchV3.ConsoleMode]::GetConsoleMode($handle, [ref]$mode)) {
        Write-Warning 'No accessible classic console input handle. QuickEdit could not be checked (for example, headless/ISE).'
        return
    }
    [uint32]$newMode = ($mode -bor 0x0080) -band (-bnot 0x0040)
    if (-not [BaselineWatchV3.ConsoleMode]::SetConsoleMode($handle, $newMode)) {
        throw "Cannot disable QuickEdit. Win32 error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    [uint32]$verified = 0
    if ((-not [BaselineWatchV3.ConsoleMode]::GetConsoleMode($handle, [ref]$verified)) -or (($verified -band 0x0040) -ne 0)) {
        throw 'QuickEdit disable verification failed.'
    }
    Write-Host 'QuickEdit: DISABLED and verified for this console session.'
}
Disable-QuickEdit
function Get-Clean([object]$Value) {
    $s = ([string]$Value).Trim()
    if ($s -eq '-') { return '' }
    return $s
}
function Get-Key([string]$Name, [string]$Path) {
    # Length prefix makes the pair unambiguous even if values contain separators.
    $n = Get-Clean $Name
    $p = Get-Clean $Path
    return ('{0}:{1}{2}' -f $n.Length, $n, $p)
}
function Read-Baseline([string]$File) {
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) {
        throw "Baseline CSV not found: $File"
    }
    $rows = @(Import-Csv -LiteralPath $File -Encoding UTF8)
    if ($rows.Count -eq 0) { throw "Baseline CSV is empty: $File" }
    $columns = @($rows[0].PSObject.Properties.Name)
    if (($columns -notcontains 'Name') -or ($columns -notcontains 'Path')) {
        throw "Baseline CSV needs Name and Path columns: $File"
    }
    $pairs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $missingPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $rows) {
        $n = Get-Clean $row.Name
        $p = Get-Clean $row.Path
        if (-not $n) { continue }
        [void]$names.Add($n)
        # Missing paths are tracked separately, never as a wildcard for a real path.
        if ($p) { [void]$pairs.Add((Get-Key $n $p)) }
        else { [void]$missingPaths.Add($n) }
    }
    if ($names.Count -eq 0) { throw "Baseline CSV has no names: $File" }
    return @{ Pairs = $pairs; Names = $names; MissingPaths = $missingPaths }
}
function Get-Reason($Baseline, [string]$Name, [string]$Path, [switch]$AllowMissingPath) {
    if (-not $Path) {
        if ($AllowMissingPath -and $Baseline.MissingPaths.Contains($Name)) { return '' }
        return 'PathUnavailable'
    }
    if ($Baseline.Pairs.Contains((Get-Key $Name $Path))) { return '' }
    if ($Baseline.Names.Contains($Name)) { return 'DifferentPath' }
    return 'NewName'
}
$processSet = Read-Baseline $ProcessBaseline
$serviceSet = Read-Baseline $ServiceBaseline
if (-not $OutputDirectory) {
    $desktop = [Environment]::GetFolderPath('DesktopDirectory')
    if (-not $desktop) { throw 'This account has no Desktop. Supply -OutputDirectory.' }
    $OutputDirectory = Join-Path $desktop ('BaselineWatch-' + $env:COMPUTERNAME)
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force)
$dataDirectory = Join-Path $OutputDirectory '_data'
[void](New-Item -ItemType Directory -Path $dataDirectory -Force)
$processView = Join-Path $OutputDirectory 'unfamiliar-processes.csv'
$serviceView = Join-Path $OutputDirectory 'unfamiliar-services.csv'
$processOutput = Join-Path $dataDirectory 'unfamiliar-processes.csv'
$serviceOutput = Join-Path $dataDirectory 'unfamiliar-services.csv'
$viewStatus = @{ ProcessError=''; ServiceError=''; Pending=$false }

$columns = @('Host','Name','Path','Reason','FirstSeenUtc','LastSeenUtc','TimesSeen',
             'InstancesLastSeen','LastPIDs','LastCommandLines','ServiceState','ServiceAccount')
$header = ($columns | ForEach-Object { '"' + $_ + '"' }) -join ','
$legacyColumns = @('ObservationId','RunId','PollId','ObservedUtc','Host','Name','Path','Reason',
                  'Instances','PIDs','CommandLines','ServiceState','ServiceAccount')
$legacyHeader = ($legacyColumns | ForEach-Object { '"' + $_ + '"' }) -join ','
$utf8 = [Text.UTF8Encoding]::new($true)
$runId = [guid]::NewGuid().ToString('N')
function New-SummaryState {
    return @{
        Rows=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
        Dirty=$false; LastWriteError=''
    }
}
$processState = New-SummaryState
$serviceState = New-SummaryState
$clock = [Diagnostics.Stopwatch]::StartNew()
$health = @{ Process='Not scanned'; Service='Not scanned'; Poll=0; Saved='Not yet';
             ProcessError=''; ServiceError='' }
$lock = $null
$ownsLock = $false
$ready = $false

function Merge-Observation($State, $Observation, [switch]$Announce) {
    $key = Get-Key $Observation.Name $Observation.Path
    if (-not $State.Rows.ContainsKey($key)) {
        $State.Rows[$key] = [pscustomobject][ordered]@{
            Host=$Observation.Host; Name=$Observation.Name; Path=$Observation.Path; Reason=$Observation.Reason;
            FirstSeenUtc=$Observation.ObservedUtc; LastSeenUtc=$Observation.ObservedUtc;
            TimesSeen=[long]0; InstancesLastSeen=0; LastPIDs=''; LastCommandLines='';
            ServiceState=''; ServiceAccount=''
        }
        if ($Announce) {
            Write-Host ('[{0}] NEW {1}: {2} | {3}' -f (Get-Date -Format 'HH:mm:ss'),
                $Observation.Reason, $Observation.Name, $Observation.Path) -ForegroundColor Yellow
        }
    }
    $r = $State.Rows[$key]
    $r.TimesSeen = [long]$r.TimesSeen + 1
    if ([DateTimeOffset]::Parse($Observation.ObservedUtc) -lt [DateTimeOffset]::Parse($r.FirstSeenUtc)) {
        $r.FirstSeenUtc = $Observation.ObservedUtc
    }
    if ([DateTimeOffset]::Parse($Observation.ObservedUtc) -ge [DateTimeOffset]::Parse($r.LastSeenUtc)) {
        $r.LastSeenUtc=$Observation.ObservedUtc
        $r.Reason=$Observation.Reason
        $r.InstancesLastSeen=$Observation.Instances
        $r.LastPIDs=$Observation.PIDs
        $r.LastCommandLines=$Observation.CommandLines
        $r.ServiceState=$Observation.ServiceState
        $r.ServiceAccount=$Observation.ServiceAccount
    }
    $State.Dirty=$true
}
function Load-Summary($State, [string]$File) {
    if (-not [IO.File]::Exists($File)) { $State.Dirty=$true; return }
    $reader=[IO.StreamReader]::new($File,$true)
    try { $existingHeader=$reader.ReadLine() } finally { $reader.Dispose() }
    if ($existingHeader -ceq $header) {
        foreach ($r in @(Import-Csv -LiteralPath $File -Encoding UTF8)) {
            $key=Get-Key $r.Name $r.Path
            if ($State.Rows.ContainsKey($key)) { throw "Duplicate summary key in $File; file preserved." }
            $r.TimesSeen=[long]$r.TimesSeen
            if ($r.TimesSeen -lt 1) { throw "Invalid TimesSeen in $File" }
            [void][DateTimeOffset]::Parse($r.FirstSeenUtc)
            [void][DateTimeOffset]::Parse($r.LastSeenUtc)
            $State.Rows.Add($key,$r)
        }
    } elseif ($existingHeader -ceq $legacyHeader) {
        # Count each v3 observation once; ignore repeats of identical ObservationId.
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        Import-Csv -LiteralPath $File -Encoding UTF8 | ForEach-Object {
            if (-not $_.ObservationId) { throw "Missing v3 ObservationId in $File; file preserved." }
            if ($seen.Add($_.ObservationId)) {
                [void][DateTimeOffset]::Parse($_.ObservedUtc)
                Merge-Observation $State $_
            }
        }
        $archive=Join-Path $OutputDirectory 'v3-originals'
        [void](New-Item -ItemType Directory -Path $archive -Force)
        $backup=Join-Path $archive (([IO.Path]::GetFileNameWithoutExtension($File))+'-'+[guid]::NewGuid().ToString('N')+'.csv')
        [IO.File]::Copy($File,$backup,$false)
        $State.Dirty=$true
        Write-Host "Consolidated v3 history: $File (original saved in v3-originals)."
    } else {
        throw "Unsupported results CSV header: $File. Existing data preserved."
    }
}
function Save-Summary($State, [string]$File) {
    if (-not $State.Dirty) { return }
    $temp=$File+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try {
        if ($State.Rows.Count -gt 0) {
            [string[]]$lines=@($State.Rows.Values | Sort-Object Name,Path |
                Select-Object -Property $columns | ConvertTo-Csv -NoTypeInformation)
        } else { [string[]]$lines=@($header) }
        [IO.File]::WriteAllLines($temp,$lines,$utf8)
        # Windows PowerShell 5.1 may bind $null to an empty string here.
        # Always supply a concrete backup pathname to File.Replace.
        Install-PreparedFile $temp $File
        $State.Dirty=$false
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}

function Install-PreparedFile([string]$Temp, [string]$Destination) {
    if ([IO.File]::Exists($Destination)) {
        $backup=$Temp+'.previous'
        [IO.File]::Replace($Temp,$Destination,$backup)
        # The new destination is committed. Backup cleanup failure is nonfatal.
        try { if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) } }
        catch { Write-Warning "Saved successfully, but could not remove temporary backup: $backup" }
    } else {
        [IO.File]::Move($Temp,$Destination)
    }
}
function Publish-View([string]$Source, [string]$Destination) {
    $temp=$Destination+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try {
        [IO.File]::Copy($Source,$temp,$false)
        Install-PreparedFile $temp $Destination
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}
function Flush-Findings {
    foreach ($entry in @(@{State=$processState;File=$processOutput},@{State=$serviceState;File=$serviceOutput})) {
        $state=$entry.State
        try {
            Save-Summary $state $entry.File
            if ($state.LastWriteError) {
                Write-Host "Main CSV writes recovered: $($entry.File)"
                $state.LastWriteError=''
            }
        } catch {
            $message=$_.Exception.Message
            if ($state.LastWriteError -ne $message) {
                Write-Warning "MAIN CSV SAVE FAILED; counts retained in memory for retry. $($entry.File): $message"
            }
            $state.LastWriteError=$message
        }
    }
    if (-not $processState.Dirty -and -not $serviceState.Dirty) { $health.Saved=Get-Date -Format 'HH:mm:ss' }
    $viewStatus.Pending=$false
    foreach ($entry in @(@{Source=$processOutput;Destination=$processView;Field='ProcessError';State=$processState},
                        @{Source=$serviceOutput;Destination=$serviceView;Field='ServiceError';State=$serviceState})) {
        try {
            if ($entry.State.Dirty) {
                $viewStatus.Pending=$true
                continue
            }
            Publish-View $entry.Source $entry.Destination
            if ($viewStatus[$entry.Field]) {
                Write-Host "Readable copy refreshed: $($entry.Destination)"
                $viewStatus[$entry.Field]=''
            }
        } catch {
            $viewStatus.Pending=$true
            $message=$_.Exception.Message
            if ($viewStatus[$entry.Field] -ne $message) {
                Write-Warning "Main CSV is saved in _data. Readable copy refresh failed; retrying every write cycle. $($entry.Destination): $message"
            }
            $viewStatus[$entry.Field]=$message
        }
    }
    try {
        $Host.UI.RawUI.WindowTitle=('BaselineWatch | poll {0} | P:{1} S:{2} | main saved {3} | data pending {4} | view pending {5}' -f
            $health.Poll,$health.Process,$health.Service,$health.Saved,
            ($processState.Dirty -or $serviceState.Dirty),$viewStatus.Pending)
    } catch { }
}
function Report-ScanFailure([string]$Kind, [string]$Message) {
    $health[$Kind]='ERROR'
    $field=$Kind+'Error'
    if ($health[$field] -ne $Message) { Write-Warning "$Kind scan failed: $Message" }
    $health[$field]=$Message
}
function Collect-Findings([string]$Kind, $Baseline, $State, [int]$PollId) {
    if ($Kind -eq 'Process') {
        $items = @(Get-CimInstance -ClassName Win32_Process -OperationTimeoutSec 10 -ErrorAction Stop)
    } else {
        $items = @(Get-CimInstance -ClassName Win32_Service -OperationTimeoutSec 10 -ErrorAction Stop)
    }
    $observed = [DateTime]::UtcNow.ToString('o')
    $groups = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    $examined = 0
    foreach ($item in $items) {
        if (($Kind -eq 'Service') -and (-not $IncludeStoppedServices) -and ($item.State -ne 'Running')) { continue }
        $examined++
        $n = Get-Clean $item.Name
        if ($Kind -eq 'Process') { $path = Get-Clean $item.ExecutablePath }
        else { $path = Get-Clean $item.PathName }
        $reason = Get-Reason $Baseline $n $path -AllowMissingPath:($AllowBaselineMissingPaths -and $Kind -eq 'Process')
        if (-not $reason) { continue }
        $key = Get-Key $n $path
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = [pscustomobject][ordered]@{
                ObservationId=[guid]::NewGuid().ToString('N'); RunId=$runId; PollId=$PollId;
                ObservedUtc=$observed; Host=$env:COMPUTERNAME; Name=$n; Path=$path; Reason=$reason;
                Instances=0; PIDs=''; CommandLines=''; ServiceState=''; ServiceAccount=''
            }
        }
        $r = $groups[$key]
        $r.Instances++
        if ($r.PIDs) { $r.PIDs += ';' }
        $r.PIDs += [string]$item.ProcessId
        if ($Kind -eq 'Process') {
            if ($r.CommandLines) { $r.CommandLines += ' | ' }
            $r.CommandLines += [string]$item.CommandLine
        } else {
            $r.ServiceState = [string]$item.State
            $r.ServiceAccount = [string]$item.StartName
        }
    }
    foreach ($r in $groups.Values) { Merge-Observation $State $r -Announce }
    $health[$Kind] = "OK ($examined)"
    $health[$Kind+'Error']=''

}
try {
    # Same folder may be resumed, but never concurrently written by two instances.
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($OutputDirectory.ToLowerInvariant()))).Replace('-','') }
    finally { $sha.Dispose() }
    $lock = [Threading.Mutex]::new($false, ('Global\BaselineWatch-' + $hash))
    try { $ownsLock = $lock.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $ownsLock = $true }
    if (-not $ownsLock) { throw 'A watcher is already writing to this output folder. Stop that instance first.' }
    # On first upgrade only, import existing root findings. Once _data exists,
    # it is authoritative; never import later edits made to the readable copies.
    foreach ($entry in @(@{Source=$processView;Destination=$processOutput},
                        @{Source=$serviceView;Destination=$serviceOutput})) {
        if ((-not [IO.File]::Exists($entry.Destination)) -and [IO.File]::Exists($entry.Source)) {
            [IO.File]::Copy($entry.Source,$entry.Destination,$false)
        }
    }
    Load-Summary $processState $processOutput
    Load-Summary $serviceState $serviceOutput
    $ready = $true
    Flush-Findings
    Write-Host "Watch-Baseline v5.1 | fixed file replacement | independent readable copies"
    Write-Host "Readable copies: $OutputDirectory"
    Write-Host "Main CSVs (leave closed): $dataDirectory"
    Write-Host "Scan: $PollIntervalSeconds seconds; save summaries: $WriteIntervalSeconds seconds. One row per name/path; counts survive restarts."
    if ($AllowBaselineMissingPaths) { Write-Warning 'Explicit baseline blank-path process entries match by name only.' }
    $nextPoll = 0.0
    $nextWrite = [double]$WriteIntervalSeconds
    do {
        $now = $clock.Elapsed.TotalSeconds
        if ($now -ge $nextPoll) {
            $pollStarted = $now
            $health.Poll++
            try { Collect-Findings 'Process' $processSet $processState $health.Poll }
            catch { Report-ScanFailure 'Process' $_.Exception.Message }
            try { Collect-Findings 'Service' $serviceSet $serviceState $health.Poll }
            catch { Report-ScanFailure 'Service' $_.Exception.Message }
            # No overlapping scans or catch-up storm when CIM is slow.
            $nextPoll = [Math]::Max(($pollStarted + $PollIntervalSeconds), ($clock.Elapsed.TotalSeconds + 0.1))
        }
        if ($Once -or $clock.Elapsed.TotalSeconds -ge $nextWrite) {
            Flush-Findings
            $nextWrite = $clock.Elapsed.TotalSeconds + $WriteIntervalSeconds
        }
        if (-not $Once) { Start-Sleep -Milliseconds 200 }
    } while (-not $Once)
} finally {
    if ($ownsLock) {
        # Best effort on graceful Ctrl+C; hard termination/power loss can lose unsaved counts.
        try {
            if ($ready -and ($processState.Dirty -or $serviceState.Dirty)) { Flush-Findings }
        } finally { $lock.ReleaseMutex() }
    }
    if ($null -ne $lock) { $lock.Dispose() }
    Write-Host "Watcher stopped. Existing findings remain in $OutputDirectory"
}
