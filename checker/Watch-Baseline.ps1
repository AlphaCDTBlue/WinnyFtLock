#requires -Version 5.1
# v3: 10-second inventory, 30-second append-only output; no automatic remediation.
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
$processOutput = Join-Path $OutputDirectory 'unfamiliar-processes.csv'
$serviceOutput = Join-Path $OutputDirectory 'unfamiliar-services.csv'
$columns = @('ObservationId','RunId','PollId','ObservedUtc','Host','Name','Path','Reason',
             'Instances','PIDs','CommandLines','ServiceState','ServiceAccount')
$header = ($columns | ForEach-Object { '"' + $_ + '"' }) -join ','
$utf8 = [Text.UTF8Encoding]::new($true)
$runId = [guid]::NewGuid().ToString('N')
$processQueue = [Collections.Generic.List[object]]::new()
$serviceQueue = [Collections.Generic.List[object]]::new()
$clock = [Diagnostics.Stopwatch]::StartNew()
$health = @{ Process='Not scanned'; Service='Not scanned'; Poll=0 }
$lock = $null
$ownsLock = $false

function Initialize-Csv([string]$File) {
    # CreateNew fails if another writer creates it first; existing data is never truncated.
    if (-not [IO.File]::Exists($File)) {
        $stream = [IO.File]::Open($File, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $writer = [IO.StreamWriter]::new($stream, $utf8)
        try { $writer.WriteLine($header) } finally { $writer.Dispose() }
    } else {
        $reader = [IO.StreamReader]::new($File, $true)
        try { $actualHeader = $reader.ReadLine() } finally { $reader.Dispose() }
        if ($actualHeader -cne $header) {
            throw "Existing CSV has a different schema: $File. Preserved unchanged. Choose another -OutputDirectory."
        }
    }
}
function Append-Queue($Queue, [string]$File) {
    if ($Queue.Count -eq 0) { return 0 }
    # Retain queued rows on failure for retry. ObservationId allows deduplication
    # if an interrupted partial append is retried.
    $count = $Queue.Count
    $lines = @($Queue.ToArray() | Select-Object -Property $columns | ConvertTo-Csv -NoTypeInformation)
    $stream = [IO.File]::Open($File, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    $writer = [IO.StreamWriter]::new($stream, $utf8)
    try {
        for ($i=1; $i -lt $lines.Count; $i++) { $writer.WriteLine($lines[$i]) }
        $writer.Flush()
    } finally { $writer.Dispose() }
    $Queue.Clear()
    return $count
}
function Flush-Findings {
    $p = '0'; $s = '0'
    try { $p = [string](Append-Queue $processQueue $processOutput) }
    catch { $p = 'FAILED'; Write-Warning ("Process CSV append failed; queued for retry: " + $_.Exception.Message) }
    try { $s = [string](Append-Queue $serviceQueue $serviceOutput) }
    catch { $s = 'FAILED'; Write-Warning ("Service CSV append failed; queued for retry: " + $_.Exception.Message) }
    Write-Host ('[{0}] Poll {1}; processes={2}; services={3}; appended process rows={4}, service rows={5}; pending={6}' -f
        (Get-Date -Format 'HH:mm:ss'), $health.Poll, $health.Process, $health.Service,
        $p, $s, ($processQueue.Count + $serviceQueue.Count))
}
function Collect-Findings([string]$Kind, $Baseline, $Queue, [int]$PollId) {
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
    foreach ($r in $groups.Values) {
        $Queue.Add($r)
        Write-Host ('[{0}] {1}: {2} | {3} | {4}' -f (Get-Date -Format 'HH:mm:ss'), $Kind, $r.Reason, $r.Name, $r.Path) -ForegroundColor Yellow
    }
    $health[$Kind] = "OK ($examined checked)"
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
    Initialize-Csv $processOutput
    Initialize-Csv $serviceOutput
    Write-Host "Output: $OutputDirectory"
    Write-Host "Scan: $PollIntervalSeconds seconds; append: $WriteIntervalSeconds seconds. Existing CSV rows are preserved."
    if ($AllowBaselineMissingPaths) { Write-Warning 'Explicit baseline blank-path process entries match by name only.' }
    $nextPoll = 0.0
    $nextWrite = [double]$WriteIntervalSeconds
    do {
        $now = $clock.Elapsed.TotalSeconds
        if ($now -ge $nextPoll) {
            $pollStarted = $now
            $health.Poll++
            try { Collect-Findings 'Process' $processSet $processQueue $health.Poll }
            catch { $health.Process = 'ERROR'; Write-Warning ("Process scan failed: " + $_.Exception.Message) }
            try { Collect-Findings 'Service' $serviceSet $serviceQueue $health.Poll }
            catch { $health.Service = 'ERROR'; Write-Warning ("Service scan failed: " + $_.Exception.Message) }
            # No overlapping scans or catch-up storm when CIM is slow.
            $nextPoll = [Math]::Max(($pollStarted + $PollIntervalSeconds), ($clock.Elapsed.TotalSeconds + 0.1))
        }
        if ($Once -or $clock.Elapsed.TotalSeconds -ge $nextWrite) {
            Flush-Findings
            $nextWrite = $clock.Elapsed.TotalSeconds + $WriteIntervalSeconds
        }
        if (($processQueue.Count + $serviceQueue.Count) -gt 10000) {
            throw 'Over 10,000 rows pending: output writes may be blocked. Stopping rather than silently discarding observations.'
        }
        if (-not $Once) { Start-Sleep -Milliseconds 200 }
    } while (-not $Once)
} finally {
    if ($ownsLock) {
        # Best effort on graceful Ctrl+C; hard termination/power loss can lose unflushed rows.
        try {
            if (($processQueue.Count + $serviceQueue.Count) -gt 0) { Flush-Findings }
        } finally { $lock.ReleaseMutex() }
    }
    if ($null -ne $lock) { $lock.Dispose() }
    Write-Host "Watcher stopped. Existing findings remain in $OutputDirectory"
}
