#requires -Version 5.1
<#
Read-only host inventory monitor. Does not stop/change processes or services.
Baseline input defaults to the two CSVs beside this script.
Outputs go to the invoking user's Desktop, in a new folder for each run.
#>
[CmdletBinding()]
param(
    [string]$ProcessBaseline = (Join-Path $PSScriptRoot 'baseline-processes.csv'),
    [string]$ServiceBaseline = (Join-Path $PSScriptRoot 'baseline-services.csv'),
    [ValidateRange(1,86400)][int]$IntervalSeconds = 30,
    [string]$OutputDirectory,
    [switch]$Once,
    [switch]$IncludeStoppedServices
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

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
    foreach ($row in $rows) {
        $n = Get-Clean $row.Name
        $p = Get-Clean $row.Path
        if (-not $n) { continue }
        [void]$names.Add($n)
        # Unknown baseline paths never authorize a path or a missing path.
        if ($p) { [void]$pairs.Add((Get-Key $n $p)) }
    }
    if ($names.Count -eq 0) { throw "Baseline CSV has no names: $File" }
    return @{ Pairs = $pairs; Names = $names }
}
function Get-Reason($Baseline, [string]$Name, [string]$Path) {
    if (-not $Path) { return 'PathUnavailable' }
    if ($Baseline.Pairs.Contains((Get-Key $Name $Path))) { return '' }
    if ($Baseline.Names.Contains($Name)) { return 'DifferentPath' }
    return 'NewName'
}
$processSet = Read-Baseline $ProcessBaseline
$serviceSet = Read-Baseline $ServiceBaseline

if (-not $OutputDirectory) {
    $desktop = [Environment]::GetFolderPath('DesktopDirectory')
    if (-not $desktop) {
        throw 'This account has no Desktop. Supply -OutputDirectory explicitly.'
    }
    $OutputDirectory = Join-Path $desktop ('BaselineWatch-{0}-{1}-{2}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID)
}
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force)
$processOutput = Join-Path $OutputDirectory 'unfamiliar-processes.csv'
$serviceOutput = Join-Path $OutputDirectory 'unfamiliar-services.csv'
$errorOutput = Join-Path $OutputDirectory 'watcher-errors.log'
# Never overwrite results from a prior run supplied explicitly.
if ((Test-Path -LiteralPath $processOutput) -or (Test-Path -LiteralPath $serviceOutput)) {
    throw 'Output folder already has finding CSVs. Choose a new folder.'
}
$columns = @('Host','Name','Path','Reason','FirstSeenUtc','LastSeenUtc',
             'PollsSeen','InstancesLastSeen','LastPIDs','LastCommandLine','ServiceState','ServiceAccount')
$header = ($columns | ForEach-Object { '"' + $_ + '"' }) -join ','
Set-Content -LiteralPath $processOutput -Value $header -Encoding UTF8
Set-Content -LiteralPath $serviceOutput -Value $header -Encoding UTF8

$processFindings = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
$serviceFindings = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Write-WatcherError([string]$Area, [string]$Message) {
    $line = '{0} {1}: {2}' -f [DateTime]::UtcNow.ToString('o'), $Area, $Message
    Add-Content -LiteralPath $errorOutput -Value $line -Encoding UTF8
    Write-Warning $line
}
function Update-Finding($Store, $PollSeen, [string]$Name, [string]$Path,
                        [string]$Reason, [string]$Time, [object]$Item, [string]$Kind) {
    $key = Get-Key $Name $Path
    if (-not $Store.ContainsKey($key)) {
        $Store[$key] = [pscustomobject][ordered]@{
            Host=$env:COMPUTERNAME; Name=$Name; Path=$Path; Reason=$Reason;
            FirstSeenUtc=$Time; LastSeenUtc=$Time; PollsSeen=0; InstancesLastSeen=0;
            LastPIDs=''; LastCommandLine=''; ServiceState=''; ServiceAccount=''
        }
        Write-Host ('[{0}] {1}: {2} | {3} | {4}' -f (Get-Date -Format 'HH:mm:ss'), $Kind, $Reason, $Name, $Path) -ForegroundColor Yellow
    }
    $r = $Store[$key]
    if ($PollSeen.Add($key)) {
        $r.PollsSeen++
        $r.InstancesLastSeen = 0
        $r.LastPIDs = ''
    }
    $r.LastSeenUtc = $Time
    $r.InstancesLastSeen++
    if ($r.LastPIDs) { $r.LastPIDs += ';' }
    $r.LastPIDs += [string]$Item.ProcessId
    if ($Kind -eq 'Process') {
        $r.LastCommandLine = [string]$Item.CommandLine
    } else {
        $r.ServiceState = [string]$Item.State
        $r.ServiceAccount = [string]$Item.StartName
    }
}
function Save-Findings($Store, [string]$Destination) {
    if ($Store.Count -eq 0) { return }
    $temp = $Destination + '.tmp'
    try {
        $Store.Values | Sort-Object Name,Path |
            Select-Object -Property $columns |
            Export-Csv -LiteralPath $temp -NoTypeInformation -Encoding UTF8
        Move-Item -LiteralPath $temp -Destination $Destination -Force
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}
Write-Host "Baseline watcher: $OutputDirectory"
Write-Host "Poll interval: $IntervalSeconds seconds. Ctrl+C stops. Familiar = name + path from any host."
Write-Host 'Blank/inaccessible paths are reported for review. Run elevated to improve path visibility.'
try {
    do {
        $time = [DateTime]::UtcNow.ToString('o')
        $pollSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            $items = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
            foreach ($item in $items) {
                $n = Get-Clean $item.Name
                $p = Get-Clean $item.ExecutablePath
                $reason = Get-Reason $processSet $n $p
                if ($reason) { Update-Finding $processFindings $pollSeen $n $p $reason $time $item 'Process' }
            }
        } catch { Write-WatcherError 'Process inventory' $_.Exception.Message }
        $pollSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            $items = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
            foreach ($item in $items) {
                if ((-not $IncludeStoppedServices) -and $item.State -ne 'Running') { continue }
                $n = Get-Clean $item.Name
                $p = Get-Clean $item.PathName
                $reason = Get-Reason $serviceSet $n $p
                if ($reason) { Update-Finding $serviceFindings $pollSeen $n $p $reason $time $item 'Service' }
            }
        } catch { Write-WatcherError 'Service inventory' $_.Exception.Message }
        try { Save-Findings $processFindings $processOutput }
        catch { Write-WatcherError 'Write process CSV (close it in Excel if locked)' $_.Exception.Message }
        try { Save-Findings $serviceFindings $serviceOutput }
        catch { Write-WatcherError 'Write service CSV (close it in Excel if locked)' $_.Exception.Message }
        if (-not $Once) { Start-Sleep -Seconds $IntervalSeconds }
    } while (-not $Once)
} finally {
    Write-Host "Watcher stopped. Findings remain in $OutputDirectory"
}
