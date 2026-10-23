# Run in Windows PowerShell 5.1. Tests functions only, using synthetic data.
# Does not inventory processes/services or start the watcher.
$ErrorActionPreference = 'Stop'
$watcher = Join-Path $PSScriptRoot 'Watch-Baseline.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($watcher, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors | Out-String) }
$functions = $ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)
foreach ($f in $functions) { Invoke-Expression $f.Extent.Text }
function Assert-Equal($Actual, $Expected, [string]$Label) {
    if ($Actual -ne $Expected) { throw "$Label failed: expected '$Expected', got '$Actual'" }
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('BaselineWatcherTest-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $temp)
try {
    $csv = Join-Path $temp 'fixture.csv'
    @(
        [pscustomobject]@{Name='ok.exe';Path='C:\Windows\ok.exe'},
        [pscustomobject]@{Name='unknown.exe';Path=''},
        [pscustomobject]@{Name='svc';Path='C:\svc.exe -arg safe'}
    ) | Export-Csv -LiteralPath $csv -Encoding UTF8 -NoTypeInformation
    $b = Read-Baseline $csv
    Assert-Equal (Get-Reason $b 'OK.EXE' 'c:\windows\OK.exe') '' 'Case-insensitive match'
    Assert-Equal (Get-Reason $b 'ok.exe' 'C:\Temp\ok.exe') 'DifferentPath' 'New path'
    Assert-Equal (Get-Reason $b 'new.exe' 'C:\new.exe') 'NewName' 'New name'
    Assert-Equal (Get-Reason $b 'unknown.exe' '') 'PathUnavailable' 'Missing path'
    Assert-Equal (Get-Reason $b 'unknown.exe' 'C:\new.exe') 'DifferentPath' 'Blank path is not wildcard'
    Assert-Equal (Get-Reason $b 'svc' 'C:\svc.exe -arg changed') 'DifferentPath' 'Service arguments'
    Assert-Equal (Get-Reason $b 'unknown.exe' '' -AllowMissingPath) '' 'Opt-in exact missing-path entry'
    Assert-Equal (Get-Reason $b 'never-seen.exe' '' -AllowMissingPath) 'PathUnavailable' 'Unlisted missing path'
    Assert-Equal (Get-Reason $b 'unknown.exe' 'C:\Temp\unknown.exe' -AllowMissingPath) 'DifferentPath' 'Opt-in is not a real-path wildcard'
    $store = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $item = [pscustomobject]@{ProcessId=101;CommandLine='new.exe first'}
    Update-Finding $store $seen 'new.exe' 'C:\new.exe' 'NewName' '2026-01-01T00:00:00Z' $item 'Process'
    $item.ProcessId=102
    Update-Finding $store $seen 'new.exe' 'C:\new.exe' 'NewName' '2026-01-01T00:00:00Z' $item 'Process'
    $row = $store[(Get-Key 'new.exe' 'C:\new.exe')]
    Assert-Equal $store.Count 1 'Group duplicate instances'
    Assert-Equal $row.PollsSeen 1 'Count one poll'
    Assert-Equal $row.InstancesLastSeen 2 'Count instances'
    $seen.Clear()
    Update-Finding $store $seen 'new.exe' 'C:\new.exe' 'NewName' '2026-01-01T00:00:30Z' $item 'Process'
    Assert-Equal $row.PollsSeen 2 'Count second poll'
    Assert-Equal $row.InstancesLastSeen 1 'Reset latest instance count'
    $columns = @('Host','Name','Path','Reason','FirstSeenUtc','LastSeenUtc','PollsSeen','InstancesLastSeen','LastPIDs','LastCommandLine','ServiceState','ServiceAccount')
    $output = Join-Path $temp 'results.csv'
    Save-Findings $store $output
    Assert-Equal @(Import-Csv -LiteralPath $output).Count 1 'One output row'
    Write-Host 'PASS: watcher syntax, matching, grouping, counters and CSV output.'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}
