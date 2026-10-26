<#
gitat.ps1 - Standalone IIS recovery for Windows Server / Windows PowerShell 5.1.
Run as Administrator: .\gitat.ps1  (no arguments; rerunning preserves the baseline).
First run: verify the website is clean, install Git, and run Deploy-BlueOps.ps1.
Keep Svc-Control.ps1 OR Svcwithme.ps1 beside this file, or in general\upkeep.
Runtime + primary Git baseline: C:\ProgramData\IISCache
Emergency copy: C:\Users\Public\Pictures\.<random GUID> (hidden, private ACL).
Exact path: (Get-Content C:\ProgramData\IISCache\settings.json -Raw | ConvertFrom-Json).EmergencyPath
Every ~10 seconds: verify approved copies, restore changed/missing protected files,
quarantine unexpected files, repair ACLs, and recover stopped IIS services/pools/sites.
All editors are treated the same, including Grey Team. No accounts/passwords/sessions change.
Protected: inetpub + local IIS physical roots + three main IIS configuration files.
Excluded by default: logs, temp, cache, history at each protected root.
Database contents, remote shares, certificates and external dependencies are NOT backed up.
No automatic baseline updates. Both copies are on this server, not an offline backup.
If an older approved watchdog baseline is found, its original scope/exclusions are retained.
BlueOps installs its worker in C:\BlueOps even if its source is run from another folder.
This script copies the controller there, repairs the known legacy IIS ACL bug only,
and calls it for W3SVC. WAS recovery runs directly as SYSTEM.
PATHS / STATE:
IISCache\gitat-engine.ps1 - installed runtime, SYSTEM scheduled task: gitat.
IISCache\settings.json - approved roots, hashes, ACLs, Git commits and exact EmergencyPath.
IISCache\baselines\<generation>\{site0,site1,...,iiscfg} - primary independent Git repositories.
Public Pictures\.<GUID>\{site0,site1,...,iiscfg} + manifest.json - emergency repositories/settings.
IISCache\quarantine\<time>\<target>\* - preserved changed/unexpected website files.
IISCache\status.json / paused - heartbeat and optional maintenance pause marker.
IISCache\blueops-before-repair\* - original worker and W3SVC SDDL if legacy repair was needed.
IISCache-Setup\gitat-engine.ps1 - private installer staging file.
%ProgramData%\gitat-setup\<GUID>\* - temporary SYSTEM request/script/controller/result;
    removed after success, retained after failure for diagnosis; temporary gitat-Setup-<GUID> task.
C:\BlueOps\Svc-Control.ps1 / Svc-Control-Worker.ps1 - teammate controller/worker.
C:\BlueOps\request.json / audit.log - teammate transient request and service audit trail.
\Microsoft\Windows\Bluetooth\BthServiceMonitor - teammate one-use SYSTEM task, then deleted.
%WINDIR%\System32\inetsrv\backup\gitat-<timestamp> - extra IIS configuration backup via appcmd.
%WINDIR%\System32\inetsrv\config - applicationHost.config, administration.config, redirection.config.
%ProgramData%\watchdogs\* - old approved baseline read/migrated; old data retained.
No website files are moved away during setup. Baseline copies are separate from live content.
An existing baseline keeps its old protected roots/exclusions; reruns never approve live drift.
Temporary .staging-* directories and .replaced-* recovery copies stay alongside repository copies.
The primary directory stays in ProgramData for machine-wide state; private ACLs protect it.
Hidden attributes are only cosmetic. A local administrator can still defeat local recovery.
Do not run from inside a website folder; the cloned repo should stay outside inetpub.
#>
[CmdletBinding()]
param()
# Optional constants for an unusual health endpoint; leave blank for automatic selection.
$SiteName = ''
$HealthUrl = ''
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess){throw 'Use 64-bit Windows PowerShell 5.1 as Administrator.'}
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not(New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Open Windows PowerShell as Administrator.'}
function Protect-Setup([string]$Path){
    $p=[IO.Path]::GetFullPath($Path)
    while($p){if((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "Reparse point refused: $p"};$p=[IO.Path]::GetDirectoryName($p)}
    New-Item -ItemType Directory -Path $Path -Force|Out-Null
    $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)');Set-Acl -LiteralPath $Path -AclObject $acl
}
function Get-GitatEngineSource {
$engine={
param(
    [ValidateSet('Setup','Preflight','Baseline','Rebaseline','Install','Run','Once','Pause','Resume','Status','Uninstall')]
    [string]$Action = 'Status',
    [string]$SiteName = '',
    [string]$HealthUrl = '',
    [string]$ExpectedText = '',
    [ValidateRange(0,10)][int]$MaxRedirects = 0,
    [string]$ExpectedFinalUrl = '',
    [string[]]$Exclude = @('logs','temp','cache','history'),
    [ValidateSet('Quarantine','Report')][string]$NewFiles = 'Quarantine',
    [string]$GitPath = '',
    [string]$ServiceController = '',
    [ValidatePattern('^$|^[a-f0-9]{32}$')][string]$InternalRequest = ''
)

$ErrorActionPreference = 'Stop'
$store = Join-Path $env:ProgramData 'IISCache'
$configPath = Join-Path $store 'settings.json'
$statusPath = Join-Path $store 'status.json'
$pausePath = Join-Path $store 'paused'
$taskName = 'gitat'
$installedScript = Join-Path $store 'gitat-engine.ps1'
$blueOpsControl = 'C:\BlueOps\Svc-Control.ps1'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from Windows PowerShell as Administrator.'
}
if (-not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Use 64-bit Windows PowerShell 5.1, not PowerShell 7.'
}

function Write-Json($Path, $Value) {
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath "$Path.tmp" -Encoding UTF8
    Move-Item -LiteralPath "$Path.tmp" -Destination $Path -Force
}

function Get-IisServiceState([string[]]$Names = @('WAS','W3SVC')) {
    foreach ($name in $Names) {
        if ($name -notin @('WAS','W3SVC')) { throw 'Only IIS services are managed by gitat.' }
        $svc = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if (-not $svc) { throw "Service was not found: $name" }
        [pscustomobject]@{ Name = $name; State = $svc.State.Replace(' ',''); StartMode = $svc.StartMode }
    }
}

function Invoke-BlueOps([string]$Name, [string]$Operation) {
    if ($Name -notin @('WAS','W3SVC')) { throw "Unsupported service: $Name" }
    if ($Operation -notin @('Start','Restart')) { throw 'Watchdogs only starts or restarts services.' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Service recovery must run as SYSTEM.' }
    $service = Get-IisServiceState @($Name)
    if ($service.StartMode -eq 'Disabled') {
        $out = & "$env:SystemRoot\System32\sc.exe" config $Name start= auto 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Could not enable ${Name}: $($out -join ' ')" }
    }
    if ($Name -eq 'WAS') {
        Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop
        $svc = New-Object -TypeName System.ServiceProcess.ServiceController -ArgumentList WAS
        try {
            $deadline = (Get-Date).AddSeconds(30)
            do {
                $svc.Refresh()
                if ([string]$svc.Status -notmatch 'Pending$') { break }
                if ((Get-Date) -ge $deadline) { throw 'WAS is stuck in a pending state.' }
                Start-Sleep -Milliseconds 250
            } while ($true)
            if ($Operation -eq 'Restart' -and $svc.Status -ne 'Stopped') {
                $svc.Stop()
                $svc.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
            }
            $svc.Refresh()
            if ($svc.Status -eq 'Paused') { $svc.Continue() }
            elseif ($svc.Status -ne 'Running') { $svc.Start() }
            $svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
        }
        finally { $svc.Dispose() }
        $script:lastServiceAction = [pscustomobject]@{Service='WAS';Action=$Operation;Success=$true;State='Running';Controller='gitat SYSTEM';Time=(Get-Date).ToString('o')}
        return
    }
    Assert-PlainPath $script:blueOpsControl
    $request = 'C:\BlueOps\request.json'
    Assert-PlainPath $request
    $taskPath = '\Microsoft\Windows\Bluetooth\'
    $busy = Get-ScheduledTask -TaskName BthServiceMonitor -TaskPath $taskPath -ErrorAction SilentlyContinue
    # The repo controller (Svcwithme.ps1) gives up after 15 seconds and removes its task even if the worker is
    # still busy, which can strand request.json. A request this old with no task is dead, so clear it.
    $clearedStale = $false
    if ((Test-Path -LiteralPath $request) -and -not $busy) {
        $requestAge = ((Get-Date) - (Get-Item -LiteralPath $request -Force).LastWriteTime).TotalSeconds
        if ($requestAge -gt 120) {
            Remove-Item -LiteralPath $request -Force
            $clearedStale = $true
        }
    }
    if ((Test-Path -LiteralPath $request) -or $busy) {
        throw 'BlueOps has an existing request/task. Wait for it to finish; pause gitat before manual BlueOps actions. A request older than 2 minutes with no task is cleared automatically.'
    }
    $response = & $script:blueOpsControl -Service IIS -Action $Operation
    foreach ($item in @($response)) {
        if ($null -ne $item -and $item.PSObject.Properties['Success'] -and -not $item.Success) { throw 'BlueOps reported a failed service action.' }
    }
    if (Test-Path -LiteralPath $request) { throw 'BlueOps left its request pending; the service action was not verified.' }
    if (Get-ScheduledTask -TaskName BthServiceMonitor -TaskPath $taskPath -ErrorAction SilentlyContinue) { throw 'BlueOps did not remove its temporary task.' }
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $service = Get-IisServiceState @('W3SVC')
        if ($service.State -eq 'Running' -and $service.StartMode -ne 'Disabled') { break }
        if ((Get-Date) -ge $deadline) { throw "IIS is still $($service.State) after BlueOps $Operation." }
        Start-Sleep -Milliseconds 250
    } while ($true)
    $script:lastServiceAction = [pscustomobject]@{Service='IIS';Action=$Operation;Success=$true;State=$service.State;Controller='BlueOps';StaleRequestCleared=$clearedStale;Time=(Get-Date).ToString('o')}
}

function Assert-PlainPath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing a junction or symbolic link: $current"
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function Get-ProtectedFiles([string]$Root, [string[]]$Excluded, [string]$Folder = $Root, [switch]$DirectoriesOnly) {
    if (-not (Test-Path -LiteralPath $Folder)) { return }
    Assert-PlainPath $Folder
    foreach ($item in Get-ChildItem -LiteralPath $Folder -Force) {
        $relative = $item.FullName.Substring($Root.TrimEnd('\','/').Length + 1).Replace('\','/')
        $skip = $false
        foreach ($entry in $Excluded) {
            $entry = $entry.Replace('\','/').Trim('/')
            if ($relative -eq $entry -or $relative.StartsWith("$entry/", [StringComparison]::OrdinalIgnoreCase)) { $skip = $true }
        }
        if ($skip) { continue }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing a junction or symbolic link: $($item.FullName)" }
        if ($item.PSIsContainer) {
            if ($DirectoriesOnly) { $relative }
            Get-ProtectedFiles $Root $Excluded $item.FullName -DirectoriesOnly:$DirectoriesOnly
        }
        elseif (-not $DirectoriesOnly) { $relative }
    }
}

function Invoke-Git([string]$Repo, [string[]]$GitArgs) {
    if (-not (Test-Path -LiteralPath $script:git -PathType Leaf)) { throw "Git was not found at $script:git" }
    $ErrorActionPreference = 'Continue'
    $result = & $script:git -C $Repo -c "safe.directory=$Repo" -c core.autocrlf=false -c core.fsmonitor=false -c "core.hooksPath=$store\no-hooks" --literal-pathspecs @GitArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Git failed: $($result -join ' ')" }
    $result | ForEach-Object { "$_" }
}

function Resolve-IisTarget($Sites, [string]$Name, [string]$Url) {
    $available = @($Sites)
    if (-not $Name) {
        if(-not $available.Count){throw 'No IIS websites were found.'}
        $choice=@($available|Where-Object { [string]$_.State -eq 'Started' }|Sort-Object @{Expression={$_.Name -ne 'Default Web Site'}},Name|Select-Object -First 1)
        if(-not $choice.Count){throw 'Start and verify a clean IIS website before taking the first baseline.'}
        $Name=$choice[0].Name
    }
    $selected = @($available | Where-Object { $_.Name -eq $Name } | Select-Object -First 1)
    if (-not $selected.Count) { throw "Site not found: $Name" }
    $site = $selected[0]
    if (-not $Url) {
        $bindings = @($site.Bindings | Where-Object { $_.Protocol -in @('http','https') } | Sort-Object { $_.Protocol -ne 'http' } | Select-Object -First 1)
        if (-not $bindings.Count) { throw 'No HTTP binding was found. Set the HealthUrl constant at the top of gitat.ps1.' }
        $binding = $bindings[0]
        $hostName = $binding.Host
        if (-not $hostName) { $hostName = $binding.EndPoint.Address.ToString() }
        if ($hostName -in @('0.0.0.0','::')) { $hostName = '127.0.0.1' }
        $Url = (New-Object UriBuilder($binding.Protocol, $hostName, $binding.EndPoint.Port, '/')).Uri.AbsoluteUri
    }
    [pscustomobject]@{ SiteName = $site.Name; HealthUrl = $Url }
}

function Test-Http($Settings) {
    try {
        $response = Invoke-WebRequest -Uri $Settings.HealthUrl -UseBasicParsing -TimeoutSec 3 -MaximumRedirection $Settings.MaxRedirects
        $finalUri = $response.BaseResponse.ResponseUri
        if (-not $finalUri) { $finalUri = $response.BaseResponse.RequestMessage.RequestUri }
        if (-not $finalUri) { throw 'The HTTP response did not contain a final URL.' }
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
        if ($Settings.ExpectedText -and -not ([string]$response.Content).Contains($Settings.ExpectedText)) { throw 'Expected page text was not found.' }
        if ($Settings.ExpectedFinalUrl -and $finalUri.GetLeftPart([UriPartial]::Path) -cne ([uri]$Settings.ExpectedFinalUrl).GetLeftPart([UriPartial]::Path)) { throw "Unexpected final URL: $($finalUri.AbsoluteUri)" }
        [pscustomobject]@{ Healthy = $true; StatusCode = [int]$response.StatusCode; FinalUrl = $finalUri.AbsoluteUri; Result = 'HTTP 200; final destination and configured text checks passed.' }
    }
    catch { [pscustomobject]@{ Healthy = $false; Result = $_.Exception.Message } }
}

function Get-AccessSddl([string]$Path) {
    (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
}

function Restore-Access([string]$Path, [string]$Sddl) {
    if (-not $Sddl) { throw 'This baseline has no saved file permissions. Pause and create an approved Rebaseline first.' }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access) -eq $Sddl) { return $false }
    $acl.SetSecurityDescriptorSddlForm($Sddl, [Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $Path -AclObject $acl
    if ((Get-AccessSddl $Path) -ne $Sddl) { throw "Permission restore verification failed: $Path" }
    return $true
}

function Set-PrivateDirectory([string]$Path) {
    Assert-PlainPath $Path
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-BlueOpsInterface([string]$Path = '') {
    if (-not $Path) { $Path = $script:blueOpsControl }
    Assert-PlainPath $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'BlueOps controller missing. Run Deploy-BlueOps.ps1 first, then run gitat.ps1 with Svc-Control.ps1 or Svcwithme.ps1 beside it.'
    }
    $command = Get-Command $Path -ErrorAction Stop
    $services = @($command.Parameters['Service'].Attributes | Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues })
    $actions = @($command.Parameters['Action'].Attributes | Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues })
    if ('IIS' -notin $services -or 'Start' -notin $actions -or 'Restart' -notin $actions) {
        throw 'BlueOps must accept -Service IIS and -Action Start/Restart.'
    }
    Assert-PlainPath 'C:\BlueOps\Svc-Control-Worker.ps1'
    if (-not (Test-Path 'C:\BlueOps\Svc-Control-Worker.ps1' -PathType Leaf)) { throw 'BlueOps worker is missing. Run Deploy-BlueOps.ps1 first.' }
}

function Install-BlueOpsController([string]$Source) {
    $base = Split-Path $script:blueOpsControl
    $worker = Join-Path $base 'Svc-Control-Worker.ps1'
    Assert-PlainPath $worker
    if (-not (Test-Path -LiteralPath $worker -PathType Leaf)) { throw 'Run the repository Deploy-BlueOps.ps1 first; its generated worker is missing.' }
    if (-not $Source) { $Source = $script:blueOpsControl }
    Assert-PlainPath $Source
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw 'The BlueOps controller (general\Svcwithme.ps1) was not found. Copy it beside gitat.ps1 before running the script.' }
    Set-PrivateDirectory $base
    Assert-PlainPath $script:blueOpsControl
    if ([IO.Path]::GetFullPath($Source) -ne [IO.Path]::GetFullPath($script:blueOpsControl)) {
        Copy-Item -LiteralPath $Source -Destination $script:blueOpsControl -Force
        Unblock-File -LiteralPath $script:blueOpsControl -ErrorAction SilentlyContinue
    }
    foreach ($file in @($script:blueOpsControl,$worker)) {
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;SY)(A;;FA;;;BA)')
        Set-Acl -LiteralPath $file -AclObject $acl
    }
    Assert-BlueOpsInterface
}

# The repo ships the controller as general\Svcwithme.ps1 (there is no Svc-Control.ps1 file). It is installed
# on the host as C:\BlueOps\Svc-Control.ps1 either way.
function Find-BlueOpsController([string]$Explicit) {
    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit -PathType Leaf)) { throw "Controller not found: $Explicit" }
        return $Explicit
    }
    $candidates = @()
    if ($PSScriptRoot) {
        $parent = Split-Path -Parent $PSScriptRoot
        $candidates += @(
            (Join-Path $PSScriptRoot 'Svc-Control.ps1'),
            (Join-Path $PSScriptRoot 'Svcwithme.ps1')
        )
        if ($parent) {
            $candidates += @(
                (Join-Path $parent 'general\Svc-Control.ps1'),
                (Join-Path $parent 'general\Svcwithme.ps1')
            )
        }
    }
    if($PSScriptRoot){$parent=Split-Path $PSScriptRoot -Parent;$candidates+=@(
        (Join-Path $PSScriptRoot 'general\upkeep\Svcwithme.ps1'),(Join-Path $parent 'general\upkeep\Svcwithme.ps1'),(Join-Path $parent 'general\upkeep\Svc-Control.ps1')
    )}
    $candidates += $script:blueOpsControl
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw 'BlueOps controller not found. Expected Svcwithme.ps1 (or Svc-Control.ps1) next to this script, in ..\general\, or at C:\BlueOps\Svc-Control.ps1. You can also pass -ServiceController with its full path.'
}

function Stop-PreviousGuard([string]$Name, [string]$Script) {
    $task = Get-ScheduledTask -TaskName $Name -TaskPath '\' -ErrorAction SilentlyContinue
    if (-not $task) { return }
    Assert-PlainPath $Script
    if (-not (Test-Path -LiteralPath $Script -PathType Leaf)) { throw "Existing $Name task has no expected script at $Script. Review the task before setup." }
    if (-not @($task.Actions | Where-Object { $_.Arguments -like ('*"' + $Script + '"*') }).Count) { throw "The existing $Name task points to an unexpected command. Review it before setup." }
    & $Script -Action Pause | Out-Null
    Disable-ScheduledTask -TaskName $Name -TaskPath '\' | Out-Null
    Stop-ScheduledTask -TaskName $Name -TaskPath '\'
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-ScheduledTask -TaskName $Name -TaskPath '\').State -eq 'Running') {
        if ((Get-Date) -ge $deadline) { throw "$Name did not stop. Existing recovery data was retained." }
        Start-Sleep -Seconds 1
    }
}

function Get-EmergencyPath($Settings) {
    $base=Join-Path $env:PUBLIC 'Pictures'
    if(-not $Settings.PSObject.Properties['EmergencyPath']){
        $Settings|Add-Member NoteProperty EmergencyPath (Join-Path $base ('.'+[guid]::NewGuid().ToString('N')))
        Write-Json $configPath $Settings
    }
    $path=[IO.Path]::GetFullPath([string]$Settings.EmergencyPath)
    if([IO.Path]::GetDirectoryName($path) -ine [IO.Path]::GetFullPath($base) -or [IO.Path]::GetFileName($path) -notmatch '^\.[a-f0-9]{32}$'){throw 'Unexpected emergency-copy path in settings.json.'}
    Assert-PlainPath $path
    foreach($target in $Settings.Targets){
        $live=[IO.Path]::GetFullPath($target.Root).TrimEnd('\')
        if($path -ieq $live -or $path.StartsWith($live+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Emergency storage overlaps a protected IIS directory.'}
    }
    return $path
}
function Test-ApprovedRepo($Target,[string]$Repo) {
    try{
        Assert-PlainPath $Repo
        if(-not(Test-Path -LiteralPath $Repo -PathType Container)){return $false}
        foreach($item in Get-ChildItem -LiteralPath $Repo -Force -Recurse){Assert-PlainPath $item.FullName}
        Invoke-Git $Repo @('cat-file','-e',($Target.Commit+'^{commit}'))|Out-Null
        Invoke-Git $Repo @('fsck','--full','--no-reflogs','--no-progress',$Target.Commit)|Out-Null
        foreach($file in $Target.Files){
            if($file.Path -match '(^[\\/]|:|(^|[\\/])\.\.([\\/]|$))'){throw 'Unsafe baseline-relative path.'}
            $path=Join-Path $Repo $file.Path;Assert-PlainPath $path
            if(-not(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.Hash){return $false}
        }
        return $true
    }catch{return $false}
}
function Copy-ApprovedRepo($Target,[string]$Source,[string]$Destination) {
    if(-not(Test-ApprovedRepo $Target $Source)){throw 'Refusing to copy an unverified recovery baseline.'}
    Assert-PlainPath $Destination
    $parent=Split-Path $Destination -Parent;Set-PrivateDirectory $parent
    $stage=Join-Path $parent ('.staging-'+[guid]::NewGuid().ToString('N'))
    Set-PrivateDirectory $stage
    try{
        Get-ChildItem -LiteralPath $Source -Force|Copy-Item -Destination $stage -Recurse -Force
        # Git copies are independent file copies, not clones using shared objects/hardlinks.
        if(-not(Test-ApprovedRepo $Target $stage)){throw 'Recovery-copy hash verification failed.'}
        if(Test-Path -LiteralPath $Destination){Move-Item -LiteralPath $Destination -Destination ($Destination+'.replaced-'+[guid]::NewGuid().ToString('N'))}
        Move-Item -LiteralPath $stage -Destination $Destination
        Set-PrivateDirectory $Destination
    }finally{if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}}
}
function Sync-Emergency($Settings) {
    $path=Get-EmergencyPath $Settings
    Set-PrivateDirectory $path
    $item=Get-Item -LiteralPath $path -Force
    $item.Attributes=$item.Attributes -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System
    foreach($target in $Settings.Targets){
        if($target.Id -notmatch '^(site\d+|iiscfg)$'){throw 'Unexpected baseline target ID.'}
        $primary=[IO.Path]::GetFullPath($target.Repo)
        if(-not $primary.StartsWith(([IO.Path]::GetFullPath($store).TrimEnd('\')+'\baselines\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Primary baseline repository is outside the recovery store.'}
        $secondary=Join-Path $path $target.Id
        $primaryOk=Test-ApprovedRepo $target $primary
        $secondaryOk=Test-ApprovedRepo $target $secondary
        if(-not $primaryOk){
            # First repair the primary working tree from its approved Git commit.
            try{Invoke-Git $primary @('restore',('--source='+$target.Commit),'--worktree','--','.')|Out-Null}catch{}
            $primaryOk=Test-ApprovedRepo $target $primary
        }
        if(-not $primaryOk -and $secondaryOk){Copy-ApprovedRepo $target $secondary $primary;$primaryOk=$true}
        if(-not $primaryOk){throw "Neither recovery copy validates for $($target.Id). No new baseline was accepted."}
        if(-not $secondaryOk){Copy-ApprovedRepo $target $primary $secondary}
    }
    Write-Json (Join-Path $path 'manifest.json') $Settings
    return $path
}

function Import-PreviousBaseline {
    if(Test-Path -LiteralPath $configPath){return}
    $oldStore=Join-Path $env:ProgramData 'watchdogs'
    $oldConfig=Join-Path $oldStore 'settings.json'
    if(-not(Test-Path -LiteralPath $oldConfig)){return}
    Assert-PlainPath $oldConfig
    $old=Get-Content -LiteralPath $oldConfig -Raw|ConvertFrom-Json
    if($old.FormatVersion -ne 2){throw 'Existing watchdog baseline is an unsupported format; it was retained.'}
    $script:git=$old.GitPath
    Set-PrivateDirectory $store
    $generation=Join-Path $store ('baselines\'+[guid]::NewGuid().ToString('N'))
    foreach($target in $old.Targets){
        $source=[IO.Path]::GetFullPath($target.Repo)
        if(-not $source.StartsWith(([IO.Path]::GetFullPath($oldStore).TrimEnd('\')+'\baselines\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Legacy baseline points outside its approved store.'}
        if($target.Id -notmatch '^(site\d+|iiscfg)$'){throw 'Legacy baseline ID is invalid.'}
        if(-not(Test-ApprovedRepo $target $source)){throw 'Legacy baseline verification failed. It was retained; no fresh live baseline was captured.'}
        $destination=Join-Path $generation $target.Id
        Copy-ApprovedRepo $target $source $destination
        $target.Repo=$destination
    }
    Write-Json $configPath $old
    Write-Host 'Preserved and copied the previously approved watchdog baseline.'
}

function Repair-KnownBlueOps {
    $worker='C:\BlueOps\Svc-Control-Worker.ps1'
    Assert-PlainPath $worker
    $text=Get-Content -LiteralPath $worker -Raw
    $old='D:(D;;DCWPDTSD;;;AU)(A;;CCLCSWLORC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)'
    if(-not $text.Contains($old) -or $text.Contains('# gitat IIS SYSTEM rights repair')){return}
    if((Test-Path 'C:\BlueOps\request.json') -or (Get-ScheduledTask -TaskName BthServiceMonitor -TaskPath '\Microsoft\Windows\Bluetooth\' -ErrorAction SilentlyContinue)){throw 'BlueOps is busy; retry when its action finishes.'}
    $fixed='D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWLORC;;;AU)(A;;CCLCSWLORC;;;BA)(A;;RC;;;OW)'
    if(-not ('CDTBlueServiceSecurity' -as [type])){
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
// SYSTEM-only repair for the exact legacy BlueOps service DACL bug.
public static class CDTBlueServiceSecurity {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool CloseServiceHandle(IntPtr handle);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool QueryServiceObjectSecurity(IntPtr service,uint info,byte[] descriptor,uint size,out uint needed);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetServiceObjectSecurity(IntPtr service,uint info,byte[] descriptor);
 [StructLayout(LayoutKind.Sequential)] struct LUID {public uint Low;public int High;}
 [StructLayout(LayoutKind.Sequential)] struct PRIVILEGE {public uint Count;public LUID Luid;public uint Attributes;}
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out LUID luid);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref PRIVILEGE requested,int size,out PRIVILEGE previous,out int needed);
 static void OwnService(IntPtr manager,string name) {
  IntPtr token;if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Win32Exception();IntPtr service=IntPtr.Zero;
  PRIVILEGE previous=new PRIVILEGE();bool changed=false;
  try {LUID luid;if(!LookupPrivilegeValue(null,"SeTakeOwnershipPrivilege",out luid))throw new Win32Exception();var requested=new PRIVILEGE{Count=1,Luid=luid,Attributes=2};int needed;
   if(!AdjustTokenPrivileges(token,false,ref requested,Marshal.SizeOf(typeof(PRIVILEGE)),out previous,out needed))throw new Win32Exception();
   int error=Marshal.GetLastWin32Error();if(error!=0)throw new Win32Exception(error);changed=true;
   service=OpenService(manager,name,0x80000);if(service==IntPtr.Zero)throw new Win32Exception();
   var owner=new RawSecurityDescriptor("O:SY");byte[] bytes=new byte[owner.BinaryLength];owner.GetBinaryForm(bytes,0);if(!SetServiceObjectSecurity(service,1,bytes))throw new Win32Exception();
  }finally{if(service!=IntPtr.Zero)CloseServiceHandle(service);if(changed){PRIVILEGE ignored;int needed;AdjustTokenPrivileges(token,false,ref previous,Marshal.SizeOf(typeof(PRIVILEGE)),out ignored,out needed);}CloseHandle(token);}
 }
 public static string Read(string name) {
  IntPtr manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new Win32Exception();IntPtr service=IntPtr.Zero;
  try {service=OpenService(manager,name,0x20000);if(service==IntPtr.Zero)throw new Win32Exception();uint n;QueryServiceObjectSecurity(service,7,null,0,out n);if(n==0)throw new Win32Exception();byte[] bytes=new byte[n];if(!QueryServiceObjectSecurity(service,7,bytes,n,out n))throw new Win32Exception();return new RawSecurityDescriptor(bytes,0).GetSddlForm(AccessControlSections.Owner|AccessControlSections.Group|AccessControlSections.Access);}
  finally {if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}
 }
 public static void SetDacl(string name,string sddl) {
  IntPtr manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new Win32Exception();IntPtr service=IntPtr.Zero;
  try {service=OpenService(manager,name,0x40000);if(service==IntPtr.Zero && Marshal.GetLastWin32Error()==5){OwnService(manager,name);service=OpenService(manager,name,0x40000);}if(service==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error(),"Cannot repair "+name+" DACL; use your BlueOps recovery script first.");var descriptor=new RawSecurityDescriptor(sddl);byte[] bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);if(!SetServiceObjectSecurity(service,4,bytes))throw new Win32Exception();}
  finally {if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}
 }
}
'@
    }
    $backup=Join-Path $store 'blueops-before-repair';Set-PrivateDirectory $backup
    if(-not(Test-Path (Join-Path $backup 'Svc-Control-Worker.ps1'))){Copy-Item -LiteralPath $worker -Destination (Join-Path $backup 'Svc-Control-Worker.ps1')}
    $before=[CDTBlueServiceSecurity]::Read('W3SVC')
    if(-not(Test-Path (Join-Path $backup 'W3SVC.sddl'))){Set-Content -LiteralPath (Join-Path $backup 'W3SVC.sddl') -Value $before -Encoding UTF8}
    [void][CDTBlueServiceSecurity]::SetDacl('W3SVC',$fixed)
    $anchor='$unlockedSDDL = '+[char]34+'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)'+[char]34
    if(-not $text.Contains($anchor)){throw 'Unrecognized legacy worker format; IIS service ACL was repaired, but review its worker before proceeding.'}
    $patch="`r`n# gitat IIS SYSTEM rights repair`r`nif(`$svcName -eq 'W3SVC'){`$lockedSDDL='$fixed';`$unlockedSDDL='$fixed'}`r`n"
    $text.Replace($anchor,($anchor+$patch))|Set-Content -LiteralPath $worker -Encoding UTF8
    foreach($arguments in @(@('failure','W3SVC','reset=','0','actions=','restart/5000/restart/5000/restart/5000'),@('failureflag','W3SVC','1'))){
        $message=& "$env:SystemRoot\System32\sc.exe" @arguments 2>&1
        if($LASTEXITCODE){throw "BlueOps IIS recovery configuration failed: $message"}
    }
    Write-Host 'Repaired the known BlueOps SYSTEM configuration-rights bug; original worker and ACL saved.'
}

function Install-StandaloneWatchdog([hashtable]$SiteParameters, [string]$ControllerSource) {
    Assert-PlainPath $script:store
    Assert-PlainPath $script:configPath
    Assert-BlueOpsInterface $ControllerSource
    Import-PreviousBaseline
    if(-not(Test-Path $configPath) -and (Test-Path (Join-Path $store 'baselines'))){throw 'Primary baseline exists but settings.json is missing. Restore the saved emergency manifest; no new live baseline was accepted.'}
    if (Test-Path -LiteralPath $script:configPath) {
        $saved = Get-Content -LiteralPath $script:configPath -Raw | ConvertFrom-Json
        if ($saved.FormatVersion -ne 2) { throw 'Existing baseline format is unsupported. The baseline has been retained.' }
        foreach ($key in $SiteParameters.Keys) {
            if (($SiteParameters[$key] | ConvertTo-Json -Compress) -cne ($saved.$key | ConvertTo-Json -Compress)) {
                Write-Warning "Using the previously approved $key setting. The baseline was not replaced."
            }
        }
    }
    if(Test-Path -LiteralPath $script:configPath){$SiteParameters=@{}}
    $hasBaseline=Test-Path -LiteralPath $script:configPath
    if(-not $hasBaseline){$preflight=& $PSCommandPath -Action Preflight @SiteParameters|ConvertFrom-Json;if(-not $preflight.Ready){throw ($preflight.Problems -join '; ')}}
    $touched = $false
    try {
        $touched = $true
        Stop-PreviousGuard 'watchdogs' (Join-Path $env:ProgramData 'watchdogs\watchdogs.ps1')
        Stop-PreviousGuard 'watchdogsgit' (Join-Path $env:ProgramData 'watchdogs\watchdogsgit.ps1')
        Stop-PreviousGuard 'gitat' $script:installedScript
        Install-BlueOpsController $ControllerSource
        Repair-KnownBlueOps
        Invoke-BlueOps 'WAS' 'Start'
        Invoke-BlueOps 'W3SVC' 'Start'
        Set-PrivateDirectory $script:store
        if (-not (Test-Path -LiteralPath $script:configPath)) {
            & $PSCommandPath -Action Baseline @SiteParameters | Out-Null
        }
        Remove-Item -LiteralPath $script:pausePath -Force -ErrorAction SilentlyContinue
        & $PSCommandPath -Action Once | Out-Null
        $state = Get-Content -LiteralPath $script:statusPath -Raw | ConvertFrom-Json
        if (-not $state.Healthy -or $state.Paused) { throw "First recovery pass failed: $($state | ConvertTo-Json -Depth 8 -Compress)" }
        $stamp = $state.Time
        & $PSCommandPath -Action Install | Out-Null
        $deadline = (Get-Date).AddSeconds(60)
        do {
            Start-Sleep -Seconds 2
            $state = Get-Content -LiteralPath $script:statusPath -Raw | ConvertFrom-Json
            $task = Get-ScheduledTask -TaskName gitat -TaskPath '\'
            if ($state.Time -ne $stamp -and $state.Healthy -and -not $state.Paused -and $task.State -eq 'Running') { break }
        } while ((Get-Date) -lt $deadline)
        if ($state.Time -eq $stamp -or -not $state.Healthy -or $state.Paused -or $task.State -ne 'Running') { throw 'No fresh healthy background heartbeat arrived. Inspect -Action Status.' }
        foreach($legacy in @('watchdogs','watchdogsgit')){if(Get-ScheduledTask -TaskName $legacy -TaskPath '\' -ErrorAction SilentlyContinue){Unregister-ScheduledTask -TaskName $legacy -TaskPath '\' -Confirm:$false}}
        'Installed gitat as SYSTEM; starts at boot. Existing baseline retained when present.'
    }
    catch {
        if ($touched -and (Test-Path -LiteralPath $script:store)) {
            New-Item -ItemType File -Path $script:pausePath -Force | Out-Null
        }
        throw
    }
}

function Invoke-LocalSystemRequest([hashtable]$Parameters) {
    $work = Join-Path $env:ProgramData 'gitat-setup'
    Set-PrivateDirectory $work
    $id = [guid]::NewGuid().ToString('N')
    $job = Join-Path $work $id
    Set-PrivateDirectory $job
    $staged = Join-Path $job 'gitat-engine.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $staged
    if ($Parameters.Action -eq 'Setup') {
        $source = Find-BlueOpsController ([string]$Parameters.ServiceController)
        Assert-PlainPath $source
        $copy = Join-Path $job 'Svc-Control.ps1'
        Copy-Item -LiteralPath $source -Destination $copy
        $Parameters.ServiceController = $copy
    }
    @{ RequestId = $id; Parameters = $Parameters } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $job 'request.json') -Encoding UTF8
    $taskName = 'gitat-Setup-' + $id
    $registered = $false
    $result = $null
    try {
        $exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -InternalRequest {1}' -f $staged, $id
        $run = New-ScheduledTaskAction -Execute $exe -Argument $arguments
        $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        $options = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $run -Principal $principal -Settings $options | Out-Null
        $registered = $true
        $started = Get-Date
        Start-ScheduledTask -TaskName $taskName -TaskPath '\'
        Write-Host 'Running local setup/control as SYSTEM. Leave this window open until it finishes.'
        $deadline = $started.AddMinutes(30)
        $file = Join-Path $job 'result.json'
        while (-not (Test-Path -LiteralPath $file)) {
            if ((Get-Date) -ge $deadline) { throw "Request timed out. Diagnostic files: $job" }
            Start-Sleep -Seconds 1
            if (((Get-Date) - $started).TotalSeconds -gt 5) {
                $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\'
                $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\'
                if ($info.LastRunTime -ge $started.AddSeconds(-1) -and $task.State -ne 'Running' -and -not (Test-Path -LiteralPath $file)) {
                    throw "SYSTEM worker exited without a result (task result $($info.LastTaskResult)). Diagnostic files: $job"
                }
            }
        }
        $result = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        if ($result.RequestId -ne $id) { throw 'Mismatched setup result.' }
        if (-not $result.Success) { throw "Request failed: $($result.Error). Diagnostic files: $job" }
        $result.Output
    }
    finally {
        if ($registered) {
            $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
            if ($task) {
                if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $taskName -TaskPath '\' }
                Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false
            }
        }
        if ($result -and $result.Success -and $result.RequestId -eq $id) { Remove-Item -LiteralPath $job -Recurse -Force }
    }
}

$env:GIT_CONFIG_NOSYSTEM = '1'
$env:GIT_CONFIG_GLOBAL = 'NUL'
$env:GIT_TERMINAL_PROMPT = '0'
foreach ($name in @('GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','GIT_COMMON_DIR','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES')) { Remove-Item "Env:\$name" -ErrorAction SilentlyContinue }

if ($InternalRequest) {
    if ($identity.User.Value -ne 'S-1-5-18') { throw 'Internal requests must run as SYSTEM.' }
    $job = Join-Path (Join-Path $env:ProgramData 'gitat-setup') $InternalRequest
    Assert-PlainPath $job
    $requestPath = Join-Path $job 'request.json'
    Assert-PlainPath $requestPath
    $result = @{ RequestId = $InternalRequest; Success = $false; Output = @(); Error = ''; Time = '' }
    $gate = $null
    $held = $false
    try {
        $request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
        if ($request.RequestId -ne $InternalRequest) { throw 'Mismatched request.' }
        $parameters = @{}
        foreach ($p in $request.Parameters.PSObject.Properties) {
            if ($p.Name -notin @('Action','SiteName','HealthUrl','ExpectedText','MaxRedirects','ExpectedFinalUrl','Exclude','NewFiles','GitPath','ServiceController')) { throw 'Unsupported request parameter.' }
            $parameters[$p.Name] = $p.Value
        }
        if ($parameters.Action -notin @('Setup','Baseline','Rebaseline','Install','Once','Pause','Resume','Uninstall')) { throw 'Unsupported request action.' }
        $gate = New-Object Threading.Mutex($false, 'Global\gitat-Setup')
        try { $held = $gate.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'Another gitat setup or management request is running.' }
        $result.Output = @(& $PSCommandPath @parameters)
        $result.Success = $true
    }
    catch { $result.Error = $_.Exception.Message }
    finally {
        if ($held) { $gate.ReleaseMutex() }
        if ($gate) { $gate.Dispose() }
        $result.Time = (Get-Date).ToString('o')
        Write-Json (Join-Path $job 'result.json') $result
    }
    return
}

if ($Action -eq 'Run' -and $identity.User.Value -ne 'S-1-5-18') {
    throw 'Use -Action Setup to install the background SYSTEM task. Do not run the recovery loop in an administrator session.'
}
if ($Action -notin @('Status','Preflight','Run') -and $identity.User.Value -ne 'S-1-5-18') {
    $parameters = @{}
    foreach ($key in $PSBoundParameters.Keys) { $parameters[$key] = $PSBoundParameters[$key] }
    $parameters.Action = $Action
    Invoke-LocalSystemRequest $parameters
    return
}
if ($Action -eq 'Setup') {
    $siteParameters = @{}
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('Action','InternalRequest','ServiceController')) { $siteParameters[$key] = $PSBoundParameters[$key] }
    }
    Install-StandaloneWatchdog $siteParameters $ServiceController
    return
}


if ($Action -eq 'Preflight') {
    $problems = New-Object 'Collections.Generic.List[string]'
    if (Test-Path -LiteralPath $configPath) {
        try {
            $saved = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
            foreach ($name in @('SiteName','HealthUrl','ExpectedText','ExpectedFinalUrl','GitPath')) {
                if (-not (Get-Variable -Name $name -ValueOnly) -and $saved.PSObject.Properties[$name]) { Set-Variable -Name $name -Value $saved.$name }
            }
        }
        catch { $problems.Add("Could not read existing gitat settings: $($_.Exception.Message)") }
    }
    if (Get-ScheduledTask -TaskName 'IISAutoRestore' -ErrorAction SilentlyContinue) { $problems.Add('The earlier IISAutoRestore task is still installed. Uninstall it before deploying gitat so two recovery loops do not compete.') }
    $dll = "$env:SystemRoot\System32\inetsrv\Microsoft.Web.Administration.dll"
    if (-not $GitPath) {
        $gitCommand = Get-Command git.exe -ErrorAction SilentlyContinue
        $GitPath = if ($gitCommand) { $gitCommand.Source } else { "$env:ProgramFiles\Git\cmd\git.exe" }
    }
    $gitVersion = $null
    if (Test-Path -LiteralPath $GitPath -PathType Leaf) {
        $gitVersion = (& $GitPath --version) -join ' '
        if ($LASTEXITCODE -ne 0 -or $gitVersion -notmatch '(\d+\.\d+\.\d+)' -or [version]$Matches[1] -lt [version]'2.23.0') { $problems.Add('Git 2.23 or newer is required.') }
    }
    else { $problems.Add("Git was not found at $GitPath") }
    $sites = @()
    $services = @()
    try { $services = @(Get-IisServiceState) }
    catch { $problems.Add($_.Exception.Message) }
    if (Test-Path -LiteralPath $dll -PathType Leaf) {
        try {
            [void][Reflection.Assembly]::LoadFrom($dll)
            $manager = New-Object Microsoft.Web.Administration.ServerManager
            $sites = @($manager.Sites | ForEach-Object { [pscustomobject]@{ Name = $_.Name; State = [string]$_.State; Bindings = @($_.Bindings | ForEach-Object { "$($_.Protocol) $($_.BindingInformation)" }) } })
            $selected = Resolve-IisTarget @($manager.Sites) $SiteName $HealthUrl
            $SiteName = $selected.SiteName
            $HealthUrl = $selected.HealthUrl
        }
        catch { $problems.Add($_.Exception.Message) }
        finally { if ($manager) { $manager.Dispose() } }
    }
    else { $problems.Add('Microsoft.Web.Administration.dll is missing. Install the IIS management/scripting components before deployment.') }
    $http = if ($HealthUrl) { Test-Http ([pscustomobject]@{ HealthUrl = $HealthUrl; ExpectedText = $ExpectedText; MaxRedirects = $MaxRedirects; ExpectedFinalUrl = $ExpectedFinalUrl }) } else { [pscustomobject]@{ Healthy = $false; Result = 'No health URL selected.' } }
    if (-not $http.Healthy) { $problems.Add($http.Result) }
    [pscustomobject]@{ Ready = ($problems.Count -eq 0); Computer = $env:COMPUTERNAME; SiteName = $SiteName; HealthUrl = $HealthUrl; HTTP = $http; GitPath = $GitPath; GitVersion = $gitVersion; ManagementDll = $dll; DllPresent = (Test-Path -LiteralPath $dll); Sites = $sites; Services = $services; Problems = @($problems.ToArray()) } | ConvertTo-Json -Depth 8
    return
}

function Enter-CycleLock {
    try { $locked = $script:cycleMutex.WaitOne(30000) }
    catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'The current recovery pass is still busy. Retry this command shortly.' }
}

if ($Action -eq 'Status') {
    Assert-PlainPath $store
    Assert-PlainPath $statusPath
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    $state = if (Test-Path -LiteralPath $statusPath) { Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json } else { $null }
    $age = if ($state -and $state.Time) { [math]::Round(((Get-Date).ToUniversalTime() - ([datetimeoffset]$state.Time).UtcDateTime).TotalSeconds, 1) } else { $null }
    $paused = Test-Path -LiteralPath $pausePath
    $fresh = $null -ne $age -and $age -ge 0 -and $age -le 120
    [pscustomobject]@{
        Task = $taskName
        TaskState = if ($task) { [string]$task.State } else { 'Not installed' }
        RunningAs = if ($task) { $task.Principal.UserId } else { $null }
        RecoveryActive = [bool]($task -and $task.State -eq 'Running' -and $fresh -and -not $paused -and -not $state.Paused)
        Healthy = [bool]($task -and $task.State -eq 'Running' -and $fresh -and -not $paused -and -not $state.Paused -and $state.Healthy)
        HeartbeatAgeSeconds = $age
        Paused = $paused
        BaselinePresent = Test-Path -LiteralPath $configPath
        BaselinePath = Join-Path $store 'baselines'
        PrimaryPath = $store
        EmergencyPath = if(Test-Path $configPath){(Get-Content $configPath -Raw|ConvertFrom-Json).EmergencyPath}else{$null}
        LastPass = $state
    } | ConvertTo-Json -Depth 12
    return
}

Assert-PlainPath $store
New-Item -ItemType Directory -Path $store -Force | Out-Null
& "$env:SystemRoot\System32\icacls.exe" $store /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the recovery directory.' }
$cycleMutex = New-Object Threading.Mutex($false, 'Global\gitat-Cycle')

if ($Action -in @('Pause','Uninstall')) {
    New-Item -ItemType File -Path $pausePath -Force | Out-Null
    Enter-CycleLock
    try {
        if ($Action -eq 'Uninstall') {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                Stop-ScheduledTask -TaskName $taskName
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }
        }
        Write-Output 'Recovery is paused. Baselines and quarantine files have been retained.'
    }
    finally { $cycleMutex.ReleaseMutex(); $cycleMutex.Dispose() }
    return
}
if ($Action -eq 'Resume') {
    if (-not (Test-Path -LiteralPath $configPath)) { throw 'Create a baseline first.' }
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    if (-not $task -or $task.State -eq 'Disabled') { throw 'The background task is absent or disabled. Run -Action Setup first.' }
    Remove-Item -LiteralPath $pausePath -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName $taskName
    Write-Output 'Automatic recovery resumed.'
    return
}

$managementDll = "$env:SystemRoot\System32\inetsrv\Microsoft.Web.Administration.dll"
if (-not (Test-Path -LiteralPath $managementDll -PathType Leaf)) { throw 'Microsoft.Web.Administration.dll is missing. Run -Action Preflight and install the IIS management/scripting components.' }
[void][Reflection.Assembly]::LoadFrom($managementDll)

if ($Action -in @('Baseline','Rebaseline')) {
    if ($Action -eq 'Baseline' -and (Test-Path -LiteralPath $configPath)) { throw 'A baseline already exists. Use Pause, then Rebaseline for an approved change.' }
    if ($Action -eq 'Rebaseline' -and -not (Test-Path -LiteralPath $pausePath)) { throw 'Run -Action Pause before replacing the baseline.' }
    Enter-CycleLock
    try {
        if ($Action -eq 'Rebaseline') {
            $previous = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
            foreach ($name in @('SiteName','HealthUrl','ExpectedText','MaxRedirects','ExpectedFinalUrl','Exclude','NewFiles','GitPath')) {
                if (-not $PSBoundParameters.ContainsKey($name) -and $previous.PSObject.Properties[$name]) { Set-Variable -Name $name -Value $previous.$name }
            }
        }
        if (-not $GitPath) {
            $command = Get-Command git.exe -ErrorAction SilentlyContinue
            if ($command) { $GitPath = $command.Source }
            else { $GitPath = "$env:ProgramFiles\Git\cmd\git.exe" }
        }
        $script:git = (Get-Item -LiteralPath $GitPath).FullName
        $versionText = Invoke-Git $store @('--version') | Select-Object -Last 1
        if ($versionText -notmatch '(\d+\.\d+\.\d+)' -or [version]$Matches[1] -lt [version]'2.23.0') { throw 'Git 2.23 or newer is required.' }
        if ($Exclude | Where-Object { -not $_ -or $_ -match '(^[\\/]|:|(^|[\\/])\.\.([\\/]|$))' }) { throw 'Exclusions must be relative paths within the site, such as uploads or App_Data.' }
        $manager = New-Object Microsoft.Web.Administration.ServerManager
        try {
            $selected = Resolve-IisTarget @($manager.Sites) $SiteName $HealthUrl
            $SiteName = $selected.SiteName
            $HealthUrl = $selected.HealthUrl
            $settings = [ordered]@{ FormatVersion = 2; Computer = $env:COMPUTERNAME; PrimaryPath = $store; SiteName = $SiteName; HealthUrl = $HealthUrl; ExpectedText = $ExpectedText; MaxRedirects = $MaxRedirects; ExpectedFinalUrl = $ExpectedFinalUrl; Exclude = @($Exclude); NewFiles = $NewFiles; GitPath = $script:git; Pools = @(); Targets = @() }
            $http = Test-Http ([pscustomobject]$settings)
            if (-not $http.Healthy) { throw "The baseline health check failed: $($http.Result)" }
            if (-not $settings.ExpectedFinalUrl) { $settings.ExpectedFinalUrl = ([uri]$http.FinalUrl).GetLeftPart([UriPartial]::Path) }
            $site = $manager.Sites[$SiteName]
            if (-not $site) { throw "IIS site '$SiteName' was not found. Supply -SiteName with its exact name." }
            if ([string]$site.State -ne 'Started') { throw 'Start the intended site and verify it before taking a baseline.' }
            $settings.Pools = @($manager.Sites | ForEach-Object {$_.Applications} | ForEach-Object { $_.ApplicationPoolName } | Sort-Object -Unique)
            $settings['SiteNames']=@($manager.Sites|Where-Object {[string]$_.State -eq 'Started'}|ForEach-Object Name)
            $roots = @($manager.Sites | ForEach-Object {$_.Applications} | ForEach-Object { $_.VirtualDirectories } | ForEach-Object { [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($_.PhysicalPath)).TrimEnd('\') } | Sort-Object -Unique | Sort-Object Length)
        }
        finally { $manager.Dispose() }
        $redirectPath = "$env:SystemRoot\System32\inetsrv\config\redirection.config"
        if (([xml](Get-Content -LiteralPath $redirectPath -Raw)).configuration.configurationRedirection.enabled -eq 'true') { throw 'Shared IIS configuration is not supported by this local recovery script.' }
        $inetpub=Join-Path $env:SystemDrive 'inetpub'
        if(Test-Path -LiteralPath $inetpub -PathType Container){$roots=@(@($roots)+@($inetpub)|Sort-Object -Unique|Sort-Object Length)}
        $selectedRoots = @()
        foreach ($root in $roots) {
            if ($root -notmatch '^[A-Za-z]:\\.+') { throw "Use a local site directory, not a drive root or UNC share: $root" }
            if ($store.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase) -or $root.StartsWith("$store\", [StringComparison]::OrdinalIgnoreCase) -or $root -eq $store) { throw 'The recovery directory must be outside every protected site directory.' }
            if (-not @($selectedRoots | Where-Object { $root.StartsWith("$_\", [StringComparison]::OrdinalIgnoreCase) }).Count) { $selectedRoots += $root }
        }
        $generation = Join-Path $store ('baselines\' + [guid]::NewGuid().ToString('N'))
        $number = 0
        foreach ($root in @($selectedRoots) + @("$env:SystemRoot\System32\inetsrv\config")) {
            $isConfig = $root -eq "$env:SystemRoot\System32\inetsrv\config"
            $id = if ($isConfig) { 'iiscfg' } else { 'site' + $number; $number++ }
            Assert-PlainPath $root
            $names = if ($isConfig) { @('applicationHost.config','administration.config','redirection.config') | Where-Object { Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf } } else { @(Get-ProtectedFiles $root $Exclude) }
            if (-not @($names).Count) { throw "No baseline files found in $root" }
            $repo = Join-Path $generation $id
            New-Item -ItemType Directory -Path $repo -Force | Out-Null
            $directories = @([pscustomobject]@{ Path = '.'; AccessSddl = (Get-AccessSddl $root) })
            if (-not $isConfig) {
                foreach ($relative in Get-ProtectedFiles $root $Exclude -DirectoriesOnly) {
                    $directories += [pscustomobject]@{ Path = $relative; AccessSddl = (Get-AccessSddl (Join-Path $root $relative)) }
                }
            }
            $files = @()
            foreach ($relative in $names) {
                if ($relative -match '(^|/)\.git(/|$)') { throw 'Move existing .git metadata outside the site before creating a baseline.' }
                $source = Join-Path $root $relative
                Assert-PlainPath $source
                $copy = Join-Path $repo $relative
                New-Item -ItemType Directory -Path (Split-Path $copy) -Force | Out-Null
                Copy-Item -LiteralPath $source -Destination $copy -Force
                $files += [pscustomobject]@{ Path = $relative; Hash = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash; AccessSddl = (Get-AccessSddl $source) }
            }
            Invoke-Git $repo @('init','--quiet') | Out-Null
            '* -text -filter -ident -working-tree-encoding' | Set-Content -LiteralPath (Join-Path $repo '.git\info\attributes') -Encoding ASCII
            Invoke-Git $repo @('add','--force','--all','--','.') | Out-Null
            Invoke-Git $repo @('-c','user.name=gitat','-c','user.email=iis-restore@localhost','-c','commit.gpgSign=false','commit','--quiet','-m','Approved IIS baseline') | Out-Null
            $commit = (Invoke-Git $repo @('rev-parse','HEAD') | Select-Object -Last 1).Trim()
            $settings.Targets += [pscustomobject]@{ Id = $id; Root = $root; Repo = $repo; Commit = $commit; IsConfig = $isConfig; Directories = $directories; Files = $files }
        }
        $backup = 'gitat-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
        & "$env:SystemRoot\System32\inetsrv\appcmd.exe" add backup $backup | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'IIS could not create its secondary configuration backup.' }
        $settings['IISBackup'] = $backup
        Write-Json $configPath $settings
        [void](Sync-Emergency (Get-Content $configPath -Raw|ConvertFrom-Json))
        Write-Output "Baseline saved for '$SiteName'. Protected roots: $($settings.Targets.Root -join ', ')."
        Write-Output 'Baseline creation does not start or resume automatic recovery.'
    }
    finally { $cycleMutex.ReleaseMutex(); $cycleMutex.Dispose() }
    return
}

if (-not (Test-Path -LiteralPath $configPath)) { throw 'Run -Action Baseline against the clean, working site first.' }
if ((Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json).FormatVersion -ne 2) { throw 'This older baseline has no ACL snapshot. Pause, verify clean files and permissions, then explicitly run -Action Rebaseline.' }
if (-not (Test-Path -LiteralPath $blueOpsControl -PathType Leaf)) { throw 'BlueOps is required. Run the included Deploy-BlueOps.ps1 first.' }
Assert-PlainPath $blueOpsControl
if ($Action -eq 'Install') {
    Assert-PlainPath $installedScript
    if ([IO.Path]::GetFullPath($PSCommandPath) -ne $installedScript) { Copy-Item -LiteralPath $PSCommandPath -Destination $installedScript -Force }
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;SY)(A;;FA;;;BA)')
    Set-Acl -LiteralPath $installedScript -AclObject $acl
    $run = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action Run' -f $installedScript)
    $triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)))
    $options = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $run -Trigger $triggers -Settings $options -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    Write-Output 'Installed and started. The task also runs at boot. If paused, use -Action Resume.'
    return
}

function Save-Quarantine([string]$Source, [string]$Id, [string]$Relative, [switch]$Move) {
    $destination = Join-Path $script:quarantine "$Id\$Relative"
    New-Item -ItemType Directory -Path (Split-Path $destination) -Force | Out-Null
    if ($Move) { Move-Item -LiteralPath $Source -Destination $destination -Force }
    else { Copy-Item -LiteralPath $Source -Destination $destination -Force }
}

$instanceMutex = New-Object Threading.Mutex($false, 'Global\gitat-Runner')
try { $ownsRunner = $instanceMutex.WaitOne(0) }
catch [Threading.AbandonedMutexException] { $ownsRunner = $true }
if (-not $ownsRunner) { throw 'A recovery loop is already running. Use -Action Status to inspect it.' }
$restartPending = $false
$lastRestore = $null
$script:lastServiceAction = $null
$nextRecovery = [datetime]::MinValue
$failures = 0
try {
    do {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        Enter-CycleLock
        try {
            $settings = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
            if ($settings.FormatVersion -ne 2) { throw 'Unsupported baseline format. An approved Rebaseline is required.' }
            $script:git = $settings.GitPath
            $paused = Test-Path -LiteralPath $pausePath
            $events = New-Object 'Collections.Generic.List[string]'
            $errors = New-Object 'Collections.Generic.List[string]'
            $script:quarantine = Join-Path $store ('quarantine\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
            $before = @()
            try { $before = @(Get-IisServiceState) }
            catch { $errors.Add($_.Exception.Message) }
            if (-not $paused) {
                try{[void](Sync-Emergency $settings)}catch{$errors.Add($_.Exception.Message)}
                foreach ($target in $settings.Targets) {
                    try {
                        Assert-PlainPath $target.Root
                        Assert-PlainPath $target.Repo
                        if (-not (Test-Path -LiteralPath $target.Root)) { New-Item -ItemType Directory -Path $target.Root -Force | Out-Null }
                        foreach ($directory in $target.Directories) {
                            $liveDirectory = Join-Path $target.Root $directory.Path
                            Assert-PlainPath $liveDirectory
                            if (-not (Test-Path -LiteralPath $liveDirectory)) { New-Item -ItemType Directory -Path $liveDirectory -Force | Out-Null }
                            if (Restore-Access $liveDirectory $directory.AccessSddl) { $events.Add("Restored directory permissions: $liveDirectory"); $lastRestore = (Get-Date).ToString('o') }
                        }
                        foreach ($file in $target.Files) {
                            $live = Join-Path $target.Root $file.Path
                            Assert-PlainPath $live
                            $exists = Test-Path -LiteralPath $live -PathType Leaf
                            if ($exists -and (Restore-Access $live $file.AccessSddl)) { $events.Add("Restored file permissions: $live"); $lastRestore = (Get-Date).ToString('o') }
                            if ($exists -and (Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -eq $file.Hash) { continue }
                            Invoke-Git $target.Repo @('restore',"--source=$($target.Commit)",'--worktree','--',$file.Path) | Out-Null
                            $clean = Join-Path $target.Repo $file.Path
                            if ((Get-FileHash -LiteralPath $clean -Algorithm SHA256).Hash -ne $file.Hash) { throw "Baseline verification failed for $($file.Path)" }
                            if ($exists) { Save-Quarantine $live $target.Id $file.Path }
                            New-Item -ItemType Directory -Path (Split-Path $live) -Force | Out-Null
                            Copy-Item -LiteralPath $clean -Destination $live -Force
                            [void](Restore-Access $live $file.AccessSddl)
                            if ((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -ne $file.Hash) { throw "Restore verification failed for $live" }
                            $events.Add("Restored: $live")
                            $lastRestore = (Get-Date).ToString('o')
                            if ($target.IsConfig -or [IO.Path]::GetExtension($live) -eq '.config') { $restartPending = $true }
                        }
                        if (-not $target.IsConfig) {
                            $known = @{}
                            foreach ($file in $target.Files) { $known[$file.Path] = $true }
                            foreach ($relative in Get-ProtectedFiles $target.Root $settings.Exclude) {
                                if ($known.ContainsKey($relative)) { continue }
                                if ($settings.NewFiles -eq 'Quarantine') {
                                    Save-Quarantine (Join-Path $target.Root $relative) $target.Id $relative -Move
                                    $events.Add("Quarantined new file: $relative")
                                    if ([IO.Path]::GetExtension($relative) -eq '.config') { $restartPending = $true }
                                }
                                else { $events.Add("Unexpected file: $relative") }
                            }
                        }
                    }
                    catch { $errors.Add("$($target.Id): $($_.Exception.Message)") }
                }
            }
            $siteState = 'Unknown'
            $poolStates = @()
            if (-not $paused) {
                try {
                    foreach ($name in @('WAS','W3SVC')) {
                        $service = Get-IisServiceState @($name)
                        if ($service.State -ne 'Running' -or $service.StartMode -eq 'Disabled') {
                            Invoke-BlueOps $name 'Start'
                            $events.Add("BlueOps started service: $name")
                        }
                    }
                    if ($restartPending) {
                        Invoke-BlueOps 'W3SVC' 'Restart'
                        $restartPending = $false
                        $events.Add('Restarted W3SVC after configuration repair.')
                    }
                    $manager = New-Object Microsoft.Web.Administration.ServerManager
                    try {
                        foreach ($name in $settings.Pools) {
                            $pool = $manager.ApplicationPools[$name]
                            if (-not $pool) { throw "Application pool missing: $name" }
                            if ([string]$pool.State -ne 'Started') { [void]$pool.Start(); $events.Add("Started application pool: $name") }
                        }
                        $siteNames=if($settings.SiteNames){@($settings.SiteNames)}else{@($settings.SiteName)}
                        foreach($name in $siteNames){
                            $site=$manager.Sites[$name];if(-not $site){throw "Site missing: $name"}
                            if([string]$site.State -ne 'Started'){[void]$site.Start();$events.Add("Started website: $name")}
                        }
                    }
                    finally { $manager.Dispose() }
                }
                catch { $errors.Add($_.Exception.Message) }
            }
            try {
                $manager = New-Object Microsoft.Web.Administration.ServerManager
                $siteState = [string]$manager.Sites[$settings.SiteName].State
                $poolStates = @($settings.Pools | ForEach-Object { [pscustomobject]@{ Name = $_; State = [string]$manager.ApplicationPools[$_].State } })
            }
            catch { $errors.Add($_.Exception.Message) }
            finally { if ($manager) { $manager.Dispose() } }
            $http = Test-Http $settings
            if (-not $paused -and (Get-Date) -ge $nextRecovery) {
                if (-not $http.Healthy -or $siteState -ne 'Started' -or @($poolStates | Where-Object State -ne 'Started').Count) { $failures++ }
                else { $failures = 0 }
                if ($failures -ge 3) {
                    try {
                        $manager = New-Object Microsoft.Web.Administration.ServerManager
                        foreach ($name in $settings.Pools) {
                            $pool = $manager.ApplicationPools[$name]
                            if ($pool -and [string]$pool.State -eq 'Started') { [void]$pool.Recycle() }
                        }
                        $events.Add('Recycled running application pools after three failed health checks; cooling down for 60 seconds.')
                    }
                    catch { $errors.Add($_.Exception.Message) }
                    finally { if ($manager) { $manager.Dispose() } }
                    $nextRecovery = (Get-Date).AddSeconds(60)
                    $failures = 0
                }
            }
            $after = @()
            try { $after = @(Get-IisServiceState) }
            catch { $errors.Add($_.Exception.Message) }
            $healthy = $http.Healthy -and $siteState -eq 'Started' -and $errors.Count -eq 0 -and -not @($after | Where-Object State -ne 'Running').Count -and -not @($poolStates | Where-Object State -ne 'Started').Count
            Write-Json $statusPath ([ordered]@{ Time = (Get-Date).ToString('o'); Paused = $paused; Healthy = $healthy; ServiceController = 'BlueOps'; LastServiceAction = $script:lastServiceAction; ServicesBefore = $before; Services = $after; Site = $siteState; Pools = $poolStates; HTTP = $http; LastRestore = $lastRestore; RecoveryNotBefore = $nextRecovery.ToString('o'); Events = @($events.ToArray()); Errors = @($errors.ToArray()); ScanSeconds = [math]::Round($clock.Elapsed.TotalSeconds, 2) })
        }
        catch { Write-Json $statusPath @{ Time = (Get-Date).ToString('o'); Error = $_.Exception.Message } }
        finally { $cycleMutex.ReleaseMutex() }
        if ($Action -eq 'Once') { Get-Content -LiteralPath $statusPath -Raw; break }
        Start-Sleep -Milliseconds ([math]::Max(100, 10000 - [int]$clock.ElapsedMilliseconds))
    } while ($true)
}
finally { $instanceMutex.ReleaseMutex(); $instanceMutex.Dispose(); $cycleMutex.Dispose() }

}
return $engine.ToString()
}
$parent=Split-Path $PSScriptRoot -Parent
$candidates=@(
    (Join-Path $PSScriptRoot 'Svc-Control.ps1'),(Join-Path $PSScriptRoot 'Svcwithme.ps1'),
    (Join-Path $PSScriptRoot 'general\upkeep\Svc-Control.ps1'),(Join-Path $PSScriptRoot 'general\upkeep\Svcwithme.ps1'),
    (Join-Path $parent 'general\upkeep\Svc-Control.ps1'),(Join-Path $parent 'general\upkeep\Svcwithme.ps1'),
    'C:\BlueOps\Svc-Control.ps1'
)
$controller=$candidates|Where-Object {Test-Path -LiteralPath $_ -PathType Leaf}|Select-Object -First 1
if(-not $controller){throw 'Copy Svc-Control.ps1 or Svcwithme.ps1 beside gitat.ps1; run Deploy-BlueOps.ps1 first.'}
$work=Join-Path $env:ProgramData 'IISCache-Setup';Protect-Setup $work
$engine=Join-Path $work 'gitat-engine.ps1'
if((Test-Path $engine) -and ((Get-Item $engine -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Setup engine is a reparse point.'}
Get-GitatEngineSource|Set-Content -LiteralPath $engine -Encoding UTF8
$current=& $engine -Action Status|ConvertFrom-Json
$runtime=Join-Path $env:ProgramData 'IISCache\gitat-engine.ps1'
if($current.Healthy -and (Test-Path -LiteralPath $runtime) -and (Get-FileHash $runtime).Hash -eq (Get-FileHash $engine).Hash){
    Write-Host 'gitat is already running. The approved baseline was retained.'
    $current|Select-Object Task,TaskState,Healthy,HeartbeatAgeSeconds,PrimaryPath,EmergencyPath|Format-List
    return
}
$arguments=@{Action='Setup';ServiceController=$controller}
if($SiteName){$arguments.SiteName=$SiteName}
if($HealthUrl){$arguments.HealthUrl=$HealthUrl}
& $engine @arguments | Out-Host
$state=& $engine -Action Status|ConvertFrom-Json
$state|Select-Object Task,TaskState,Healthy,HeartbeatAgeSeconds,PrimaryPath,EmergencyPath|Format-List
if(-not $state.Healthy){throw 'IIS recovery is not healthy. Review C:\ProgramData\IISCache\status.json.'}
