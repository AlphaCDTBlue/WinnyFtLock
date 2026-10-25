param(
    [ValidateSet('Preflight','Baseline','Rebaseline','Install','Run','Once','Pause','Resume','Status','Uninstall')]
    [string]$Action = 'Status',
    [string]$SiteName = '',
    [string]$HealthUrl = '',
    [string]$ExpectedText = '',
    [ValidateRange(0,10)][int]$MaxRedirects = 5,
    [string]$ExpectedFinalUrl = '',
    [string[]]$Exclude = @('App_Data','uploads','logs','temp','cache'),
    [ValidateSet('Quarantine','Report')][string]$NewFiles = 'Quarantine',
    [string]$GitPath = ''
)

$ErrorActionPreference = 'Stop'
$store = Join-Path $env:ProgramData 'watchdogs'
$configPath = Join-Path $store 'settings.json'
$statusPath = Join-Path $store 'status.json'
$pausePath = Join-Path $store 'paused'
$taskName = 'watchdogs'
$installedScript = Join-Path $store 'watchdogs.ps1'
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
        if ($name -notin @('WAS','W3SVC')) { throw 'Only IIS services are managed by watchdogs.' }
        $svc = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if (-not $svc) { throw "Service was not found: $name" }
        [pscustomobject]@{ Name = $name; State = $svc.State.Replace(' ',''); StartMode = $svc.StartMode }
    }
}

function Invoke-BlueOps([string]$Name, [string]$Operation) {
    $key = switch ($Name) { 'W3SVC' { 'IIS' }; 'WAS' { 'WAS' }; default { throw "Unsupported service: $Name" } }
    if ($Operation -notin @('Start','Restart')) { throw 'Watchdogs only starts or restarts services.' }
    Assert-PlainPath $script:blueOpsControl
    $result = & $script:blueOpsControl -Service $key -Action $Operation
    if (-not $result.Success -or $result.State -ne 'Running') { throw "BlueOps failed to $Operation $Name." }
    $script:lastServiceAction = $result
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
        if ($available.Count -ne 1) { throw "Found $($available.Count) IIS sites. Supply -SiteName, or set iis_site_name in deployment-vars.yml, to select the intended site." }
        $Name = $available[0].Name
    }
    $selected = @($available | Where-Object { $_.Name -eq $Name } | Select-Object -First 1)
    if (-not $selected.Count) { throw "Site not found: $Name" }
    $site = $selected[0]
    if (-not $Url) {
        $bindings = @($site.Bindings | Where-Object { $_.Protocol -in @('http','https') } | Sort-Object { $_.Protocol -ne 'http' } | Select-Object -First 1)
        if (-not $bindings.Count) { throw 'No HTTP binding was found. Supply -HealthUrl, or set iis_health_url in deployment-vars.yml.' }
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

if ($Action -eq 'Preflight') {
    $problems = New-Object 'Collections.Generic.List[string]'
    if (Test-Path -LiteralPath $configPath) {
        try {
            $saved = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
            foreach ($name in @('SiteName','HealthUrl','ExpectedText','ExpectedFinalUrl','GitPath')) {
                if (-not (Get-Variable -Name $name -ValueOnly) -and $saved.PSObject.Properties[$name]) { Set-Variable -Name $name -Value $saved.$name }
            }
        }
        catch { $problems.Add("Could not read existing watchdogs settings: $($_.Exception.Message)") }
    }
    if (Get-ScheduledTask -TaskName 'IISAutoRestore' -ErrorAction SilentlyContinue) { $problems.Add('The earlier IISAutoRestore task is still installed. Uninstall it before deploying watchdogs so two recovery loops do not compete.') }
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
    if (Test-Path -LiteralPath $statusPath) { Get-Content -LiteralPath $statusPath -Raw }
    else { Write-Output 'No recovery pass has been recorded yet.' }
    Write-Output "Pause requested: $(Test-Path -LiteralPath $pausePath)"
    Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Select-Object TaskName, State
    return
}

Assert-PlainPath $store
New-Item -ItemType Directory -Path $store -Force | Out-Null
& "$env:SystemRoot\System32\icacls.exe" $store /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the recovery directory.' }
$cycleMutex = New-Object Threading.Mutex($false, 'Global\watchdogs-Cycle')

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
    Remove-Item -LiteralPath $pausePath -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName $taskName
    Write-Output 'Automatic recovery resumed.'
    return
}

$env:GIT_CONFIG_NOSYSTEM = '1'
$env:GIT_CONFIG_GLOBAL = 'NUL'
$env:GIT_TERMINAL_PROMPT = '0'
foreach ($name in @('GIT_DIR','GIT_WORK_TREE','GIT_INDEX_FILE','GIT_COMMON_DIR','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES')) { Remove-Item "Env:\$name" -ErrorAction SilentlyContinue }
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
            $settings = [ordered]@{ FormatVersion = 2; SiteName = $SiteName; HealthUrl = $HealthUrl; ExpectedText = $ExpectedText; MaxRedirects = $MaxRedirects; ExpectedFinalUrl = $ExpectedFinalUrl; Exclude = @($Exclude); NewFiles = $NewFiles; GitPath = $script:git; Pools = @(); Targets = @() }
            $http = Test-Http ([pscustomobject]$settings)
            if (-not $http.Healthy) { throw "The baseline health check failed: $($http.Result)" }
            if (-not $settings.ExpectedFinalUrl) { $settings.ExpectedFinalUrl = ([uri]$http.FinalUrl).GetLeftPart([UriPartial]::Path) }
            $site = $manager.Sites[$SiteName]
            if (-not $site) { throw "IIS site '$SiteName' was not found. Supply -SiteName with its exact name." }
            if ([string]$site.State -ne 'Started') { throw 'Start the intended site and verify it before taking a baseline.' }
            $settings.Pools = @($site.Applications | ForEach-Object { $_.ApplicationPoolName } | Sort-Object -Unique)
            $roots = @($site.Applications | ForEach-Object { $_.VirtualDirectories } | ForEach-Object { [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($_.PhysicalPath)).TrimEnd('\') } | Sort-Object -Unique | Sort-Object Length)
        }
        finally { $manager.Dispose() }
        $redirectPath = "$env:SystemRoot\System32\inetsrv\config\redirection.config"
        if (([xml](Get-Content -LiteralPath $redirectPath -Raw)).configuration.configurationRedirection.enabled -eq 'true') { throw 'Shared IIS configuration is not supported by this local recovery script.' }
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
            Invoke-Git $repo @('-c','user.name=watchdogs','-c','user.email=iis-restore@localhost','-c','commit.gpgSign=false','commit','--quiet','-m','Approved IIS baseline') | Out-Null
            $commit = (Invoke-Git $repo @('rev-parse','HEAD') | Select-Object -Last 1).Trim()
            $settings.Targets += [pscustomobject]@{ Id = $id; Root = $root; Repo = $repo; Commit = $commit; IsConfig = $isConfig; Directories = $directories; Files = $files }
        }
        $backup = 'watchdogs-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
        & "$env:SystemRoot\System32\inetsrv\appcmd.exe" add backup $backup | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'IIS could not create its secondary configuration backup.' }
        $settings['IISBackup'] = $backup
        Write-Json $configPath $settings
        Write-Output "Baseline saved for '$SiteName'. Protected roots: $($settings.Targets.Root -join ', ')."
        Write-Output 'Baseline creation does not start or resume automatic recovery.'
    }
    finally { $cycleMutex.ReleaseMutex(); $cycleMutex.Dispose() }
    return
}

if (-not (Test-Path -LiteralPath $configPath)) { throw 'Run -Action Baseline against the clean, working site first.' }
if ((Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json).FormatVersion -ne 2) { throw 'This older baseline has no ACL snapshot. Pause, verify clean files and permissions, then explicitly run -Action Rebaseline.' }
if (-not (Test-Path -LiteralPath $blueOpsControl -PathType Leaf)) { throw 'BlueOps is required. Deploy this package with deploy.yml first.' }
Assert-PlainPath $blueOpsControl
if ($Action -eq 'Install') {
    if ([IO.Path]::GetFullPath($PSCommandPath) -ne $installedScript) { Copy-Item -LiteralPath $PSCommandPath -Destination $installedScript -Force }
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

$instanceMutex = New-Object Threading.Mutex($false, 'Global\watchdogs-Runner')
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
                        $site = $manager.Sites[$settings.SiteName]
                        if (-not $site) { throw "Site missing: $($settings.SiteName)" }
                        if ([string]$site.State -ne 'Started') { [void]$site.Start(); $events.Add("Started website: $($settings.SiteName)") }
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
