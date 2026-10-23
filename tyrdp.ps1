[CmdletBinding()]
param(
    [ValidateSet('Install','Status','Uninstall')]
    [string]$Action = 'Status',
    [string[]]$GreyAccounts = @(),
    [string[]]$AdditionalExemptAccounts = @(),
    [switch]$AllowNoGreyAccounts,
    [Security.SecureString]$VerificationCode,
    [ValidateRange(1,300)][int]$GraceSeconds = 15,
    [ValidateRange(1,300)][int]$ResponseSeconds = 15
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell (or an administrative WinRM session).'
}

# Everyone is covered by default -- there's no list of "defended" accounts to keep
# up to date. Any local/domain account that can RDP in, including one created
# after this runs, has to pass the code challenge below unless its SID is pinned
# in ExemptSids (the Grey Team accounts resolved right here at install time).
$Root = 'C:\BlueOps\RdpGuard'
$TaskName = 'CDT-RdpGuard-Watch'
$ConfigPath = Join-Path $Root 'config.json'
$StopFlag = Join-Path $Root 'stop.flag'

function Resolve-Account([string]$Account) {
    $qualified = $Account
    if ($qualified.StartsWith('.\')) { $qualified = $env:COMPUTERNAME + $qualified.Substring(1) }
    elseif (-not $qualified.Contains('\') -and -not $qualified.Contains('@')) { $qualified = "$env:COMPUTERNAME\$qualified" }
    try {
        $sid = (New-Object Security.Principal.NTAccount($qualified)).Translate([Security.Principal.SecurityIdentifier]).Value
        [pscustomobject]@{ Account = $qualified; Sid = $sid }
    } catch { throw "Cannot resolve '$qualified'. Supply an exact existing local or DOMAIN\user account." }
}

function Protect-Locked([string]$Path) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Protect-Responses([string]$Path) {
    # SYSTEM/Administrators get full control. Authenticated Users may CREATE a file
    # here (that's how the in-session prompt hands back a code) but can't list, read
    # or delete what's already in the folder -- one RDP user can't see or clear
    # another user's pending response. SYSTEM reads and deletes each file right away.
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier('S-1-5-11')), 'CreateFiles', 'None', 'None', 'Allow')))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

# --- SYSTEM-run worker: polls RDP sessions, prompts, logs off on a bad/late code ---
$watchScript = @'
$root = 'C:\BlueOps\RdpGuard'
$state = @{}
while (-not (Test-Path "$root\stop.flag")) {
    $config = Get-Content "$root\config.json" -Raw | ConvertFrom-Json
    $now = Get-Date
    $seen = @{}

    foreach ($row in ((query session 2>$null) | Select-Object -Skip 1)) {
        $cols = ($row.TrimStart('>').Trim()) -split '\s{2,}'
        if ($cols.Count -lt 4 -or $cols[0] -notlike 'rdp-tcp#*' -or [string]::IsNullOrWhiteSpace($cols[1])) { continue }
        $sessionName, $userName, $id, $sessState = $cols[0..3]
        $seen[$id] = $true

        $sid = $null; $account = $null
        foreach ($candidate in @("$env:COMPUTERNAME\$userName", $userName)) {
            try { $sid = (New-Object Security.Principal.NTAccount($candidate)).Translate([Security.Principal.SecurityIdentifier]).Value; $account = $candidate; break } catch {}
        }
        if (-not $sid) { continue }
        if ($config.ExemptSids -contains $sid) { continue }   # Grey Team

        if (-not $state.ContainsKey($id)) {
            $state[$id] = [pscustomobject]@{ FirstSeen = $now; Verified = $false; Denied = $false; Prompted = $false; LastState = $sessState; Account = $account }
        }
        $entry = $state[$id]
        if ($entry.Verified -and $entry.LastState -eq 'Disc' -and $sessState -eq 'Active') {
            $entry.Verified = $false; $entry.Prompted = $false; $entry.FirstSeen = $now
        }
        $entry.LastState = $sessState
        if ($entry.Verified) { continue }
        if ($entry.Denied) {
            logoff $id 2>$null | Out-Null
            continue
        }

        $elapsed = ($now - $entry.FirstSeen).TotalSeconds
        $deadline = $config.GraceSeconds + $config.ResponseSeconds + 5

        if (-not $entry.Prompted -and $sessState -eq 'Active' -and $elapsed -ge $config.GraceSeconds -and $elapsed -lt $deadline) {
            $cmdFile = "$root\prompt_$id.cmd"
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Normal -STA -File $root\Prompt.ps1 $id $($config.ResponseSeconds)" | Out-File $cmdFile -Encoding ASCII -Force
            $launcherAcl = Get-Acl -LiteralPath $cmdFile
            $launcherAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                (New-Object Security.Principal.SecurityIdentifier('S-1-5-11')), 'ReadAndExecute', 'Allow')))
            Set-Acl -LiteralPath $cmdFile -AclObject $launcherAcl
            schtasks /create /tn "RdpGuardPrompt-$id" /tr $cmdFile /sc once /st 00:00 /ru $entry.Account /it /f 2>$null | Out-Null
            schtasks /run /tn "RdpGuardPrompt-$id" 2>$null | Out-Null
            $entry.Prompted = $true
        }

        if ((Test-Path "$root\responses\response_$id.json") -or $elapsed -ge $deadline) {
            $responseFile = "$root\responses\response_$id.json"
            $pass = $false
            if (Test-Path $responseFile) {
                try {
                    $response = Get-Content $responseFile -Raw | ConvertFrom-Json
                    if ($response.Status -eq 'Submitted') {
                        $code = [string]$response.Code
                        $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($code, [Convert]::FromBase64String($config.Salt), $config.Iterations)
                        $pass = ([Convert]::ToBase64String($kdf.GetBytes(32)) -eq $config.Hash)
                    }
                } catch {}
                Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
            }
            if ($pass) {
                $entry.Verified = $true
                "$(Get-Date -Format u) VERIFIED id=$id user=$($entry.Account)" | Out-File "$root\audit.log" -Append
            } else {
                $entry.Denied = $true
                logoff $id 2>$null | Out-Null
                "$(Get-Date -Format u) LOGOFF_REQUESTED id=$id user=$($entry.Account)" | Out-File "$root\audit.log" -Append
            }
            schtasks /delete /tn "RdpGuardPrompt-$id" /f 2>$null | Out-Null
            Remove-Item "$root\prompt_$id.cmd" -Force -ErrorAction SilentlyContinue
        }
    }

    foreach ($id in @($state.Keys)) {
        if (-not $seen.ContainsKey($id)) {
            $state.Remove($id)
            schtasks /delete /tn "RdpGuardPrompt-$id" /f 2>$null | Out-Null
            Remove-Item "$root\prompt_$id.cmd" -Force -ErrorAction SilentlyContinue
            Remove-Item "$root\responses\response_$id.json" -Force -ErrorAction SilentlyContinue
        }
    }

    Get-Date -Format u | Out-File "$root\heartbeat.txt" -Force
    Start-Sleep -Seconds 2
}
'@

# --- Runs INSIDE the flagged RDP session itself (launched there via a one-off
# interactive scheduled task) -- this is the actual "enter the code" prompt ---
$promptScript = @'
param([Parameter(Mandatory)][int]$SessionId, [int]$Seconds = 15)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'
$script:status = 'Closed'
$script:answer = ''
$script:ready = $false
$script:deadline = (Get-Date).AddSeconds($Seconds)
$path = "C:\BlueOps\RdpGuard\responses\response_$SessionId.json"

$form = New-Object System.Windows.Forms.Form
$form.Text = 'CDT RDP Verification'
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
$form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized
$form.TopMost = $true
$form.BackColor = [System.Drawing.Color]::FromArgb(20,26,38)
$form.ForeColor = [System.Drawing.Color]::White
$form.KeyPreview = $true

$panel = New-Object System.Windows.Forms.Panel
$panel.Size = [System.Drawing.Size]::new(560,260)
$panel.BackColor = [System.Drawing.Color]::FromArgb(35,44,62)
$form.Controls.Add($panel)

$title = New-Object System.Windows.Forms.Label
$title.Text = 'CDT RDP SESSION VERIFICATION'
$title.Font = [System.Drawing.Font]::new('Segoe UI',18,[System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true
$title.Location = [System.Drawing.Point]::new(28,25)
$panel.Controls.Add($title)

$warning = New-Object System.Windows.Forms.Label
$warning.Text = 'Enter the code. Closing, minimizing or switching away ends verification.'
$warning.Font = [System.Drawing.Font]::new('Segoe UI',10)
$warning.Size = [System.Drawing.Size]::new(505,45)
$warning.Location = [System.Drawing.Point]::new(28,77)
$panel.Controls.Add($warning)

$input = New-Object System.Windows.Forms.TextBox
$input.UseSystemPasswordChar = $true
$input.Font = [System.Drawing.Font]::new('Segoe UI',15)
$input.Size = [System.Drawing.Size]::new(330,35)
$input.Location = [System.Drawing.Point]::new(28,137)
$panel.Controls.Add($input)

$button = New-Object System.Windows.Forms.Button
$button.Text = 'Verify'
$button.Font = [System.Drawing.Font]::new('Segoe UI',11)
$button.Size = [System.Drawing.Size]::new(140,36)
$button.Location = [System.Drawing.Point]::new(380,137)
$panel.Controls.Add($button)
$form.AcceptButton = $button

$counter = New-Object System.Windows.Forms.Label
$counter.Font = [System.Drawing.Font]::new('Segoe UI',11)
$counter.AutoSize = $true
$counter.Location = [System.Drawing.Point]::new(28,202)
$panel.Controls.Add($counter)

$button.Add_Click({
    $script:answer = $input.Text
    $script:status = 'Submitted'
    $form.Close()
})
$form.Add_FormClosing({
    # Even Alt+F4 or the taskbar close generates a negative response.
    $focusTimer.Stop()
    $json = @{ Code = $script:answer; Status = $script:status } | ConvertTo-Json -Compress
    try { [System.IO.File]::WriteAllText($path, $json, [Text.Encoding]::UTF8) } catch { }
})
$form.Add_Resize({
    if ($script:ready -and $form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
        $script:status = 'Minimized'
        $form.Close()
    }
})
# Windows sometimes steals focus momentarily for a notification. Allow a brief
# return to the prompt, but fail if another window stays active.
$focusTimer = New-Object System.Windows.Forms.Timer
$focusTimer.Interval = 1200
$focusTimer.Add_Tick({
    $focusTimer.Stop()
    if ($script:ready -and -not $form.ContainsFocus -and $script:status -ne 'Submitted') {
        $script:status = 'FocusLost'
        $form.Close()
    }
})
$form.Add_Activated({ $focusTimer.Stop() })
$form.Add_Deactivate({
    if ($script:ready -and $script:status -ne 'Submitted') {
        $focusTimer.Stop()
        $focusTimer.Start()
    }
})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 100
$timer.Add_Tick({
    $remaining = [math]::Max(0, [math]::Ceiling(($script:deadline - (Get-Date)).TotalSeconds))
    $counter.Text = "Time remaining: $remaining seconds"
    if ($remaining -le 0) {
        $script:status = 'TimedOut'
        $form.Close()
    }
})
$form.Add_Shown({
    $panel.Left = [int](($form.ClientSize.Width - $panel.Width)/2)
    $panel.Top = [int](($form.ClientSize.Height - $panel.Height)/2)
    $input.Focus() | Out-Null
    $script:ready = $true
    $script:deadline = (Get-Date).AddSeconds($Seconds)
    $timer.Start()
})
try { [System.Windows.Forms.Application]::Run($form) }
finally {
    $timer.Stop(); $timer.Dispose()
    $focusTimer.Stop(); $focusTimer.Dispose()
    $form.Dispose()
}
'@

switch ($Action) {
    'Status' {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $task) { Write-Output 'RDP guard is not installed.'; break }
        $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $heartbeat = Join-Path $Root 'heartbeat.txt'
        $age = $null
        if (Test-Path -LiteralPath $heartbeat) { $age = [math]::Round(((Get-Date) - (Get-Item $heartbeat).LastWriteTime).TotalSeconds, 1) }
        [pscustomobject]@{
            Computer = $env:COMPUTERNAME; TaskState = $task.State.ToString(); Mode = 'Enforce'
            GraceSeconds = $config.GraceSeconds; ResponseSeconds = $config.ResponseSeconds
            ExemptAccounts = $config.ExemptAccounts -join ', '
            HeartbeatAgeSeconds = $age; Healthy = ($task.State -eq 'Running' -and $null -ne $age -and $age -lt 15)
            AuditLog = Join-Path $Root 'audit.log'
        }
        $log = Join-Path $Root 'audit.log'
        if (Test-Path -LiteralPath $log) { Write-Output "`nLast events:"; Get-Content -LiteralPath $log -Tail 5 }
        break
    }
    'Uninstall' {
        New-Item -ItemType File -Path $StopFlag -Force | Out-Null
        Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
        Get-ScheduledTask -TaskName 'RdpGuardPrompt-*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
        Write-Output "Guard stopped and task removed. Files/logs kept at $Root for review."
        break
    }
    'Install' {
        if ($GreyAccounts.Count -eq 0 -and -not $AllowNoGreyAccounts) {
            throw 'No Grey Team accounts provided. For a test VM only, explicitly pass -AllowNoGreyAccounts.'
        }
        if ($GreyAccounts.Count -eq 1) { throw 'Specify at least two Grey accounts or explicitly allow zero for testing.' }
        if (@($GreyAccounts | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            throw 'Grey Team account names cannot be empty.'
        }
        $greyResolved = @($GreyAccounts | ForEach-Object { Resolve-Account $_ })
        $additionalResolved = @($AdditionalExemptAccounts | ForEach-Object { Resolve-Account $_ })
        $greySids = @($greyResolved | ForEach-Object { $_.Sid } | Select-Object -Unique)
        if ($GreyAccounts.Count -gt 0 -and $greySids.Count -lt 2) {
            throw 'Provide at least two distinct, resolvable Grey Team user SIDs.'
        }
        $resolved = @($greyResolved) + @($additionalResolved)
        $sids = @($resolved | ForEach-Object { $_.Sid } | Select-Object -Unique)
        if (-not $VerificationCode -and -not $AllowNoGreyAccounts) {
            throw 'A unique -VerificationCode (SecureString) is required for competition installation.'
        }
        if (-not $VerificationCode) {
            Write-Warning 'Using the bundled TEST verification code. Supply -VerificationCode on any production/competition host.'
        }

        # The bundled verification hash is for TESTING ONLY. For competition installs
        # supply a new SecureString with -VerificationCode.
        $salt = 'nT1X/oj+tM6A+/I3FD2TA4HheC5KGl4ZiTPhVdCqqHg='
        $hash = 'H3tEC3+kEuFKniLa5y3X2k3rUdcwftnx2m9UqsLcoXc='
        $iterations = 150000
        if ($VerificationCode) {
            $saltBytes = New-Object byte[] 32
            [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($saltBytes)
            $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($VerificationCode)
            try {
                $text = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
                if ($text.Length -lt 8) { throw 'Use a verification code of at least 8 characters.' }
                $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($text, $saltBytes, $iterations)
                $hash = [Convert]::ToBase64String($kdf.GetBytes(32))
                $salt = [Convert]::ToBase64String($saltBytes)
            } finally { $text = $null; [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
        }

        Remove-Item -LiteralPath $StopFlag -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $Root 'responses') -Force | Out-Null
        Protect-Locked $Root
        Protect-Responses (Join-Path $Root 'responses')
        $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existing) {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        $watchScript | Out-File (Join-Path $Root 'Watch.ps1') -Encoding UTF8 -Force
        $promptScript | Out-File (Join-Path $Root 'Prompt.ps1') -Encoding UTF8 -Force
        $promptPath = Join-Path $Root 'Prompt.ps1'
        $promptAcl = Get-Acl -LiteralPath $promptPath
        $promptAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier('S-1-5-11')), 'ReadAndExecute', 'Allow')))
        Set-Acl -LiteralPath $promptPath -AclObject $promptAcl

        $config = [ordered]@{
            GraceSeconds = $GraceSeconds; ResponseSeconds = $ResponseSeconds
            ExemptAccounts = @($resolved | ForEach-Object { $_.Account }); ExemptSids = $sids
            Salt = $salt; Hash = $hash; Iterations = $iterations
        }
        $config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8

        Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
        $tAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Root\Watch.ps1`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $TaskName -Action $tAction -Trigger $trigger -Principal $principal -Settings $settings -Description 'CDT RDP verification guard.' -Force | Out-Null
        Start-ScheduledTask -TaskName $TaskName

        Start-Sleep -Seconds 2
        & $PSCommandPath -Action Status
        break
    }
}
