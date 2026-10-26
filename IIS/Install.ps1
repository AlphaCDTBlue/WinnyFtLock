# Install.ps1 - installs Sysinternals Suite + Wireshark (+ Npcap). Run as Administrator, NO arguments.
# Offline: put SysinternalsSuite.zip / Wireshark*x64.exe / npcap*.exe next to this script.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'   # progress bar makes Invoke-WebRequest crawl on 5.1

$ToolsDir = 'C:\Tools'
$SysDir = Join-Path $ToolsDir 'Sysinternals'
$DlDir = Join-Path $ToolsDir '_downloads'
$InstallNpcap = $true
$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

function Say([string]$m, [string]$c = 'Gray') { Write-Host $m -ForegroundColor $c }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Say 'Run this as Administrator.' 'Red'; exit 1 }

# Server 2019 PowerShell often defaults to old TLS and fails downloads
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 12288 } catch { }

New-Item -ItemType Directory -Path $ToolsDir, $DlDir -Force | Out-Null
try { Start-Transcript -Path (Join-Path $ToolsDir 'toolkit.log') -Append | Out-Null } catch { }

function Get-File {
    param([string[]]$Urls, [string]$Dest, [long]$MinBytes = 100000)
    foreach ($u in $Urls) {
        for ($i = 1; $i -le 3; $i++) {
            try {
                Say "Downloading $u (try $i)"
                Invoke-WebRequest -Uri $u -OutFile $Dest -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop
                if ((Test-Path $Dest) -and ((Get-Item $Dest).Length -ge $MinBytes)) { return $true }
                Say 'Downloaded file too small, retrying' 'Yellow'
            } catch {
                Say ('Download error: ' + $_.Exception.Message) 'Yellow'
            }
            Remove-Item $Dest -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
    }
    return $false
}

function Find-LocalFile([string]$Filter) {
    foreach ($d in @($here, $DlDir)) {
        $f = Get-ChildItem -Path $d -Filter $Filter -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($f) { return $f.FullName }
    }
    return $null
}

function Test-Signature([string]$Path, [string]$SubjectPattern) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    $st = $sig.Status.ToString()
    if ($st -eq 'HashMismatch' -or $st -eq 'NotSigned') {
        Say "Signature check FAILED for $Path ($st)" 'Red'; return $false
    } elseif ($st -ne 'Valid') {
        Say "Signature status for $Path is $st (offline/chain issue?) - continuing" 'Yellow'
    }
    if ($sig.SignerCertificate -and ($sig.SignerCertificate.Subject -notmatch $SubjectPattern)) {
        Say "Unexpected signer for $Path : $($sig.SignerCertificate.Subject)" 'Red'; return $false
    }
    return $true
}

function Add-ToMachinePath([string]$Dir) {
    $mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (($mp -split ';') -notcontains $Dir) {
        [Environment]::SetEnvironmentVariable('Path', ($mp.TrimEnd(';') + ';' + $Dir), 'Machine')
    }
    if (($env:Path -split ';') -notcontains $Dir) { $env:Path = $env:Path + ';' + $Dir }
}

function Set-SysEula {
    $names = @('Process Explorer', 'Process Monitor', 'Autoruns', 'TCPView', 'PsExec', 'Sigcheck', 'Handle', 'ListDLLs',
        'Strings', 'AccessChk', 'Sysmon', 'Streams', 'PsLoggedon', 'PsList', 'PsKill', 'PsService', 'PsGetSid', 'PsInfo',
        'PsFile', 'PsPasswd', 'PsLogList', 'PsSuspend', 'PsShutdown', 'LogonSessions', 'PipeList', 'ProcDump', 'RAMMap',
        'VMMap', 'DebugView', 'AccessEnum', 'ShareEnum', 'Whois', 'Coreinfo', 'Contig', 'Junction', 'RegJump')
    foreach ($root in @('HKCU:\Software\Sysinternals', 'Registry::HKEY_USERS\.DEFAULT\Software\Sysinternals')) {
        foreach ($n in $names) {
            try {
                $k = "$root\$n"
                New-Item -Path $k -Force | Out-Null
                New-ItemProperty -Path $k -Name 'EulaAccepted' -Value 1 -PropertyType DWord -Force | Out-Null
            } catch { }
        }
    }
}

function Install-Sysinternals {
    $existing = @(Get-ChildItem -Path $SysDir -Filter *.exe -ErrorAction SilentlyContinue).Count
    if (($existing -ge 50) -and (Test-Path (Join-Path $SysDir 'procexp64.exe'))) {
        Say "Sysinternals already installed ($existing tools)." 'Green'
        Set-SysEula
        Add-ToMachinePath $SysDir
        return $true
    }
    $zip = Join-Path $DlDir 'SysinternalsSuite.zip'
    $ok = Get-File -Urls @('https://download.sysinternals.com/files/SysinternalsSuite.zip') -Dest $zip -MinBytes 5000000
    if (-not $ok) {
        $l = Find-LocalFile 'SysinternalsSuite*.zip'
        if ($l) { $zip = $l; $ok = $true; Say "Using local $zip" 'Yellow' }
    }
    New-Item -ItemType Directory -Path $SysDir -Force | Out-Null
    if ($ok) {
        try { Expand-Archive -Path $zip -DestinationPath $SysDir -Force -ErrorAction Stop }
        catch { Say ('Extract failed (a tool running from there?): ' + $_.Exception.Message) 'Red'; $ok = $false }
    }
    if (-not $ok) {
        Say 'Suite zip failed - trying core tools one by one...' 'Yellow'
        $core = @('procexp64.exe', 'procmon64.exe', 'Autoruns64.exe', 'autorunsc64.exe', 'tcpview64.exe', 'Sysmon64.exe',
            'PsExec64.exe', 'sigcheck64.exe', 'handle64.exe', 'Listdlls64.exe', 'strings64.exe', 'accesschk64.exe',
            'logonsessions64.exe', 'procdump64.exe', 'psloggedon64.exe', 'pslist64.exe', 'pskill64.exe')
        foreach ($t in $core) {
            [void](Get-File -Urls @("https://live.sysinternals.com/$t") -Dest (Join-Path $SysDir $t) -MinBytes 50000)
        }
    }
    $count = @(Get-ChildItem -Path $SysDir -Filter *.exe -ErrorAction SilentlyContinue).Count
    if ($count -lt 5) { return $false }
    Get-ChildItem -Path $SysDir -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    foreach ($t in @('procexp64.exe', 'autoruns64.exe', 'sigcheck64.exe')) {
        $p = Join-Path $SysDir $t
        if (Test-Path $p) { [void](Test-Signature $p 'Microsoft') }
    }
    Set-SysEula
    Add-ToMachinePath $SysDir
    Say "Sysinternals: $count tools in $SysDir (open a NEW shell for PATH)" 'Green'
    return $true
}

function Get-WiresharkCandidates {
    # Wireshark 4.7+ (what "latest" points to) dropped Server 2019. 4.6 was the last branch that supports it.
    $names = @()
    try {
        $page = Invoke-WebRequest -Uri 'https://www.wireshark.org/download/win64/' -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
        foreach ($branch in @('4\.6', '4\.4')) {
            $v = [regex]::Matches($page.Content, "Wireshark-($branch\.\d+)-x64\.exe") |
                ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique |
                Sort-Object { [version]$_ } -Descending | Select-Object -First 1
            if ($v) { $names += "Wireshark-$v-x64.exe" }
        }
    } catch { Say 'Could not read Wireshark download listing, using fallback versions' 'Yellow' }
    foreach ($f in @('Wireshark-4.6.9-x64.exe', 'Wireshark-4.4.19-x64.exe')) {
        if ($names -notcontains $f) { $names += $f }
    }
    return $names
}

function Invoke-WiresharkInstaller([string]$Exe) {
    $wsExe = Join-Path (Join-Path $env:ProgramFiles 'Wireshark') 'Wireshark.exe'
    $p = Start-Process -FilePath $Exe -ArgumentList '/S' -Wait -PassThru
    for ($i = 0; ($i -lt 30) -and (-not (Test-Path $wsExe)); $i++) { Start-Sleep -Seconds 2 }
    if (Test-Path $wsExe) { return $true }
    Say ("Installer exit code " + $p.ExitCode + " - Wireshark.exe not found") 'Yellow'
    return $false
}

function Install-Wireshark {
    $wsDir = Join-Path $env:ProgramFiles 'Wireshark'
    $wsExe = Join-Path $wsDir 'Wireshark.exe'
    if (Test-Path $wsExe) { Say 'Wireshark already installed.' 'Green'; Add-ToMachinePath $wsDir; return $true }
    Remove-Item (Join-Path $DlDir 'Wireshark-latest-x64.exe') -Force -ErrorAction SilentlyContinue

    foreach ($name in (Get-WiresharkCandidates)) {
        $exe = Join-Path $DlDir $name
        $ok = Get-File -Urls @("https://www.wireshark.org/download/win64/$name", "https://2.na.dl.wireshark.org/win64/$name") -Dest $exe -MinBytes 40000000
        if (-not $ok) { continue }
        if (-not (Test-Signature $exe 'Wireshark')) { continue }
        Say "Installing $name silently..."
        if (Invoke-WiresharkInstaller $exe) { Add-ToMachinePath $wsDir; return $true }
        Say "$name failed - trying next version" 'Yellow'
    }

    $l = Find-LocalFile 'Wireshark-4.*x64*.exe'
    if ($l) {
        Say "Trying local installer $l" 'Yellow'
        if ((Test-Signature $l 'Wireshark') -and (Invoke-WiresharkInstaller $l)) { Add-ToMachinePath $wsDir; return $true }
    }
    return $false
}

function Install-Npcap {
    if ((Get-Service -Name npcap -ErrorAction SilentlyContinue) -or (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll")) {
        Say 'Npcap already installed.' 'Green'; return $true
    }
    $url = $null
    try {
        $page = Invoke-WebRequest -Uri 'https://npcap.com/dist/' -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
        $vers = [regex]::Matches($page.Content, 'npcap-(\d+\.\d+)\.exe') | ForEach-Object { $_.Groups[1].Value } |
            Select-Object -Unique | Sort-Object { [version]$_ } -Descending
        if ($vers) { $url = 'https://npcap.com/dist/npcap-' + @($vers)[0] + '.exe' }
    } catch { Say 'Could not read npcap.com listing, using fallback version' 'Yellow' }
    if (-not $url) { $url = 'https://npcap.com/dist/npcap-1.90.exe' }
    $exe = Join-Path $DlDir 'npcap-latest.exe'
    $ok = Get-File -Urls @($url) -Dest $exe -MinBytes 500000
    if (-not $ok) {
        $l = Find-LocalFile 'npcap-*.exe'
        if ($l) { $exe = $l; $ok = $true; Say "Using local $exe" 'Yellow' }
    }
    if (-not $ok) { return $false }
    if (-not (Test-Signature $exe 'Insecure|Npcap|Nmap')) { return $false }
    Say 'Npcap installer opening now - click I Agree > Install > Next > Finish (free edition has no silent mode).' 'Yellow'
    $p = Start-Process -FilePath $exe -PassThru
    [void]$p.WaitForExit(900000)
    Start-Sleep -Seconds 3
    return [bool](Get-Service -Name npcap -ErrorAction SilentlyContinue)
}

$results = [ordered]@{}

$r = @(Install-Sysinternals)[-1]
$results['Sysinternals'] = if ($r) { 'OK' } else { 'FAILED' }

$r = @(Install-Wireshark)[-1]
$results['Wireshark'] = if ($r) { 'OK' } else { 'FAILED' }

if ($r -and $InstallNpcap) {
    $n = @(Install-Npcap)[-1]
    $results['Npcap'] = if ($n) { 'OK' } else { 'FAILED (Wireshark cannot capture without it)' }
    if ($n) {
        try {
            $ifs = & (Join-Path $env:ProgramFiles 'Wireshark\dumpcap.exe') -D 2>$null
            if ($ifs) { $results['Capture test'] = 'OK - interfaces found' } else { $results['Capture test'] = 'FAILED - no interfaces (reboot may be needed)' }
        } catch { $results['Capture test'] = 'could not run dumpcap' }
    }
}

Write-Host ''
Say '=== Toolkit summary ===' 'Cyan'
$fail = $false
foreach ($k in $results.Keys) {
    $color = 'Green'
    if ($results[$k] -like 'FAILED*') { $color = 'Red'; $fail = $true }
    Write-Host (' {0,-14} {1}' -f $k, $results[$k]) -ForegroundColor $color
}
try { Stop-Transcript | Out-Null } catch { }
if ($fail) { exit 1 } else { exit 0 }
