<#
.SYNOPSIS
  Show-Connections.ps1 - one-time list of every remote IP talking to this server right now.

.DESCRIPTION
  Run in PowerShell (admin is not required, but it shows more with it):
      .\Show-Connections.ps1
  No arguments. It prints one line per remote IP + direction + port + process.

  Columns:
    RemoteIP   the other machine
    Dir        IN  = that machine connected to a service on this server
               OUT = this server connected out to that machine
               This is a GUESS: a connection is called IN when its local port has
               a listener on this server, otherwise OUT.
    Port       IN: the local port being used (3389 = RDP, 80/443 = web, ...)
               OUT: the remote port this server is calling
    Process    program that owns the connection
    Service    Windows service(s) inside that process
    Conns      how many connections to that IP on that port
    States     Established = live now; TimeWait/CloseWait = just finished

  Not shown: connections to 127.0.0.1 / ::1 and connections to the server itself.
  UDP has no connections, so UDP traffic (DNS, etc.) does not appear here.
  It does not say WHO is behind a connection or WHAT they ran: use cmdwatch.ps1.

  If a query fails, it says so and shows nothing. An error is never reported as
  "no connections".
#>

$ErrorActionPreference = 'Stop'

# ---- read every TCP connection in one call (no filters) ----
try {
    $tcp = @(Get-NetTCPConnection)
} catch {
    Write-Host "ERROR: could not read TCP connections: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Nothing is shown, because an empty list here would be misleading.' -ForegroundColor Red
    exit 1
}
if (-not $tcp.Count) {
    Write-Host 'ERROR: Windows returned no TCP connections at all, not even listeners. That is not normal.' -ForegroundColor Red
    Write-Host 'Treat this result as unreliable.' -ForegroundColor Red
    exit 1
}

# ports this server is listening on = inbound services
$listenPorts = @{}
$tcp | Where-Object { $_.State -eq 'Listen' } | ForEach-Object { $listenPorts[[int]$_.LocalPort] = $true }

# process id -> program name, and process id -> service name(s)
$namesOk = $true
$nameError = ''
$procs = @{}
$svcs = @{}
try {
    Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
    Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object {
        $k = [int]$_.ProcessId
        if ($svcs.ContainsKey($k)) { $svcs[$k] += ',' + $_.Name } else { $svcs[$k] = $_.Name }
    }
} catch {
    $namesOk = $false
    $nameError = $_.Exception.Message
}

$skip = '^(127\.|::1$|0\.0\.0\.0$|::$)'
$rows = @($tcp | Where-Object {
    $_.State -ne 'Listen' -and $_.State -ne 'Bound' -and
    $_.RemoteAddress -notmatch $skip -and $_.RemoteAddress -ne $_.LocalAddress
} | ForEach-Object {
    $dir = 'OUT'
    $port = $_.RemotePort
    if ($listenPorts.ContainsKey([int]$_.LocalPort)) { $dir = 'IN'; $port = $_.LocalPort }
    $procId = [int]$_.OwningProcess
    [pscustomobject]@{
        RemoteIP = [string]$_.RemoteAddress
        Dir      = $dir
        Port     = [int]$port
        Process  = [string]$procs[$procId]
        Service  = [string]$svcs[$procId]
        State    = [string]$_.State
    }
})

Write-Host ''
Write-Host ("Connections on {0} at {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Host ''

if (-not $rows.Count) {
    Write-Host 'No remote connections right now (the TCP query worked; there are none).'
} else {
    $rows | Group-Object RemoteIP, Dir, Port, Process | ForEach-Object {
        $f = $_.Group[0]
        [pscustomobject]@{
            RemoteIP = $f.RemoteIP
            Dir      = $f.Dir
            Port     = $f.Port
            Process  = $f.Process
            Service  = $f.Service
            Conns    = $_.Count
            States   = (($_.Group | ForEach-Object { $_.State } | Select-Object -Unique) -join ',')
        }
    } | Sort-Object Dir, RemoteIP, Port | Format-Table -AutoSize -Wrap

    $ips = @($rows | ForEach-Object { $_.RemoteIP } | Select-Object -Unique)
    Write-Host ("{0} different remote IPs." -f $ips.Count)
}

Write-Host 'Dir is a guess: IN = the local port has a listener on this server. TCP only.'
if (-not $namesOk) {
    Write-Host "Warning: process/service names could not be read ($nameError). Those columns may be blank." -ForegroundColor Yellow
}
