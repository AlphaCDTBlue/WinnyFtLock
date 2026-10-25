#to use on an admin PS session
#.\IP-Firewall.ps1 -Action <Block, Unblock, Status> -IP <IP Address>
#To see blocked IPs: Get-Content C:\BlueTeam\Logs\IP_Firewall_Actions.log -Tail 30


#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Block','Unblock','Status')]
    [string]$Action,
    [Parameter(Mandatory=$true)]
    [string]$IP
)

$ErrorActionPreference = 'Stop'
$parsed = $null
if (-not [System.Net.IPAddress]::TryParse($IP, [ref]$parsed)) {
    throw "Invalid IP address: $IP"
}
$IP = $parsed.ToString()
if ($parsed.Equals([System.Net.IPAddress]::Any) -or
    $parsed.Equals([System.Net.IPAddress]::IPv6Any) -or
    $parsed.Equals([System.Net.IPAddress]::Loopback) -or
    $parsed.Equals([System.Net.IPAddress]::IPv6Loopback)) {
    throw 'Refusing to manage an unspecified or loopback address.'
}

$logDir = 'C:\BlueTeam\Logs'
New-Item -Path $logDir -ItemType Directory -Force | Out-Null
$logPath = Join-Path $logDir 'IP_Firewall_Actions.log'
$id = ($IP -replace ':','_')
$names = @("BlueTeam-IPBlock-IN-$id", "BlueTeam-IPBlock-OUT-$id")
function Write-Log([string]$Message) {
    $line = '{0} | {1} | {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $env:COMPUTERNAME, $Message
    Add-Content -LiteralPath $logPath -Value $line
    Write-Host $line
}
function Get-ManagedRules {
    @(foreach ($name in $names) {
        Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    })
}
try {
    $rules = @(Get-ManagedRules)
    switch ($Action) {
        'Status' {
            if ($rules.Count -eq 0) {
                Write-Log "STATUS IP=$IP : no managed block rules found"
            } else {
                foreach ($rule in $rules) {
                    Write-Log "STATUS IP=$IP Rule=$($rule.Name) Enabled=$($rule.Enabled) Action=$($rule.Action)"
                }
            }
        }
        'Block' {
            Write-Warning 'Verify this is not a domain controller, DNS server, CA client, management host, or other critical peer.'
            $answer = Read-Host "Type BLOCK to confirm blocking $IP in both directions"
            if ($answer -cne 'BLOCK') {
                Write-Log "CANCELLED block IP=$IP"
                return
            }
            foreach ($entry in @(
                @{ Name=$names[0]; Direction='Inbound' },
                @{ Name=$names[1]; Direction='Outbound' }
            )) {
                $existing = Get-NetFirewallRule -Name $entry.Name -ErrorAction SilentlyContinue
                if ($null -eq $existing) {
                    New-NetFirewallRule -Name $entry.Name -DisplayName $entry.Name `
                        -Group 'BlueTeam Managed IP Blocks' -Direction $entry.Direction `
                        -Action Block -Enabled True -Profile Any -RemoteAddress $IP | Out-Null
                    Write-Log "CREATED block IP=$IP Direction=$($entry.Direction) Rule=$($entry.Name)"
                } else {
                    $addressFilter = $existing | Get-NetFirewallAddressFilter
                    if ($existing.Action -ne 'Block' -or $existing.Direction.ToString() -ne $entry.Direction -or
                        $addressFilter.RemoteAddress -notcontains $IP) {
                        throw "Existing managed rule $($entry.Name) differs from expected configuration. Review manually."
                    }
                    if ($existing.Enabled -ne 'True') {
                        Enable-NetFirewallRule -Name $entry.Name
                        Write-Log "REENABLED block IP=$IP Direction=$($entry.Direction)"
                    } else {
                        Write-Log "EXISTS block IP=$IP Direction=$($entry.Direction)"
                    }
                }
            }
        }
        'Unblock' {
            if ($rules.Count -eq 0) {
                Write-Log "NO-OP unblock IP=$IP : no managed rules found"
            } else {
                foreach ($rule in $rules) {
                    Remove-NetFirewallRule -Name $rule.Name
                    Write-Log "REMOVED block IP=$IP Rule=$($rule.Name)"
                }
            }
        }
    }
} catch {
    Write-Log "ERROR Action=$Action IP=$IP Message=$($_.Exception.Message)"
    throw
}
