# Create the ten CDT rotator accounts in a dedicated test OU.
# Run on a disposable Active Directory domain controller as an authorized admin.
# All accounts are standard domain users; this script grants no admin rights.

param(
    [string]$Server = $env:COMPUTERNAME,
    [string]$OUName = 'CDT-Rotator-Test',
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

$Accounts = @(
    'mrkrabs', 'spongebob', 'squidward', 'patrick', 'sandy',
    'gary', 'puff', 'larry', 'mermaidman', 'barnacleboy'
)

try {
    # Load AD commands and identify the current test domain.
    Import-Module ActiveDirectory -ErrorAction Stop
    $Domain = Get-ADDomain -Server $Server -ErrorAction Stop
    $DomainDN = $Domain.DistinguishedName

    # Keep the lab accounts together so they're easy to identify and remove.
    $TargetOU = "OU=$OUName,$DomainDN"

    # Check each username across the entire domain, not just inside our OU.
    # Pre-existing usernames are not modified or reset.
    $Existing = @()
    foreach ($Name in $Accounts) {
        $Found = Get-ADUser -Filter { SamAccountName -eq $Name } `
            -Server $Server -ErrorAction Stop
        if ($Found) { $Existing += $Name }
    }

    Write-Host "`n======================================="
    Write-Host '     CDT TEST ACCOUNT PROVISIONING'
    Write-Host '======================================='
    Write-Host "Domain: $($Domain.DNSRoot)"
    Write-Host "Server: $Server"
    Write-Host "Target OU: $TargetOU"
    Write-Host 'Roles: All standard users (no admin privileges)'
    Write-Host 'Usernames:'
    $Accounts | ForEach-Object { Write-Host " - $_" }

    if ($Existing.Count -gt 0) {
        Write-Warning "The following usernames already exist: $($Existing -join ', ')"
        Write-Host 'No changes made. Use a clean test domain or review existing accounts.'
        return
    }

    if (-not $Apply) {
        Write-Host "`nPREVIEW ONLY. No accounts created."
        Write-Host 'Run again with -Apply when ready.'
        return
    }

    # Require a precise confirmation before making any AD changes.
    $Confirmation = Read-Host "Type 'CREATE 10' to create the test users"
    if ($Confirmation -cne 'CREATE 10') {
        Write-Host 'Cancelled. No accounts created.'
        return
    }

    # Enter one temporary initial password; the rotator will replace it.
    # The domain controller enforces its own password complexity policy.
    $InitialPassword = Read-Host 'Enter initial TEST password' -AsSecureString
    $ConfirmPassword = Read-Host 'Confirm initial TEST password' -AsSecureString

    # Compare secure-string values without printing either password.
    $P1 = [PSCredential]::new('test', $InitialPassword).GetNetworkCredential().Password
    $P2 = [PSCredential]::new('test', $ConfirmPassword).GetNetworkCredential().Password
    if ($P1 -cne $P2 -or [string]::IsNullOrEmpty($P1)) {
        Write-Warning 'Passwords did not match or were blank. No accounts created.'
        return
    }
    $P1 = $null; $P2 = $null
    $ConfirmPassword.Dispose()

    # Create the OU only when necessary; do not change existing OUs.
    $OU = Get-ADOrganizationalUnit -Identity $TargetOU `
        -Server $Server -ErrorAction SilentlyContinue
    if (-not $OU) {
        New-ADOrganizationalUnit -Name $OUName -Path $DomainDN `
            -ProtectedFromAccidentalDeletion $true -Server $Server `
            -ErrorAction Stop
        Write-Host "Created OU: $TargetOU"
    }

    $Created = @()
    foreach ($Name in $Accounts) {
        try {
            # Create an enabled, ordinary test user using the temporary password.
            New-ADUser -Name $Name -SamAccountName $Name `
                -UserPrincipalName "$Name@$($Domain.DNSRoot)" `
                -Path $TargetOU -AccountPassword $InitialPassword `
                -Enabled $true -ChangePasswordAtLogon $false `
                -Description 'CDT password rotator test account' `
                -Server $Server -ErrorAction Stop
            $Created += $Name
            Write-Host "[CREATED] $Name" -ForegroundColor Green
        }
        catch {
            # Preserve what succeeded, report what failed, and stop.
            Write-Warning "[FAILED] ${Name}: $($_.Exception.Message)"
            Write-Warning "Accounts already created: $($Created -join ', ')"
            break
        }
    }

    $InitialPassword.Dispose()
    Write-Host "`nCreated $($Created.Count) of $($Accounts.Count) accounts."
    Write-Host 'No Domain Admin membership or other privileged rights were assigned.'
}
catch {
    Write-Error "Setup stopped: $($_.Exception.Message)"
}
