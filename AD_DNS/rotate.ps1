
# CDT Active Directory Password Rotator
# Run on treedome with sufficient AD permissions.

$ErrorActionPreference = "Stop"

$DC = "treedome.krusty.krab"
$Domain = "krusty.krab"

# Approved administrative accounts.
$AdminAccounts = @(
    "mrkrabs",
    "spongebob",
    "squidward",
    "patrick",
    "sandy"
)

# Approved non-administrative accounts.
$NonAdminAccounts = @(
    "gary",
    "puff",
    "larry",
    "mermaidman",
    "barnacleboy"
)

# Only these accounts can be rotated.
$AllowedAccounts = @($AdminAccounts) + @($NonAdminAccounts)


# Compare two manually entered passwords.
function Test-PasswordsMatch {
    param(
        [SecureString]$First,
        [SecureString]$Second
    )

    if ($First.Length -ne $Second.Length) {
        return $false
    }

    # Convert temporarily for a case-sensitive comparison.
    $p1 = [PSCredential]::new("temp", $First).
        GetNetworkCredential().Password

    $p2 = [PSCredential]::new("temp", $Second).
        GetNetworkCredential().Password

    return ($p1 -ceq $p2)
}


# Require the operator to enter the password twice.
function Get-ConfirmedPassword {
    param([string]$Label)

    while ($true) {

        Write-Host ""
        Write-Host "Password for: $Label"

        # Both prompts hide the actual password.
        $First = Read-Host "Enter new password" -AsSecureString
        $Second = Read-Host "Confirm new password" -AsSecureString

        if (Test-PasswordsMatch $First $Second) {

            Write-Host "[+] Password confirmed." -ForegroundColor Green

            $Second.Dispose()
            return $First
        }

        # Retry without imposing a maximum attempt count.
        Write-Warning "Passwords do not match. Try again."

        $First.Dispose()
        $Second.Dispose()
    }
}


# Load Active Directory and confirm the domain.
try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $ADDomain = Get-ADDomain `
        -Identity $Domain `
        -Server $DC `
        -ErrorAction Stop

    if ($ADDomain.DNSRoot -ine $Domain) {
        throw "Unexpected Active Directory domain."
    }

    Write-Host "[+] Connected to $Domain" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] AD connection failed." -ForegroundColor Red
    Write-Host $_.Exception.Message
    return
}


# Show the account-selection menu.
Write-Host ""
Write-Host "========================================"
Write-Host "          CDT PASSWORD ROTATOR"
Write-Host "========================================"
Write-Host ""
Write-Host "[1] Rotate ONE account"
Write-Host "[2] Rotate SELECTED accounts"
Write-Host "[3] Rotate ALL 10 accounts"
Write-Host "[4] Rotate all 5 NON-ADMIN accounts"
Write-Host "[5] Exit"
Write-Host ""

$Choice = Read-Host "Choose an option"
$Targets = @()

switch ($Choice) {

    "1" {
        Write-Host "Available: $($AllowedAccounts -join ', ')"

        $Name = (Read-Host "Enter username").Trim().ToLower()
        $Targets = @($Name)
    }

    "2" {
        Write-Host "Available: $($AllowedAccounts -join ', ')"
        Write-Host ""
        Write-Host "Separate usernames with commas."
        Write-Host "Example: gary,puff,larry"

        $InputNames = Read-Host "Enter usernames"

        # Split and normalize the selected usernames.
        $Targets = @(
            $InputNames.Split(",") |
                ForEach-Object { $_.Trim().ToLower() } |
                Where-Object { $_ -ne "" }
        )

        # Reject duplicates instead of resetting twice.
        if (@($Targets | Select-Object -Unique).Count -ne $Targets.Count) {
            Write-Host "[ERROR] Duplicate usernames."
            return
        }
    }

    "3" {
        $Targets = @($AllowedAccounts)
    }

    "4" {
        $Targets = @($NonAdminAccounts)
    }

    "5" {
        return
    }

    default {
        Write-Host "[ERROR] Invalid option."
        return
    }
}


# Refuse empty selections.
if ($Targets.Count -eq 0) {
    Write-Host "[ERROR] No accounts selected."
    return
}

# Restrict rotation to the approved account list.
$Invalid = @(
    $Targets | Where-Object { $_ -notin $AllowedAccounts }
)

if ($Invalid.Count -gt 0) {
    Write-Host "[ERROR] Unapproved accounts: $($Invalid -join ', ')"
    return
}


# Determine which Windows identity is running PowerShell.
$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$CurrentUsername = ($CurrentIdentity -split '\\')[-1]

$Validated = @()

# Verify every selected account before resetting anything.
foreach ($Username in $Targets) {

    try {
        $User = Get-ADUser `
            -Identity $Username `
            -Server $DC `
            -Properties Enabled,ServicePrincipalName `
            -ErrorAction Stop

        if (-not $User.Enabled) {
            throw "$Username is disabled."
        }

        # Avoid unexpected disruption of service identities.
        if ($User.ServicePrincipalName) {
            throw "$Username has a service principal name."
        }

        $Role = if ($Username -in $AdminAccounts) {
            "Listed Admin"
        }
        else {
            "Non-Admin"
        }

        $Validated += [PSCustomObject]@{
            Username = $Username
            Role = $Role
            DN = $User.DistinguishedName
        }
    }
    catch {
        Write-Host "[ERROR] Account validation failed: $Username" `
            -ForegroundColor Red
        Write-Host $_.Exception.Message
        return
    }
}


# Move the current account to the end of the rotation.
$ActiveAccount = @(
    $Validated | Where-Object {
        $_.Username -ieq $CurrentUsername
    }
)

if ($ActiveAccount.Count -gt 0) {

    $OtherAccounts = @(
        $Validated | Where-Object {
            $_.Username -ine $CurrentUsername
        }
    )

    $Validated = @($OtherAccounts) + @($ActiveAccount)
}


# Display the confirmed execution order.
Write-Host ""
Write-Host "========================================"
Write-Host "          ROTATION PREVIEW"
Write-Host "========================================"

$Validated |
    Select-Object Username,Role |
    Format-Table -AutoSize

Write-Host "Selected: $($Validated.Count)"
Write-Host "Domain: $Domain"
Write-Host "Passwords will not be written to files."
Write-Host ""

$Expected = "ROTATE $($Validated.Count)"
$Confirmation = Read-Host "Type '$Expected' to continue"

if ($Confirmation -cne $Expected) {
    Write-Host "Cancelled."
    return
}


# Require additional confirmation for designated admins.
$SelectedAdmins = @(
    $Validated | Where-Object {
        $_.Username -in $AdminAccounts
    }
)

if ($SelectedAdmins.Count -gt 0) {

    Write-Warning "Administrative accounts are included!"

    $SelectedAdmins | ForEach-Object {
        Write-Host " - $($_.Username)"
    }

    $AdminConfirmation = Read-Host "Type ADMINS to continue"

    if ($AdminConfirmation -cne "ADMINS") {
        Write-Host "Cancelled."
        return
    }
}


# Warn before resetting the account running the script.
if ($ActiveAccount.Count -gt 0) {

    Write-Warning "Your current login account will rotate LAST."
    Write-Host "Future logins require the new password."

    $CurrentConfirmation = Read-Host "Type CURRENT to continue"

    if ($CurrentConfirmation -cne "CURRENT") {
        Write-Host "Cancelled."
        return
    }
}


# Let the operator choose how passwords are assigned.
Write-Host ""
Write-Host "========================================"
Write-Host "           PASSWORD MODE"
Write-Host "========================================"
Write-Host ""
Write-Host "[1] BULK - One password for all selected accounts"
Write-Host "[2] INDIVIDUAL - Different password per account"
Write-Host "[3] Cancel"
Write-Host ""

$Mode = Read-Host "Choose password mode"

if ($Mode -notin @("1", "2")) {
    Write-Host "Cancelled."
    return
}

# A shared password is a risk because compromising
# one account could compromise the other accounts.
if ($Mode -eq "1" -and $Validated.Count -gt 1) {

    Write-Warning "All selected accounts will share one password."

    $SharedConfirm = Read-Host "Type SHARED to accept this risk"

    if ($SharedConfirm -cne "SHARED") {
        Write-Host "Cancelled."
        return
    }
}


# Store the passwords temporarily in process memory.
# This is NOT a CSV or persistent password file.
$PasswordAssignments = @()
$SharedPassword = $null
$Results = @()

try {

    # First collect all required passwords.
    # No Active Directory changes occur during this phase.
    if ($Mode -eq "1") {

        Write-Host ""
        Write-Host "Enter ONE password for all selected accounts."

        $SharedPassword = Get-ConfirmedPassword `
            -Label "ALL SELECTED ACCOUNTS"

        foreach ($Account in $Validated) {

            $PasswordAssignments += [PSCustomObject]@{
                Account = $Account
                Password = $SharedPassword
            }
        }
    }
    else {

        # Ask for each password before performing any reset.
        foreach ($Account in $Validated) {

            $Password = Get-ConfirmedPassword `
                -Label $Account.Username

            $PasswordAssignments += [PSCustomObject]@{
                Account = $Account
                Password = $Password
            }
        }
    }


    # All passwords have been collected.
    # Start the rotation without further prompts.
    Write-Host ""
    Write-Host "========================================"
    Write-Host "           ROTATING ACCOUNTS"
    Write-Host "========================================"

    foreach ($Assignment in $PasswordAssignments) {

        $Username = $Assignment.Account.Username

        try {

            # Submit the selected password directly to AD.
            # Active Directory enforces its password policy.
            Set-ADAccountPassword `
                -Identity $Assignment.Account.DN `
                -Server $DC `
                -Reset `
                -NewPassword $Assignment.Password `
                -Confirm:$false `
                -ErrorAction Stop

            Write-Host "[SUCCESS] $Username" -ForegroundColor Green

            $Results += [PSCustomObject]@{
                Username = $Username
                Status = "SUCCESS"
            }
        }
        catch {

            # A connection interruption may leave the
            # result uncertain even if AD accepted the reset.
            Write-Host "[ERROR] $Username" -ForegroundColor Red
            Write-Host $_.Exception.Message

            $Results += [PSCustomObject]@{
                Username = $Username
                Status = "FAILED OR UNCERTAIN"
            }

            # Stop instead of blindly continuing the batch.
            Write-Warning "Stopping remaining rotations."
            break
        }
    }
}
finally {

    # Discard password objects after the batch finishes.
    # Shared mode uses the same object for all accounts,
    # so dispose of it only once.
    if ($null -ne $SharedPassword) {
        $SharedPassword.Dispose()
    }
    else {
        foreach ($Assignment in $PasswordAssignments) {
            if ($null -ne $Assignment.Password) {
                $Assignment.Password.Dispose()
            }
        }
    }

    $PasswordAssignments = @()
}


# Display the results without displaying passwords.
Write-Host ""
Write-Host "========================================"
Write-Host "            ROTATION SUMMARY"
Write-Host "========================================"

$Results | Format-Table -AutoSize

$SuccessCount = @(
    $Results | Where-Object { $_.Status -eq "SUCCESS" }
).Count

Write-Host "Successful: $SuccessCount"
Write-Host "Processed: $($Results.Count)"
Write-Host "Selected: $($Validated.Count)"

if ($Results.Count -lt $Validated.Count) {
    Write-Warning "Some accounts were not attempted."
}

Write-Host ""
Write-Host "Verify authentication using the new passwords."
Write-Host "Done."
