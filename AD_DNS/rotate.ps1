
# CDT Active Directory Password Rotator
# Domain: krusty.krab
# Domain Controller: treedome.krusty.krab

$ErrorActionPreference = "Stop"

# Define the domain controller and expected domain.
$DC = "treedome.krusty.krab"
$Domain = "krusty.krab"

# These accounts are designated as administrators in the CDT account list.
$AdminAccounts = @(
    "mrkrabs",
    "spongebob",
    "squidward",
    "patrick",
    "sandy"
)

# These are the five designated non-admin accounts.
$NonAdminAccounts = @(
    "gary",
    "puff",
    "larry",
    "mermaidman",
    "barnacleboy"
)

# Only accounts in this list can be selected for rotation.
$AllowedAccounts = @($AdminAccounts) + @($NonAdminAccounts)


# Compare two SecureString passwords.
function Test-PasswordsMatch {
    param(
        [SecureString]$First,
        [SecureString]$Second
    )

    # Avoid converting the passwords when their lengths differ.
    if ($First.Length -ne $Second.Length) {
        return $false
    }

    # Convert temporarily to plaintext strings for comparison.
    # These values are never printed or written to files.
    $Password1 = [PSCredential]::new("temp", $First).
        GetNetworkCredential().Password

    $Password2 = [PSCredential]::new("temp", $Second).
        GetNetworkCredential().Password

    # Use case-sensitive comparison.
    return ($Password1 -ceq $Password2)
}


# Prompt for a new password until both entries match.
function Get-ConfirmedPassword {
    param([string]$Username)

    while ($true) {

        Write-Host ""
        Write-Host "Setting password for: $Username"

        # Read both entries without displaying their contents.
        $First = Read-Host "Enter new password" -AsSecureString
        $Second = Read-Host "Confirm new password" -AsSecureString

        # Only proceed when both entries match.
        if (Test-PasswordsMatch -First $First -Second $Second) {

            $Second.Dispose()

            Write-Host "[+] Passwords match." -ForegroundColor Green

            # Return the password as a SecureString.
            return $First
        }

        Write-Warning "Passwords do not match. Try again."

        # Discard the rejected entries before repeating.
        $First.Dispose()
        $Second.Dispose()
    }
}


# Load the Active Directory module and verify the domain.
try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $ADDomain = Get-ADDomain `
        -Identity $Domain `
        -Server $DC `
        -ErrorAction Stop

    if ($ADDomain.DNSRoot -ine $Domain) {
        throw "Connected to the wrong domain."
    }

    Write-Host "[+] Connected to $Domain" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Active Directory connection failed." `
        -ForegroundColor Red

    Write-Host $_.Exception.Message
    return
}


# Display the interactive menu.
Write-Host ""
Write-Host "========================================"
Write-Host "        CDT PASSWORD ROTATOR"
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
        # Display approved accounts before asking for one username.
        Write-Host ""
        Write-Host "Available accounts:"
        $AllowedAccounts | ForEach-Object {
            Write-Host " - $_"
        }

        $Name = (Read-Host "Enter username").Trim().ToLower()
        $Targets = @($Name)
    }

    "2" {
        # Display the complete list and an input example.
        Write-Host ""
        Write-Host "Available accounts:"
        $AllowedAccounts | ForEach-Object {
            Write-Host " - $_"
        }

        Write-Host ""
        Write-Host "Enter usernames separated by COMMAS."
        Write-Host "Example: gary,puff,larry"

        $InputNames = Read-Host "Enter usernames"

        # Split the input and remove extra spaces.
        $Targets = @(
            $InputNames.Split(",") |
                ForEach-Object { $_.Trim().ToLower() } |
                Where-Object { $_ -ne "" }
        )

        # Prevent the same account from being rotated twice.
        $UniqueTargets = @($Targets | Select-Object -Unique)

        if ($UniqueTargets.Count -ne $Targets.Count) {
            Write-Host "[ERROR] Duplicate usernames entered." `
                -ForegroundColor Red
            return
        }
    }

    "3" {
        # Select all ten approved accounts.
        $Targets = @($AllowedAccounts)
    }

    "4" {
        # Select only the five non-admin accounts.
        $Targets = @($NonAdminAccounts)
    }

    "5" {
        Write-Host "Exiting."
        return
    }

    default {
        Write-Host "[ERROR] Invalid menu selection." `
            -ForegroundColor Red
        return
    }
}


# Reject empty selections.
if ($Targets.Count -eq 0) {
    Write-Host "[ERROR] No accounts selected." -ForegroundColor Red
    return
}

# Check that every selected username belongs to our allowlist.
$InvalidAccounts = @(
    $Targets | Where-Object {
        $_ -notin $AllowedAccounts
    }
)

if ($InvalidAccounts.Count -gt 0) {
    Write-Host "[ERROR] Unapproved account(s):" `
        -ForegroundColor Red

    $InvalidAccounts | ForEach-Object {
        Write-Host " - $_"
    }

    Write-Host "No passwords changed."
    return
}


# Identify the current Windows account.
# If selected, this account will be moved to the end.
$CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$CurrentUsername = ($CurrentIdentity -split '\\')[-1]

# Verify every selected account before changing any passwords.
$Validated = @()

foreach ($Username in $Targets) {

    try {
        # Confirm the account exists on the expected domain controller.
        $User = Get-ADUser `
            -Identity $Username `
            -Server $DC `
            -Properties Enabled,ServicePrincipalName `
            -ErrorAction Stop

        # Avoid changing disabled accounts.
        if (-not $User.Enabled) {
            throw "Account $Username is disabled."
        }

        # Service-linked accounts may have dependent applications.
        if ($User.ServicePrincipalName) {
            throw "Account $Username has a service principal name."
        }

        # Label the account using our designated CDT account lists.
        $Role = if ($Username -in $AdminAccounts) {
            "Listed Admin"
        }
        else {
            "Non-Admin"
        }

        # Save only the validated account metadata.
        $Validated += [PSCustomObject]@{
            Username = $Username
            Role = $Role
            DN = $User.DistinguishedName
        }
    }
    catch {
        Write-Host "[ERROR] Validation failed for $Username" `
            -ForegroundColor Red

        Write-Host $_.Exception.Message
        Write-Host "No passwords have been changed."
        return
    }
}


# Move the current Windows account to the end of the rotation list.
$ActiveAccount = @(
    $Validated | Where-Object {
        $_.Username -ieq $CurrentUsername
    }
)

if ($ActiveAccount.Count -gt 0) {

    # Preserve the order of the other selected accounts.
    $OtherAccounts = @(
        $Validated | Where-Object {
            $_.Username -ine $CurrentUsername
        }
    )

    # Append the logged-in account after all other accounts.
    $Validated = @($OtherAccounts) + @($ActiveAccount)

    Write-Host ""
    Write-Warning "Current logged-in account: $CurrentUsername"
    Write-Host "This account will be rotated LAST." `
        -ForegroundColor Yellow
}


# Show every account before making any changes.
Write-Host ""
Write-Host "========================================"
Write-Host "        ROTATION CONFIRMATION"
Write-Host "========================================"

$Validated |
    Select-Object Username,Role |
    Format-Table -AutoSize

Write-Host "Total accounts: $($Validated.Count)"
Write-Host "Domain: $Domain"
Write-Host "No accounts will be disabled or deleted."
Write-Host "No passwords will be saved to disk."
Write-Host ""

# Require the operator to confirm the exact batch size.
$Expected = "ROTATE $($Validated.Count)"
$Confirmation = Read-Host "Type '$Expected' to continue"

if ($Confirmation -cne $Expected) {
    Write-Host "Rotation cancelled."
    return
}


# Require additional confirmation when admin accounts are selected.
$SelectedAdmins = @(
    $Validated | Where-Object {
        $_.Username -in $AdminAccounts
    }
)

if ($SelectedAdmins.Count -gt 0) {

    Write-Host ""
    Write-Warning "Administrative accounts are included!"

    $SelectedAdmins | ForEach-Object {
        Write-Host " - $($_.Username)"
    }

    $AdminConfirmation = Read-Host "Type ADMINS to continue"

    if ($AdminConfirmation -cne "ADMINS") {
        Write-Host "Rotation cancelled."
        return
    }
}


# Rotate the accounts one at a time.
$Results = @()

foreach ($Account in $Validated) {

    $Username = $Account.Username
    $NewPassword = $null

    Write-Host ""
    Write-Host "Rotating password for: $Username"

    # An active-session reset requires another confirmation.
    if ($Username -ieq $CurrentUsername) {

        Write-Warning "You are changing your current login password."
        Write-Host "Your existing session may continue running."
        Write-Host "Future logins will require the new password."

        $ActiveConfirmation = Read-Host "Type CURRENT to continue"

        if ($ActiveConfirmation -cne "CURRENT") {

            # Cancellation is not an AD failure.
            $Results += [PSCustomObject]@{
                Username = $Username
                Status = "CANCELLED - NOT CHANGED"
            }

            Write-Host "Current account rotation cancelled."
            break
        }
    }

    try {
        # Ask for the password twice and verify both entries match.
        $NewPassword = Get-ConfirmedPassword -Username $Username

        # Active Directory enforces its applicable password policy.
        # A reset requires sufficient permissions for this account.
        Set-ADAccountPassword `
            -Identity $Account.DN `
            -Server $DC `
            -Reset `
            -NewPassword $NewPassword `
            -Confirm:$false `
            -ErrorAction Stop

        Write-Host "[SUCCESS] Password changed for $Username" `
            -ForegroundColor Green

        # Record the outcome without recording the actual password.
        $Results += [PSCustomObject]@{
            Username = $Username
            Status = "SUCCESS"
        }
    }
    catch {
        Write-Host "[ERROR] Password reset failed: $Username" `
            -ForegroundColor Red

        Write-Host $_.Exception.Message

        # A timeout could mean AD processed the reset
        # even though the script did not receive a response.
        $Results += [PSCustomObject]@{
            Username = $Username
            Status = "FAILED OR UNCERTAIN"
        }

        # Stop the batch to avoid unexpected partial results.
        Write-Warning "Stopping remaining rotations."
        break
    }
    finally {
        # Release the SecureString after its reset attempt.
        if ($null -ne $NewPassword) {
            $NewPassword.Dispose()
        }
    }
}


# Summarize the outcome of each attempted account.
Write-Host ""
Write-Host "========================================"
Write-Host "           ROTATION SUMMARY"
Write-Host "========================================"

$Results | Format-Table -AutoSize

$SuccessCount = @(
    $Results | Where-Object {
        $_.Status -eq "SUCCESS"
    }
).Count

$CancelledCount = @(
    $Results | Where-Object {
        $_.Status -like "CANCELLED*"
    }
).Count

Write-Host "Successful: $SuccessCount"
Write-Host "Cancelled: $CancelledCount"
Write-Host "Attempted/processed: $($Results.Count)"
Write-Host "Selected: $($Validated.Count)"

if ($Results.Count -lt $Validated.Count) {
    Write-Warning "Some accounts were not attempted."
}

Write-Host ""
Write-Host "Verify authentication using the new passwords."
Write-Host "Rotation process finished."
