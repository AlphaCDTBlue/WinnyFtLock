#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [ValidateSet("Protect", "Restore", "Status")]
    [string]$Action = "Status",

    [string]$OpenfireHome = "C:\Program Files\Openfire"
)

$ErrorActionPreference = "Stop"

$ConfigFile = Join-Path $OpenfireHome "conf\openfire.xml"
$BackupDir = "C:\BlueTeam\Backups"
$AclBackup = Join-Path $BackupDir "openfire-acl.xml"

function Show-Status {
    Write-Host "`nCurrent permissions:" -ForegroundColor Cyan
    icacls.exe $ConfigFile

    Write-Host "`nFile attributes:" -ForegroundColor Cyan
    Get-Item -LiteralPath $ConfigFile |
        Select-Object FullName, Attributes
}

if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) {
    throw "Openfire configuration file not found: $ConfigFile"
}

switch ($Action) {

    "Status" {
        Show-Status
    }

    "Protect" {

        New-Item -ItemType Directory `
            -Path $BackupDir -Force | Out-Null

        if (Test-Path $AclBackup) {
            throw "ACL backup already exists. Restore or archive it before protecting again."
        }

        # Save the original ACL for restoration.
        $OriginalAcl = Get-Acl -LiteralPath $ConfigFile

        $OriginalAcl |
            Export-Clixml -LiteralPath $AclBackup

        # Remove inherited permissions.
        $Acl = Get-Acl -LiteralPath $ConfigFile
        $Acl.SetAccessRuleProtection($true, $false)

        # Remove existing explicit access rules.
        foreach ($Rule in @($Acl.Access)) {
            [void]$Acl.RemoveAccessRuleSpecific($Rule)
        }

        # Read-only permissions for SYSTEM and Administrators.
        $ReadRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
        $Allow = [System.Security.AccessControl.AccessControlType]::Allow

        $System = New-Object System.Security.Principal.SecurityIdentifier(
            "S-1-5-18"
        )

        $Admins = New-Object System.Security.Principal.SecurityIdentifier(
            "S-1-5-32-544"
        )

        foreach ($Identity in @($System, $Admins)) {

            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $Identity,
                $ReadRights,
                $Allow
            )

            $Acl.AddAccessRule($Rule)
        }

        Set-Acl -LiteralPath $ConfigFile -AclObject $Acl

        # Additional read-only attribute.
        Set-ItemProperty -LiteralPath $ConfigFile `
            -Name IsReadOnly -Value $true

        Write-Host "Openfire configuration protected." -ForegroundColor Green
        Write-Host "Original ACL backup: $AclBackup"

        Show-Status
    }

    "Restore" {

        if (-not (Test-Path $AclBackup)) {
            throw "No ACL backup found at $AclBackup"
        }

        Set-ItemProperty -LiteralPath $ConfigFile `
            -Name IsReadOnly -Value $false

        $OriginalAcl = Import-Clixml -LiteralPath $AclBackup

        Set-Acl -LiteralPath $ConfigFile -AclObject $OriginalAcl

        Write-Host "Original Openfire permissions restored." -ForegroundColor Green

        Show-Status
    }
}
