[CmdletBinding(SupportsShouldProcess)]
param()
$ErrorActionPreference = 'Stop'
$admins = 'mrkrabs','spongebob','squidward','patrick','sandy','jellyfish'
$users  = $admins + 'gary','puff','larry','mermaidman','barnacleboy'
$grey   = 'kingneptune','paintythepirate','greyteamadmin'
$a = Read-Host 'New password' -AsSecureString
$b = Read-Host 'Confirm password' -AsSecureString
$plain = { param($s) [pscredential]::new('x', $s).GetNetworkCredential().Password }
if ((& $plain $a) -cne (& $plain $b)) { throw 'Passwords do not match.' }
$keep = $users + $grey
foreach ($u in $users) {
    if (Get-LocalUser -Name $u -ErrorAction SilentlyContinue) {
        Set-LocalUser -Name $u -Password $a
        Enable-LocalUser -Name $u
        "Reset: $u"
    }
    else {
        New-LocalUser -Name $u -Password $a -PasswordNeverExpires | Out-Null
        "Created: $u"
    }
    if ($u -in $admins) {
        Add-LocalGroupMember -Group (Get-LocalGroup -SID S-1-5-32-544) -Member $u -ErrorAction SilentlyContinue
    }
}
Get-LocalUser | Where-Object {
    $_.Name -notin $keep -and $_.Name -ne $env:USERNAME -and $_.SID.Value -notmatch '-(500|501|503|504)$'
} | ForEach-Object {
    Remove-LocalUser -InputObject $_
    "Removed: $($_.Name)"
}
