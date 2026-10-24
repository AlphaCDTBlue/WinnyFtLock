# Logging directory
$LogFolder = "C:\Users\Public\Desktop\PowerShellLogs"

New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null

# PowerShell transcription policy
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

New-Item -Path $RegPath -Force | Out-Null

New-ItemProperty -Path $RegPath `
    -Name "EnableTranscripting" `
    -Value 1 `
    -PropertyType DWord -Force | Out-Null

New-ItemProperty -Path $RegPath `
    -Name "EnableInvocationHeader" `
    -Value 1 `
    -PropertyType DWord -Force | Out-Null

New-ItemProperty -Path $RegPath `
    -Name "OutputDirectory" `
    -Value $LogFolder `
    -PropertyType String -Force | Out-Null

Write-Host "PowerShell logging enabled."
