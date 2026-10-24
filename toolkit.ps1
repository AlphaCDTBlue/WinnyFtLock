param(
    [string]$ToolsDir = "C:\Tools"
)

New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null

if (-not (Get-Service npcap -ErrorAction SilentlyContinue)) {
    $npcap = "$env:TEMP\npcap.exe"
    Invoke-WebRequest "https://npcap.com/dist/npcap-1.90.exe" -OutFile $npcap
    Start-Process $npcap -ArgumentList "/S" -Wait
}

if (-not (Test-Path "C:\Program Files\Wireshark\Wireshark.exe")) {
    $wireshark = "$env:TEMP\wireshark.exe"
    Invoke-WebRequest "https://www.wireshark.org/download/win64/Wireshark-latest-x64.exe" -OutFile $wireshark
    Start-Process $wireshark -ArgumentList "/S" -Wait
}

$sysPath = Join-Path $ToolsDir "Sysinternals"
if (-not (Test-Path $sysPath)) {
    $zip = "$env:TEMP\sysinternals.zip"
    Invoke-WebRequest "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile $zip
    Expand-Archive $zip $sysPath -Force
}

Get-ChildItem $sysPath -Filter *.exe | ForEach-Object {
    $key = "HKCU:\Software\Sysinternals\$($_.BaseName)"
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name EulaAccepted -Value 1 -Type DWord
}

Write-Output "Done. Sysinternals tools: $sysPath"
