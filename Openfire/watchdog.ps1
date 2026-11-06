
$ServiceName = "Openfire"
$LogFile = "C:\Openfire-Watchdog.log"

while ($true) {
    try {
        $Service = Get-Service -Name $ServiceName -ErrorAction Stop

        if ($Service.Status -ne "Running") {
            Start-Service -Name $ServiceName -ErrorAction Stop

            $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Add-Content -Path $LogFile -Value "$Time - Openfire was stopped. Restart attempted."
        }
    }
    catch {
        $Time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path $LogFile -Value "$Time - ERROR: $($_.Exception.Message)"
    }

    Start-Sleep -Seconds 10
}
