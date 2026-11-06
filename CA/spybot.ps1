$log = "C:\SpyBot_Findings.log"

Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    $drive = $_.Root

    Get-ChildItem -LiteralPath $drive -File -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        $file = $_

        try {
            if (Select-String -LiteralPath $file.FullName -Pattern 'RED\{SPY BOT\}' -Quiet -ErrorAction Stop) {
                Write-Host "[FOUND] $($file.FullName)" -ForegroundColor Green
                Add-Content -Path $log -Value "[FOUND] $($file.FullName)"
            }
        }
        catch {
            # Skip unreadable or inaccessible files
        }
    }
}