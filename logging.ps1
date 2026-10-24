# Original transcript location
$LogFolder = "C:\Users\Public\Desktop\PowerShellLogs"

# Folder for readable copies
$OutputFolder = "$LogFolder\Formatted"

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

Get-ChildItem -Path $LogFolder -Filter "*.txt" -File -Recurse |
Where-Object { $_.FullName -notlike "$OutputFolder\*" } |
ForEach-Object {

    $Content = Get-Content -LiteralPath $_.FullName -Raw

    $Content = [regex]::Replace(
        $Content,
        '(Command start time:|Start time:|End time:)\s*(\d{14})',
        {
            param($Match)

            $Date = [datetime]::ParseExact(
                $Match.Groups[2].Value,
                "yyyyMMddHHmmss",
                [System.Globalization.CultureInfo]::InvariantCulture
            )

            $Match.Groups[1].Value + " " +
            $Date.ToString("MM/dd/yyyy hh:mm:ss tt")
        }
    )

    $OutputFile = Join-Path $OutputFolder $_.Name

    Set-Content -LiteralPath $OutputFile `
        -Value $Content -Encoding UTF8
}