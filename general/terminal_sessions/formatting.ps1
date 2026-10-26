# Original transcript location
$LogFolder = "C:\Users\Public\Desktop\PowerShellLogs"

# Folder for readable, numbered logs
$OutputFolder = "$LogFolder\Formatted"

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

# Get original transcript files only
$Files = Get-ChildItem -Path $LogFolder -Filter "*.txt" -File -Recurse |
    Where-Object {
        $_.FullName -notlike "$OutputFolder\*"
    }

# Get the actual session start time from each transcript
$Sessions = foreach ($File in $Files) {

    $Content = Get-Content -LiteralPath $File.FullName -Raw

    if ([string]::IsNullOrWhiteSpace($Content)) {
        continue
    }

    $Match = [regex]::Match(
        $Content,
        '(?m)^Start time:\s*(\d{14})'
    )

    if ($Match.Success) {
        $StartTime = [datetime]::ParseExact(
            $Match.Groups[1].Value,
            "yyyyMMddHHmmss",
            [System.Globalization.CultureInfo]::InvariantCulture
        )
    }
    else {
        $StartTime = $File.CreationTime
    }

    [PSCustomObject]@{
        File      = $File
        StartTime = $StartTime
        Content   = $Content
    }
}

# Sort terminals from oldest to newest
$Sessions = @($Sessions | Sort-Object StartTime, @{Expression={$_.File.FullName}})

$Number = 1

foreach ($Session in $Sessions) {

    # Make timestamps inside logs readable
    $Content = [regex]::Replace(
        $Session.Content,
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

    # Create readable filename
    $ReadableTime = $Session.StartTime.ToString(
        "MM-dd-yyyy_hh-mm-ss-tt"
    )

    $FileName = "terminal${Number}_${ReadableTime}.txt"

    $OutputFile = Join-Path $OutputFolder $FileName

    # Save formatted transcript
    Set-Content -LiteralPath $OutputFile `
        -Value $Content -Encoding UTF8

    $Number++
}

Write-Host "Formatted $($Number - 1) terminal logs."
Write-Host "Location: $OutputFolder"
