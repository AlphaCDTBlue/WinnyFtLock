# PowerShell Logging Scripts

## Overview

These scripts enable PowerShell session logging and format the collected logs into organized, readable files.

- **logging.ps1** – Enables automatic PowerShell transcription logging using Windows Registry settings.
- **formatting.ps1** – Collects PowerShell transcripts, sorts them chronologically, and saves numbered, formatted copies.

## How to Use

### 1. Enable Logging

Open PowerShell as Administrator and run:

```powershell
.\logging.ps1
```

This enables automatic logging for new PowerShell sessions.

Logs are saved to:
```text
C:\Users\Public\Desktop\PowerShellLogs
```

### 2. Format Logs

After generating PowerShell activity, run:

```powershell
.\formatting.ps1
```

This organizes the collected transcripts by session start time and creates readable, numbered files.

Formatted logs are saved to:
```text
C:\Users\Public\Desktop\PowerShellLogs\Formatted
```

## Notes

- Run `logging.ps1` as Administrator.
- Open new PowerShell sessions after enabling logging.
- Run `formatting.ps1` whenever you want to organize the collected logs.
- Original transcript files are preserved.
