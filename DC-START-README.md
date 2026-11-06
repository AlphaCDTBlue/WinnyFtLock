```powershell
cd "$env:USERPROFILE\Pictures\WinnyFtLock-main"
Get-ChildItem -Recurse -File | Unblock-File
powershell.exe -ExecutionPolicy Bypass -File .\DC-Phase1.ps1
 - click b and then yes, click q and back in main powershell click enter
 - click b and then exit notepad and click q and back in main powershell click enter
 - set password for option 3
cd "$env:USERPROFILE\Pictures\WinnyFtLock-main"
powershell.exe -ExecutionPolicy Bypass -File .\DC-Phase2.ps1
```
revoke only option
```powershell
powershell.exe -ExecutionPolicy Bypass -File .\DC-Phase1.ps1 -RevokeOnly
```

Optional: keep AD and DNS monitoring together by running these in **two separate elevated windows**:

```powershell
.\AD_DNS\AD-Guard.ps1
```

```powershell
.\AD_DNS\DNS-Guard.ps1
```