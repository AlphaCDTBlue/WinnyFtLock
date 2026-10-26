# DC setup

1. Put both launchers beside the repo's `AD_DNS` and `general` folders.
2. Check the domain, DC and account names at the top of `AD_DNS\rotate.ps1`.
3. Open **Windows PowerShell as Administrator**.
4. Go to the extracted repo. Change the folder name below if yours differs.

```powershell
cd "$env:USERPROFILE\Pictures\WinnyFtLock-main"
Get-ChildItem -Recurse -File | Unblock-File
powershell.exe -ExecutionPolicy Bypass -File .\DC-Phase1.ps1
```

5. AD window: accept the baseline, then press **Q** after monitoring starts.
6. DNS window: accept the baseline, then press **Q** after monitoring starts.
7. Wait for BlueOps. **The password reset script opens automatically next.**
8. Choose accounts and enter new passwords. Check the results. Type **DONE** in the launcher only if all intended resets succeeded.
9. Test a new login. Type **REVOKE** when ready to sign everyone out of this DC, including yourself.
10. Log back in. Open PowerShell as Administrator and run:

```powershell
cd "$env:USERPROFILE\Pictures\WinnyFtLock-main"
powershell.exe -ExecutionPolicy Bypass -File .\DC-Phase2.ps1
```

11. Type **READY**. Choose **KICK** for a one-time session sweep, **GATE** for persistent session verification, or Enter to skip. Review the gate's Grey-account exemptions before installing it.
12. Review IPs. Enter an IP and choose Block/Unblock/Status, or press Enter to continue.
13. AD guard runs until **Q**, then DNS guard runs until **Q**. They do not run together.

To resume sign-out if you skipped it:

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

Windows runtime testing has not been performed.
