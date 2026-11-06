# CDT Active Directory Password Rotator

A PowerShell tool for manually rotating approved Active Directory account passwords on the `krusty.krab` domain. It can change one account, a comma-separated selection, all ten approved accounts, or the five non-admin accounts.

**This tool only resets passwords.** It does not create, delete, or disable accounts; generate passwords; use Google Sheets; or write password CSV files.

## Requirements

- Run on the designated domain controller `treedome.krusty.krab`, or an authorized Windows machine with connectivity to it.
- Windows PowerShell with the **ActiveDirectory** module available.
- A signed-in account with permission to reset the selected AD users' passwords. Running on the DC alone does not grant that permission.
- Review the ten-account allowlist and the domain/DC settings in the script before using it in another environment.
- Ensure the passwords you plan to enter satisfy your AD domain's effective password policy.

## Run the rotator

Open PowerShell using an authorized account, navigate to the folder containing the script, and run:

```powershell
.\Rotate-CDTPasswords.ps1
```

If PowerShell reports that the file is not digitally signed, inspect the execution policy using `Get-ExecutionPolicy -List`. Use the organization's approved signing/execution-policy procedure; do not bypass an enforced policy.

## Menu options

```text
========================================
          CDT PASSWORD ROTATOR
========================================

[1] Rotate ONE account
[2] Rotate SELECTED accounts
[3] Rotate ALL 10 accounts
[4] Rotate all 5 NON-ADMIN accounts
[5] Exit
```

- **1 — One account:** Type one approved username, such as `gary`.
- **2 — Selected accounts:** Type usernames **separated by commas**, for example `gary,puff,larry`. Names outside the allowlist and duplicate selections are rejected.
- **3 — All accounts:** Selects all ten approved usernames.
- **4 — Non-admin accounts:** Selects `gary`, `puff`, `larry`, `mermaidman`, and `barnacleboy`.
- **5 — Exit:** Leaves without resetting anything.

### Approved usernames

| Designated admin accounts | Designated non-admin accounts |
| --- | --- |
| `mrkrabs` | `gary` |
| `spongebob` | `puff` |
| `squidward` | `larry` |
| `patrick` | `mermaidman` |
| `sandy` | `barnacleboy` |

These role labels reflect the competition's account list; the script does **not** verify actual AD group membership. Other accounts, including `krusty`, are not rotated merely because you are signed in as them.

## Confirm the selected accounts

Before changing anything, the script checks the target domain and validates that selected users exist, are enabled, and do not have a service principal name. It shows the planned rotation order and count.

Type the exact phrase requested, for example:

```text
Type 'ROTATE 3' to continue: ROTATE 3
```

If designated admin accounts are included, a second prompt requires:

```text
Type ADMINS to continue: ADMINS
```

If the currently signed-in account is also in the selected allowlist, it is placed **last** and the script additionally requires `CURRENT`. Its existing Windows session may continue, but future logins will require its new password. Have another authorized recovery login available.

## Choose how to enter passwords

```text
========================================
           PASSWORD MODE
========================================

[1] BULK - One password for all selected accounts
[2] INDIVIDUAL - Different password per account
[3] Cancel
```

### Mode 1 — Bulk

Enter the **same password twice**, once for the whole selection. After the entries match, the script uses that password for all selected accounts and runs the resets without pausing between accounts. When more than one account is selected, you must type `SHARED` to acknowledge the risk of password reuse.

**Security warning:** A single leaked password can compromise every account sharing it. Strongly prefer individual passwords for privileged accounts.

### Mode 2 — Individual

Enter and confirm a **different password for each selected account**. After collecting every password, the script runs the entire batch without further password prompts. There is no fixed limit on re-entering mismatched passwords.

Both modes use hidden password prompts (`Read-Host -AsSecureString`) and let **Active Directory enforce password requirements** rather than imposing a script-specific length/complexity policy.

## Results and errors

The script displays `[SUCCESS]` for each reset that AD reports successful and a final table containing usernames and statuses, **not passwords**.

If an AD reset fails or its result is uncertain (for example, due to a connection problem), the script **stops the remaining batch**. Earlier successful resets stay in effect; there is no automatic rollback. Review the summary before retrying, and confirm authentication independently where practical.

The script does not store passwords in files or upload them to any external service. Password values do exist temporarily in the running PowerShell process and may be exposed if the host is compromised.

## Quick example

To rotate `gary`, `puff`, and `larry` with one shared password:

1. Run `.\Rotate-CDTPasswords.ps1`.
2. Choose **2 — Rotate SELECTED accounts**.
3. Enter `gary,puff,larry`.
4. Review the three-account preview and type `ROTATE 3`.
5. Choose **1 — BULK**, then type `SHARED`.
6. Enter and confirm the new password once.
7. Read the final summary and test a new domain login.

To give all ten accounts distinct passwords, choose **3 — ALL 10**, confirm with `ROTATE 10` and `ADMINS`, then choose **2 — INDIVIDUAL**. Enter and confirm each password before the reset batch begins.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| AD module not found | Run on a system with the Active Directory PowerShell module. |
| Cannot connect to AD | Verify `treedome.krusty.krab`, DNS, network reachability, and the domain name in the script. |
| Access denied on reset | Verify the signed-in identity has reset permissions for that target account. |
| Account rejected during validation | Ensure it is on the allowlist, exists, is enabled, and has no SPN. |
| AD rejects a password | Enter a password complying with the account's actual AD password policy; rerun for that account after verifying the failed/uncertain outcome. |
| Current account selected | The script rotates it last and requires `CURRENT` confirmation. |
| Batch stops partway through | Review successful and failed/uncertain statuses; prior successful changes remain active. |

**Before competition use:** Test on an isolated lab domain and verify a fresh sign-in with a changed password. Password resets do not necessarily terminate existing sessions or invalidate every existing authentication ticket immediately.
