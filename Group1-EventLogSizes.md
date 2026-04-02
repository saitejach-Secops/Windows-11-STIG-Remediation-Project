# Group 1 — Event Log Sizes

**STIGs:** WN11-AU-000500 · WN11-AU-000505 · WN11-AU-000510
**Script:** [`WN11-AU-EventLog-Sizes.ps1`](../scripts/WN11-AU-EventLog-Sizes.ps1)

---

## Vulnerability

| STIG ID | Title | MITRE ATT&CK |
|---------|-------|--------------|
| WN11-AU-000500 | Application event log size must be 32768 KB or greater | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| WN11-AU-000505 | Security event log size must be 1024000 KB or greater | T1070.001 — Indicator Removal: Clear Windows Event Logs |
| WN11-AU-000510 | System event log size must be 32768 KB or greater | T1070.001 — Indicator Removal: Clear Windows Event Logs |

## Why This Matters

All 3 STIGs address Windows event log retention. If log sizes are too small, they overwrite themselves quickly and SOC analysts lose evidence during incident response. The Security log is the most critical — it captures every login attempt, privilege use, and account change. The default 20 MB fills up in hours on a busy system. Attackers rely on small log sizes to naturally erase their tracks without actively clearing logs.

## Registry Paths

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application → MaxSize = 32768
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security   → MaxSize = 1024000
HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System      → MaxSize = 32768
```

> These are the GPO registry paths that Tenable checks for compliance — not the direct event log configuration paths.

## Manual Remediation

1. Press `Windows + R`, type `regedit`, press Enter. Click Yes on UAC prompt.
2. Navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows`

![Registry before — no EventLog key](../evidence/group1/01-registry-before.png)

3. Right-click `Windows` → New → Key → name it `EventLog`. Create subkeys `Application`, `Security`, and `System` under it.

![Creating DWORD under EventLog\System](../evidence/group1/02-registry-create-dword.png)

4. Inside each subkey, create a DWORD (32-bit) value named `MaxSize`.

![Right-click MaxSize to modify](../evidence/group1/03-registry-modify-maxsize.png)

5. Set the decimal values: Application = 32768, Security = 1024000, System = 32768.

![Setting MaxSize to 32768 decimal](../evidence/group1/04-registry-set-32768.png)

## Tenable Scan — Before Fix (Failed)

![WN11-AU-000500 and 000505 Failed](../evidence/group1/05-tenable-000500-000505-failed.png)

![WN11-AU-000510 Failed](../evidence/group1/06-tenable-000510-failed.png)

## Tenable Scan — After Manual Fix (Passed)

![WN11-AU-000500 and 000505 Passed](../evidence/group1/07-tenable-000500-000505-passed.png)

![WN11-AU-000510 Passed](../evidence/group1/08-tenable-000510-passed.png)

## PowerShell Remediation

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\scripts\WN11-AU-EventLog-Sizes.ps1
gpupdate /force
```

![PowerShell script execution with output](../evidence/group1/09-powershell-script-run.png)

## Verification

```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application /v MaxSize
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System /v MaxSize
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security /v MaxSize
```

![reg query verification — all 3 values confirmed](../evidence/group1/10-reg-query-verification.png)

## Tenable Scan — After PowerShell Fix (Passed)

![WN11-AU-000500 and 000505 Passed after PS script](../evidence/group1/11-tenable-000500-000505-passed-ps.png)

![WN11-AU-000510 Passed after PS script](../evidence/group1/12-tenable-000510-passed-ps.png)

## Rollback

Set all 3 `MaxSize` values back to `20480` in Registry Editor, then run `gpupdate /force`.
