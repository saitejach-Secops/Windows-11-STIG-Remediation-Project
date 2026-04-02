# Group 4 — Process Auditing

**STIG:** WN11-AU-000050
**Script:** [`WN11-AU-ProcessCreation.ps1`](../scripts/WN11-AU-ProcessCreation.ps1)

---

## Vulnerability

| STIG ID | Title | MITRE ATT&CK |
|---------|-------|--------------|
| WN11-AU-000050 | Audit Detailed Tracking — Process Creation must be enabled | T1055 — Process Injection |

## Why This Matters

Every process that starts on the system generates Event ID 4688 when this audit policy is enabled. SOC analysts use this to reconstruct the full attack kill chain. When malware executes, it spawns child processes — Word spawning PowerShell, PowerShell spawning cmd, cmd running Mimikatz. Each step is a 4688 event. Without this setting, the entire process chain is invisible during incident response and threat hunting.

## Tenable Scan — Before Fix (Failed)

![WN11-AU-000050 Failed — Process Creation audit not configured](../evidence/group4/01-tenable-000050-failed.png)

## Manual Remediation

1. Press `Windows + R`, type `secpol.msc`, press Enter. Click Yes on UAC prompt.
2. Navigate to `Security Settings` → `Advanced Audit Policy Configuration` → `System Audit Policies` → `Detailed Tracking`
3. Double-click `Audit Process Creation`
4. Check **Success** and check **Failure**
5. Click Apply → OK

![Local Security Policy — Audit Process Creation with Success and Failure enabled](../evidence/group4/02-secpol-audit-process-creation.png)

Run `gpupdate /force`.

## PowerShell Remediation

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\scripts\WN11-AU-ProcessCreation.ps1
gpupdate /force
```

![PowerShell script — Audit Policy set successfully, Status: PASS](../evidence/group4/03-powershell-script-run.png)

## Tenable Scan — After Fix (Passed)

![WN11-AU-000050 Passed](../evidence/group4/04-tenable-000050-passed.png)

## Verification

```powershell
auditpol /get /subcategory:"Process Creation"
```

Expected: `Process Creation    Success and Failure`

## Rollback

Open `secpol.msc`, navigate to `Advanced Audit Policy Configuration` → `Detailed Tracking`, double-click `Audit Process Creation`, uncheck both Success and Failure, Apply → OK, then `gpupdate /force`.
