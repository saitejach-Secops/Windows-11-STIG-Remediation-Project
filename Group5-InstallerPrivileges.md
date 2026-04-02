# Group 5 — Installer Privileges

**STIG:** WN11-CC-000315
**Script:** [`WN11-CC-InstallerElevated.ps1`](../scripts/WN11-CC-InstallerElevated.ps1)

---

## Vulnerability

| STIG ID | Title | MITRE ATT&CK |
|---------|-------|--------------|
| WN11-CC-000315 | Windows Installer Always install with elevated privileges must be disabled | T1548.002 — Abuse Elevation Control Mechanism |

## Why This Matters

When `AlwaysInstallElevated` is enabled, any user can run an MSI installer as SYSTEM — the highest privilege level on Windows. Attackers create malicious MSI files that add admin accounts or install backdoors. Both the machine policy path (HKLM) and user policy path (HKCU) must be set to `0`. If either one is missing or set to `1`, the privilege escalation path still exists and the STIG fails.

## Registry Paths

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer → AlwaysInstallElevated = 0
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer → AlwaysInstallElevated = 0
```

> Both paths must be set. If either is missing or set to 1, the STIG fails.

## Tenable Scan — Before Fix (Failed)

![WN11-CC-000315 Failed — Always install with elevated privileges](../evidence/group5/01-tenable-000315-failed.png)

## Manual Remediation

1. Press `Windows + R`, type `regedit`, press Enter. Click Yes on UAC prompt.

**Machine policy (HKLM):**
- Navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows`
- Right-click `Windows` → New → Key → `Installer` (skip if it exists)
- New → DWORD (32-bit) → `AlwaysInstallElevated` → Decimal → `0` → OK

**User policy (HKCU):**
- Navigate to `HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows`
- Right-click `Windows` → New → Key → `Installer` (skip if it exists)
- New → DWORD (32-bit) → `AlwaysInstallElevated` → Decimal → `0` → OK

Close Registry Editor. Run `gpupdate /force`.

## PowerShell Remediation

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\scripts\WN11-CC-InstallerElevated.ps1
gpupdate /force
```

![PowerShell script — HKLM and HKCU both set to 0, Status: PASS](../evidence/group5/02-powershell-script-run.png)

## Tenable Scan — After Fix (Passed)

![WN11-CC-000315 Passed](../evidence/group5/03-tenable-000315-passed.png)

## Verification

```powershell
$hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated
$hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated
Write-Host "HKLM: $hklm"
Write-Host "HKCU: $hkcu"
```

Expected: both return `0`

## Rollback

Set both `AlwaysInstallElevated` values to `1` in Registry Editor, then `gpupdate /force`.
