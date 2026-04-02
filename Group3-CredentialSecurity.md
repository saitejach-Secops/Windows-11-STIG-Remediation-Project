# Group 3 — Credential Security

**STIGs:** WN11-CC-000038 · WN11-SO-000205
**Script:** [`WN11-CC-Credential-Security.ps1`](../scripts/WN11-CC-Credential-Security.ps1)

---

## Vulnerability

| STIG ID | Title | MITRE ATT&CK |
|---------|-------|--------------|
| WN11-CC-000038 | WDigest Authentication must be disabled | T1003.001 — OS Credential Dumping: LSASS Memory |
| WN11-SO-000205 | LanMan authentication level must be NTLMv2 only | T1557.001 — LLMNR/NBT-NS Poisoning and Relay |

## Why This Matters

These 2 STIGs directly prevent credential theft attacks.

- **WDigest** stores plaintext passwords in LSASS memory — disabling it means credential dumping tools like Mimikatz find nothing useful
- **Forcing NTLMv2 only** prevents relay attacks where an attacker captures an authentication response and replays it to gain unauthorized access to other systems on the network

## Registry Paths

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\WDigest → UseLogonCredential = 0
HKLM\SYSTEM\CurrentControlSet\Control\Lsa        → LmCompatibilityLevel = 5
```

### LmCompatibilityLevel Values

| Value | Meaning |
|-------|---------|
| 0 | Send LM and NTLM (most insecure) |
| 1 | Send LM and NTLM |
| 2 | Send NTLM only |
| 3 | Send NTLMv2 only |
| 4 | Send NTLMv2, refuse LM |
| **5** | **Send NTLMv2, refuse LM and NTLM (STIG required)** |

## Tenable Scan — Before Fix (Failed)

![WN11-CC-000038 Failed — WDigest](../evidence/group3/01-tenable-000038-failed.png)

![WN11-SO-000205 Failed — NTLMv2](../evidence/group3/02-tenable-SO000205-failed.png)

### Detailed Failure View

![000038 Failed — Output: NULL, Policy Value: 0](../evidence/group3/04-tenable-000038-failed-detail.png)

## Manual Remediation

1. Press `Windows + R`, type `regedit`, press Enter. Click Yes on UAC prompt.

**WDigest:**
- Navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows`
- Right-click `Windows` → New → Key → `WDigest` (skip if it exists)
- New → DWORD (32-bit) → `UseLogonCredential` → Decimal → `0` → OK

**NTLMv2:**
- Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
- Create or modify DWORD `LmCompatibilityLevel` → Decimal → `5` → OK

Close Registry Editor. Run `gpupdate /force` and restart the VM — WDigest changes require a full restart.

## PowerShell Remediation

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\scripts\WN11-CC-Credential-Security.ps1
gpupdate /force
Restart-Computer -Force
```

![PowerShell script — UseLogonCredential=0, LmCompatibilityLevel=5](../evidence/group3/05-powershell-script-code.png)

![Script execution output](../evidence/group3/03-powershell-script-run.png)

## Tenable Scan — After Fix (Passed)

![WN11-CC-000038 Passed](../evidence/group3/06-tenable-000038-passed.png)

![WN11-SO-000205 Passed](../evidence/group3/07-tenable-SO000205-passed.png)

## Verification

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDigest" | Select UseLogonCredential
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select LmCompatibilityLevel
```

Expected: `0` and `5`

## Rollback

Set `UseLogonCredential` to `1` and `LmCompatibilityLevel` to `0` in Registry Editor. Run `gpupdate /force` and restart the VM.
