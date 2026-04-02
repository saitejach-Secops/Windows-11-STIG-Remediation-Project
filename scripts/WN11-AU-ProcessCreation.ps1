<#
.SYNOPSIS
  Enables Audit Detailed Tracking - Process Creation for
  DISA Windows 11 STIG v2r2:
    WN11-AU-000050 (Audit Detailed Tracking - Process Creation
    must be configured to Success and Failure)

.DESCRIPTION
  Configures the Advanced Audit Policy for Process Creation
  using auditpol.exe with GUID to ensure compatibility with
  Windows 11. Enables both Success and Failure auditing under
  Detailed Tracking subcategory.

  This ensures Event ID 4688 is generated for every process
  creation event - critical for threat hunting and SOC
  incident response.

.NOTES
  Author          : Your Name
  LinkedIn        : https://linkedin.com/in/csai
  GitHub          : https://github.com/saitejach-Secops
  Date Created    : 03-28-2026
  Last Modified   : 03-28-2026
  CVEs            : N/A
  Plugin IDs      : N/A
  STIG-ID         : WN11-AU-000050

.TESTED ON
  Date(s) Tested  : 03-28-2026
  Tested By       : sai teja ch
  Systems Tested  : Windows 11 (Version 10.0.22621)

.USAGE
  Example usage:
    PS C:\> .\WN11-AU-ProcessCreation.ps1
    (Run as Administrator)
#>

Write-Host "Processing WN11-AU-000050 - Audit Process Creation..." -ForegroundColor Cyan

try {
    # Method 1 - Using GUID (most reliable on Windows 11)
    Write-Host "  Applying via GUID..."
    auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

    # Method 2 - Using subcategory name as fallback
    Write-Host "  Applying via subcategory name..."
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null

    Write-Host "  Audit Policy set successfully." -ForegroundColor Green
}
catch {
    Write-Error "  Error applying audit policy: $_"
}

# Verify the setting was applied correctly
Write-Host "`nVerifying WN11-AU-000050..."

$verify = auditpol /get /subcategory:"Process Creation"

Write-Host $verify

if ($verify -match "Success and Failure") {
    Write-Host "`nWN11-AU-000050 - Status: PASS" -ForegroundColor Green
} elseif ($verify -match "Success") {
    Write-Host "`nWN11-AU-000050 - Status: PARTIAL (Success only - Failure not enabled)" -ForegroundColor Yellow
} else {
    Write-Host "`nWN11-AU-000050 - Status: FAIL" -ForegroundColor Red
}
