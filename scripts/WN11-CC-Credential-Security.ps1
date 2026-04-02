<#
.SYNOPSIS
  Disables WDigest Authentication and enforces NTLMv2 only for
  DISA Windows 11 STIG v2r2:
    WN11-CC-000038 (WDigest Authentication must be disabled)
    WN11-SO-000205 (LanMan authentication level must be NTLMv2 only)

.DESCRIPTION
  Configures the following registry values:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDigest
      UseLogonCredential = 0

    HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
      LmCompatibilityLevel = 5

.NOTES
  Author          : sai teja ch
  LinkedIn        : https://linkedin.com/in/csai
  GitHub          : https://github.com/saitejach-Secops
  Date Created    : 03-28-2026
  Last Modified   : 03-28-2026
  CVEs            : N/A
  Plugin IDs      : N/A
  STIG-ID         : WN11-CC-000038, WN11-SO-000205

.TESTED ON
  Date(s) Tested  : 03-28-2026
  Tested By       : sai teja ch
  Systems Tested  : Windows 11 (Version 10.0.22621)

.USAGE
  Example usage:
    PS C:\> .\WN11-CC-Credential-Security.ps1
    (Run as Administrator, then restart if needed)
#>

# Define STIG registry settings:
$STIGSettings = @(
    @{
        STIGID      = 'WN11-CC-000038'
        Path        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDigest'
        Name        = 'UseLogonCredential'
        Value       = 0
        Type        = 'DWord'
        Description = 'WDigest Authentication Disabled'
    },
    @{
        STIGID      = 'WN11-SO-000205'
        Path        = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        Name        = 'LmCompatibilityLevel'
        Value       = 5
        Type        = 'DWord'
        Description = 'LanMan Authentication NTLMv2 Only'
    }
)

foreach ($stig in $STIGSettings) {
    Write-Host "Processing $($stig.STIGID) - $($stig.Description)..."

    try {
        # Ensure the registry key exists; create it if not present.
        if (!(Test-Path $stig.Path)) {
            New-Item -Path $stig.Path -Force | Out-Null
            Write-Host "  Created registry key for $($stig.Description)."
        }

        # Set or update the registry value.
        New-ItemProperty -Path $stig.Path `
                         -Name $stig.Name `
                         -PropertyType $stig.Type `
                         -Value $stig.Value `
                         -Force | Out-Null

        Write-Host "  Set '$($stig.Name)' to $($stig.Value)." -ForegroundColor Green
    }
    catch {
        Write-Error "  Failed to configure $($stig.Description). Error: $_"
    }
}

Write-Host "`nCredential security STIG settings applied. Restart the system for WDigest changes to take full effect." -ForegroundColor Green
