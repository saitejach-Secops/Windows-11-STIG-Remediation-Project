<#
.SYNOPSIS
  Disables Windows Installer Always Install with Elevated Privileges
  for DISA Windows 11 STIG v2r2:
    WN11-CC-000315 (The Windows Installer feature 'Always install
    with elevated privileges' must be disabled)

.DESCRIPTION
  Configures the following registry values to 0 under both
  Machine and User policy paths:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer
      AlwaysInstallElevated = 0

    HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer
      AlwaysInstallElevated = 0

  Both paths must be set to prevent privilege escalation
  via malicious MSI installer files.

.NOTES
  Author          : sai teja ch
  LinkedIn        : https://linkedin.com/in/csai
  GitHub          : https://github.com/saitejach-Secops
  Date Created    : 03-29-2026
  Last Modified   : 03-29-2026
  CVEs            : N/A
  Plugin IDs      : N/A
  STIG-ID         : WN11-CC-000315

.TESTED ON
  Date(s) Tested  : 03-29-2026
  Tested By       : sai teja ch
  Systems Tested  : Windows 11 (Version 10.0.22621)

.USAGE
  Example usage:
    PS C:\> .\WN11-CC-InstallerElevated.ps1
    (Run as Administrator)
#>

# Define both registry paths required for this STIG:
$STIGSettings = @(
    @{
        STIGID      = 'WN11-CC-000315'
        Path        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
        Name        = 'AlwaysInstallElevated'
        Value       = 0
        Type        = 'DWord'
        Description = 'Machine Policy - Always Install Elevated Disabled'
    },
    @{
        STIGID      = 'WN11-CC-000315'
        Path        = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'
        Name        = 'AlwaysInstallElevated'
        Value       = 0
        Type        = 'DWord'
        Description = 'User Policy - Always Install Elevated Disabled'
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

# Verify both paths
Write-Host "`nVerifying WN11-CC-000315..." -ForegroundColor Cyan

$hklm = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
$hkcu = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated

Write-Host "  HKLM AlwaysInstallElevated: $hklm"
Write-Host "  HKCU AlwaysInstallElevated: $hkcu"

if ($hklm -eq 0 -and $hkcu -eq 0) {
    Write-Host "`nWN11-CC-000315 - Status: PASS" -ForegroundColor Green
} else {
    Write-Host "`nWN11-CC-000315 - Status: FAIL" -ForegroundColor Red
}

Write-Host "`nRemediation complete. Run 'gpupdate /force' if needed." -ForegroundColor Green
