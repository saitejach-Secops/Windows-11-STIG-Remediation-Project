<#
.SYNOPSIS
  Sets minimum event log sizes for DISA Windows 11 STIG v2r2 using the Group Policy registry path:
    WN11-AU-000500 (Application >= 32768 KB)
    WN11-AU-000505 (Security >= 1024000 KB)
    WN11-AU-000510 (System >= 32768 KB)

.DESCRIPTION
  Creates and configures the "MaxSize" DWORD under:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\<LogName>
  to meet STIG minimum sizes:
    - Application : 32768 KB
    - Security    : 1024000 KB
    - System      : 32768 KB

.NOTES
  Author          : Sai Teja Ch
  LinkedIn        : https://linkedin.com/in/csai
  GitHub          : https://github.com/saitejach-Secops
  Date Created    : 03-28-2026
  Last Modified   : 03-28-2026
  CVEs            : N/A
  Plugin IDs      : N/A
  STIG-ID         : WN11-AU-000500, WN11-AU-000505, WN11-AU-000510

.TESTED ON
  Date(s) Tested  : 03-28-2026
  Tested By       : sai teja ch
  Systems Tested  : Windows 11 (Version 10.0.22621)

.USAGE
  Example usage:
    PS C:\> .\WN11-AU-EventLog-Sizes.ps1
    (Run as Administrator, then do "gpupdate /force" if needed)
#>

# Define the log names and their required sizes:
$LogRequirements = @(
    @{ Name = 'Application'; Size = 32768   }, # WN11-AU-000500
    @{ Name = 'Security';    Size = 1024000 }, # WN11-AU-000505
    @{ Name = 'System';      Size = 32768   }  # WN11-AU-000510
)

# Base registry path for GPO-based settings:
$BasePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog'

foreach ($log in $LogRequirements) {
    $logPath  = Join-Path $BasePath $log.Name
    $logSize  = $log.Size
    $propName = 'MaxSize'

    Write-Host "Processing $($log.Name) log under $logPath..."

    try {
        # Ensure the subkey exists; Create it if not present.
        if (!(Test-Path $logPath)) {
            New-Item -Path $logPath -Force | Out-Null
            Write-Host "  Created subkey for $($log.Name)."
        }

        # Set or update the MaxSize property.
        New-ItemProperty -Path $logPath `
                         -Name $propName `
                         -PropertyType DWORD `
                         -Value $logSize `
                         -Force | Out-Null

        Write-Host "  Set 'MaxSize' to $logSize KB for $($log.Name)."
    }
    catch {
        Write-Error "  Failed to configure $($log.Name) log size. Error: $_"
    }
}

Write-Host "`nAll desired event log sizes have been set under Policies. If needed, run 'gpupdate /force' or reboot to ensure policy is applied."
