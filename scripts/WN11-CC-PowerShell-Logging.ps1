<#
.SYNOPSIS
  Enables PowerShell Script Block Logging, Transcription Logging, and Command Line
  Process Creation auditing for DISA Windows 11 STIG v2r2:
    WN11-CC-000326 (PowerShell Script Block Logging)
    WN11-CC-000327 (PowerShell Transcription Logging)
    WN11-CC-000066 (Command Line in Process Creation Events)

.DESCRIPTION
  Creates and configures the following registry values:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
      EnableScriptBlockLogging = 1

    HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
      EnableTranscripting = 1

    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
      ProcessCreationIncludeCmdLine_Enabled = 1

.NOTES
  Author          : sai teja ch
  LinkedIn        : https://linkedin.com/in/csai
  GitHub          : https://github.com/saitejach-Secops
  Date Created    : 03-28-2026
  Last Modified   : 03-28-2026
  CVEs            : N/A
  Plugin IDs      : N/A
  STIG-ID         : WN11-CC-000326, WN11-CC-000327, WN11-CC-000066

.TESTED ON
  Date(s) Tested  : 03-28-2026
  Tested By       : sai teja ch
  Systems Tested  : Windows 11 (Version 10.0.22621)

.USAGE
  Example usage:
    PS C:\> .\WN11-CC-PowerShell-Logging.ps1
    (Run as Administrator, then do "gpupdate /force" if needed)
#>

# Define STIG registry settings:
$STIGSettings = @(
    @{
        STIGID   = 'WN11-CC-000326'
        Path     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        Name     = 'EnableScriptBlockLogging'
        Value    = 1
        Type     = 'DWord'
        Description = 'PowerShell Script Block Logging'
    },
    @{
        STIGID   = 'WN11-CC-000327'
        Path     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Name     = 'EnableTranscripting'
        Value    = 1
        Type     = 'DWord'
        Description = 'PowerShell Transcription Logging'
    },
    @{
        STIGID   = 'WN11-CC-000066'
        Path     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        Name     = 'ProcessCreationIncludeCmdLine_Enabled'
        Value    = 1
        Type     = 'DWord'
        Description = 'Command Line in Process Creation Events'
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

Write-Host "`nAll PowerShell logging STIG settings have been applied. Run 'gpupdate /force' or reboot if needed." -ForegroundColor Green
