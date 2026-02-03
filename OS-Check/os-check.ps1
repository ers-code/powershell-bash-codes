<#

.SYNOPSIS
    OS Pre/Post Restart Validation Script

.DESCRIPTION
    This script performs comprehensive operating system health checks
    before and after a server restart. It is designed for use during
    maintenance windows, OS upgrades, patching activities, or controlled
    reboots.

    The script supports two modes:
      - PRE  : Captures the server state BEFORE a restart
      - POST : Validates that the server restarted successfully and that
               critical services and system components are healthy

    Key validations include:
      - System and OS information
      - Uptime and last boot time verification
      - Logged-in user sessions
      - Pending reboot indicators
      - Full inventory of running services (formatted table)
      - Critical service validation
      - Disk space utilization
      - CPU and memory usage
      - Top CPU-consuming processes
      - Network connectivity (gateway and external reachability)

    All output is written to a timestamped log file for audit and
    troubleshooting purposes.

.PREPARED BY
    Erik Rey Santos

.LOG LOCATION
    C:\Temp\PSScript

.LOG NAMING FORMAT
    os-check-<hostname>-<timestamp>.log

.PARAMETER Mode
    PRE  - Run checks prior to restarting the server
    POST - Run checks after the server has restarted

.EXAMPLE
    Pre-restart check:
        .\os-check.ps1 -Mode PRE

    Post-restart check:
        .\os-check.ps1 -Mode POST

.NOTES
    - Compatible with Windows Server 2016 / 2019 / 2022 / 2025
    - Can be executed on domain-joined or standalone servers
    - Requires administrative privileges
#>

param(
    [ValidateSet("PRE","POST")]
    [string]$Mode = "PRE"
)

$PreparedBy = "Erik Rey Santos"
$LogDir = "C:\Temp\PSScript"

if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$Hostname  = $env:COMPUTERNAME
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile   = Join-Path $LogDir ("os-check-{0}-{1}.log" -f $Hostname, $Timestamp)

function Write-Log {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return }

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | $Message" | Tee-Object -FilePath $LogFile -Append
}

function Write-Section {
    param([Parameter(Mandatory=$true)][string]$Title)
    Write-Log ("=" * 100)
    Write-Log $Title
    Write-Log ("=" * 100)
}

# --- Script execution continues unchanged below ---

