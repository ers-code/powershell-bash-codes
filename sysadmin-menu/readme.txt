============================================================
SYSADMIN TOOLKIT MENU
============================================================

Prepared by : Erik Rey Santos
Script Name : SysAdminToolkit-Menu.ps1
Platform    : Windows Server / Windows 10+
PowerShell  : 5.1 or later
Log Path    : D:\script\logs
============================================================


OVERVIEW
------------------------------------------------------------
The SysAdmin Toolkit Menu is a centralized, menu-driven
PowerShell utility designed for system administrators to
perform common operational, security, and health checks
from a single script.

It is suitable for:
- Daily server health checks
- Pre- and post-maintenance validation
- Patch readiness verification
- Incident triage
- Security and compliance audits


LOGGING
------------------------------------------------------------
All output is logged automatically.

Log file naming format:
sysadmin-toolkit-<hostname>-<timestamp>.log

Example:
D:\script\logs\sysadmin-toolkit-SRV01-20260203-113522.log

Logging behavior:
- Timestamped entries
- Console output is written to log
- One log file per execution
- Safe for pre/post comparison


SCRIPT LOCATION & REQUIREMENTS
------------------------------------------------------------
Recommended location:
D:\Powershell\ServerCheck\SysAdminToolkit-Menu.ps1

Requirements:
- Run as Administrator (recommended)
- PowerShell Execution Policy must allow script execution
  (use Process scope if needed)

Example:
Set-ExecutionPolicy Bypass -Scope Process -Force


MENU OPTIONS & FUNCTIONS
------------------------------------------------------------

1. Logging Wrapper
   - Initializes logging
   - Captures hostname, user, OS version, last boot time

2. Server Baseline & Drift Detection
   - Installed Windows roles/features (Server OS)
   - Services status and startup type
   - Local Administrators group
   - Firewall profile configuration

3. Pre/Post Patch Capture (Baseline)
   - Running services
   - Automatic services not running
   - Listening TCP ports
   - CPU and memory snapshot

4. Critical Services Watchdog
   - Monitors critical services
   - Attempts restart if stopped
   - Logs recovery attempts

5. Unauthorized Local Admin Detector
   - Audits local Administrators group
   - Compares against approved list
   - Flags unauthorized accounts

6. Scheduled Task Auditor
   - Detects disabled tasks
   - Detects failed last run
   - Displays Run-As accounts

7. Resource Spike Monitor (Snapshot)
   - CPU utilization
   - Memory utilization
   - Top 10 CPU-consuming processes

8. SMB & Network Security Audit
   - SMBv1 / SMBv2 status
   - SMB signing configuration
   - Enumerates file shares

9. Windows Firewall Rule Auditor
   - Firewall profile status
   - Inbound allow rules review

10. Disk Cleanup & Growth Forecast (Inventory)
    - Disk usage by drive
    - Free space and percentage
    - No automatic cleanup (safe by design)

11. Domain Trust & Secure Channel Validator
    - Domain membership status
    - Secure channel validation
    - Time source verification

12. RDP Access & Security Audit
    - Network Level Authentication (NLA) status
    - Remote Desktop Users group members
    - Recent failed logon attempts (Event ID 4625)

13. Windows Update Health Tool
    - Pending reboot detection
    - Last installed hotfixes

14. Event Log Smart Triage
    - Recent System Error events
    - Focused on critical providers

15. Application Dependency Mapper
    - Maps listening ports to processes
    - Useful for change impact analysis

16. Certificate Expiry Scanner
    - Scans LocalMachine certificate store
    - Flags certificates expiring within 45 days

A. Run ALL Checks (Recommended)
   - Executes all checks in logical order
   - Best option for maintenance windows

Q. Quit
   - Exits the script safely


USAGE RECOMMENDATIONS
------------------------------------------------------------
Daily Operations:
- Run option A or 1, 2, 7, 10, 14

Pre-Maintenance / Restart:
- Run option A
- Save log as "PRE"

Post-Maintenance / Restart:
- Run option A again
- Compare logs with PRE run

Security Audits:
- Focus on options 5, 8, 9, 12, 16


NOTES & SAFETY
------------------------------------------------------------
- Script is READ-ONLY by default (except service restarts
  in the Watchdog function)
- No destructive actions are performed automatically
- Disk cleanup is intentionally informational only
- Some functions require Administrator privileges
- Security log access may be restricted by policy


CUSTOMIZATION
------------------------------------------------------------
You can safely customize:
- Critical services list (Watchdog)
- Approved local admin accounts
- Certificate expiry threshold
- Log root path

All customization variables are clearly defined inside
each function.


SUPPORT / MAINTENANCE
------------------------------------------------------------
This script is modular and extensible.
Additional checks can be added following the same
function + menu pattern.

For troubleshooting:
- Review the generated log file
- Look for WARN / ERROR entries
- Validate required privileges


END OF FILE
============================================================

