============================================================
OS HEALTH CHECK MENU SCRIPT
============================================================

Prepared by : Erik Rey Santos
Version     : 1.0
Last Update : 2026-02-03

------------------------------------------------------------
DESCRIPTION
------------------------------------------------------------
This PowerShell script provides a centralized, menu-driven
OS health check utility designed for server operations.

It is intended for:
- Pre-restart checks
- Post-restart validation
- Routine server health audits
- Incident triage and evidence collection

All outputs are automatically logged for traceability and
comparison.

------------------------------------------------------------
FEATURES
------------------------------------------------------------
The script includes the following checks:

1. Logging Wrapper
   - Initializes logging
   - Captures hostname, OS, user, and timestamp

2. Health Snapshot
   - CPU utilization
   - Memory utilization
   - Last boot time

3. Services Audit
   - Lists all running services
   - Includes service name, status, and startup type

5. Disk Alert
   - Displays disk usage for all local drives
   - Shows total size, free space, and free percentage

6. Patch Check
   - Retrieves recently installed Windows updates

8. Open Ports
   - Lists all listening TCP ports
   - Includes owning process ID

9. Event Log Triage
   - Extracts recent System-level error events

A. Run ALL Checks
   - Executes all health checks in sequence
   - Recommended for pre/post reboot validation

------------------------------------------------------------
LOGGING
------------------------------------------------------------
Log Directory:
D:\script\logs\

Log Naming Format:
os-check-<hostname>-<timestamp>.log

Example:
os-check-SRV-FILE01-20260203-101530.log

All script output is written both to the console and to the
log file for audit and troubleshooting purposes.

------------------------------------------------------------
REQUIREMENTS
------------------------------------------------------------
- Windows Server 2016 or later
- PowerShell 5.1 or newer
- Local Administrator privileges
- Access to D:\script\logs\ directory

------------------------------------------------------------
USAGE
------------------------------------------------------------
1. Copy the script and README.txt to the server
2. Run PowerShell as Administrator
3. Execute the script:

   .\OS-HealthCheck-Menu.ps1

4. Select the desired menu option
5. Review the generated log file

------------------------------------------------------------
RECOMMENDED WORKFLOW
------------------------------------------------------------

PRE-RESTART:
- Run the script
- Select option A (Run ALL Checks)
- Save the generated log

POST-RESTART:
- Run the script again
- Select option A (Run ALL Checks)
- Compare logs to validate system stability

------------------------------------------------------------
LIMITATIONS
------------------------------------------------------------
- Open Ports check displays TCP listeners only
- Event log triage focuses on recent System errors
- Script does not modify system configuration

------------------------------------------------------------
DISCLAIMER
------------------------------------------------------------
This script is provided as-is.
Always test in a non-production environment before
deployment in production systems.

------------------------------------------------------------
END OF FILE
------------------------------------------------------------

