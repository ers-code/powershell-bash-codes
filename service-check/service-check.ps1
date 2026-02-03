<#
Synopsis:
Retrieves all Windows services and displays (1) currently running services and (2) any services configured to Automatic start that are not running. Helps detect service drift, failed services after patches/reboots, and misconfigurations.

Use cases: operational readiness checks, post-restart verification, incident triage.

Prepared by: Erik Rey Santos
Version: 1.0

#>
[CmdletBinding()]
param(
  [string]$ComputerName = $env:COMPUTERNAME
)

$ErrorActionPreference = "Stop"

$svcs = Get-Service -ComputerName $ComputerName

"=== Running Services ($ComputerName) ==="
$svcs | Where-Object Status -eq "Running" |
  Sort-Object DisplayName |
  Select-Object Name, DisplayName, Status, StartType |
  Format-Table -AutoSize

"`n=== ALERT: Auto-start but NOT Running ($ComputerName) ==="
$svcs | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" } |
  Sort-Object DisplayName |
  Select-Object Name, DisplayName, Status, StartType |
  Format-Table -AutoSize
