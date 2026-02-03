# =========================================================
# OS Health Check Menu Script
# Prepared by: Erik Rey Santos
# Description:
# Centralized pre/post-restart OS health check menu with logging
# =========================================================

# --- Global Variables ---
$Hostname  = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogRoot   = "D:\script\logs"
$LogFile   = "$LogRoot\os-check-$Hostname-$Timestamp.log"

if (!(Test-Path $LogRoot)) {
    New-Item -ItemType Directory -Path $LogRoot | Out-Null
}

function Write-Log {
    param ([string]$Message)
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Message"
    $entry | Tee-Object -FilePath $LogFile -Append
}

# ---------------- FUNCTIONS ----------------

function Logging-Wrapper {
    Write-Log "Logging initialized"
    Write-Log "Hostname: $Hostname"
    Write-Log "User: $env:USERNAME"
    Write-Log "OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"
}

function Health-Snapshot {
    Write-Log "===== HEALTH SNAPSHOT ====="
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
    $mem = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100,2)

    Write-Log "CPU Usage: $([math]::Round($cpu,2)) %"
    Write-Log "Memory Usage: $mem %"
    Write-Log "Last Boot Time: $($os.LastBootUpTime)"
}

function Services-Audit {
    Write-Log "===== SERVICES AUDIT ====="
    Get-Service | Where-Object {$_.Status -eq "Running"} |
    Sort-Object DisplayName |
    Select-Object DisplayName, Status, StartType |
    Format-Table -AutoSize | Out-String |
    ForEach-Object { Write-Log $_ }
}

function Disk-Alert {
    Write-Log "===== DISK UTILIZATION ====="
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
    Select-Object DeviceID,
        @{N="Free(GB)";E={[math]::Round($_.FreeSpace/1GB,2)}},
        @{N="Size(GB)";E={[math]::Round($_.Size/1GB,2)}},
        @{N="Free%";E={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}} |
    Format-Table -AutoSize | Out-String |
    ForEach-Object { Write-Log $_ }
}

function Patch-Check {
    Write-Log "===== PATCH CHECK ====="
    Get-HotFix | Sort-Object InstalledOn -Descending |
    Select-Object -First 5 |
    Format-Table -AutoSize | Out-String |
    ForEach-Object { Write-Log $_ }
}

function Open-Ports {
    Write-Log "===== OPEN PORTS ====="
    Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort |
    Format-Table -AutoSize | Out-String |
    ForEach-Object { Write-Log $_ }
}

function Event-Log-Triage {
    Write-Log "===== EVENT LOG TRIAGE ====="
    Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 10 |
    Select TimeCreated, Id, Message |
    Format-Table -Wrap -AutoSize | Out-String |
    ForEach-Object { Write-Log $_ }
}

function Run-All {
    Logging-Wrapper
    Health-Snapshot
    Services-Audit
    Disk-Alert
    Patch-Check
    Open-Ports
    Event-Log-Triage
}

# ---------------- MENU ----------------

do {
    Clear-Host
    Write-Host "====================================="
    Write-Host " OS HEALTH CHECK MENU - $Hostname"
    Write-Host "====================================="
    Write-Host "1. Logging Wrapper"
    Write-Host "2. Health Snapshot"
    Write-Host "3. Services Audit"
    Write-Host "4. Disk Alert"
    Write-Host "5. Patch Check"
    Write-Host "6. Open Ports"
    Write-Host "7. Event Log Triage"
    Write-Host "A. Run ALL Checks (Recommended)"
    Write-Host "Q. Quit"
    Write-Host "====================================="
    $choice = Read-Host "Select an option"

    switch ($choice.ToUpper()) {
        "1" { Logging-Wrapper }
        "2" { Health-Snapshot }
        "3" { Services-Audit }
        "4" { Disk-Alert }
        "5" { Patch-Check }
        "6" { Open-Ports }
        "7" { Event-Log-Triage }
        "A" { Run-All }
        "Q" { break }
        default { Write-Host "Invalid selection" }
    }

    if ($choice.ToUpper() -ne "Q") {
        Write-Host "`nOutput logged to:"
        Write-Host $LogFile -ForegroundColor Green
        Pause
    }

} while ($true)

