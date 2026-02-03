
# =========================================================
# SYSADMIN TOOLKIT MENU SCRIPT
# Prepared by: Erik Rey Santos
# Description:
# Centralized SysAdmin PowerShell toolkit menu with logging
# =========================================================

# --- Global Variables ---
$Hostname  = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogRoot   = "D:\script\logs"
$LogFile   = "$LogRoot\sysadmin-toolkit-$Hostname-$Timestamp.log"

if (!(Test-Path $LogRoot)) {
    New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
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
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        Write-Log "OS: $($os.Caption)"
        Write-Log "Last Boot Time: $($os.LastBootUpTime)"
    } catch {
        Write-Log "WARN: Unable to query OS via CIM. $($_.Exception.Message)"
    }
}

function Server-Baseline-DriftDetection {
    Write-Log "===== SERVER BASELINE & DRIFT DETECTION ====="

    # Installed Windows Features (Server)
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            Write-Log "-- Installed Windows Features (Installed=True) --"
            Get-WindowsFeature | Where-Object InstallState -eq "Installed" |
            Select-Object DisplayName, Name, InstallState |
            Sort-Object DisplayName |
            Format-Table -AutoSize | Out-String |
            ForEach-Object { Write-Log $_ }
        } else {
            Write-Log "INFO: Get-WindowsFeature not available (likely client OS). Skipping roles/features."
        }
    } catch {
        Write-Log "WARN: Feature inventory failed. $($_.Exception.Message)"
    }

    # Services StartType + Status
    try {
        Write-Log "-- Services (Name, Status, StartType) --"
        Get-Service |
        Sort-Object DisplayName |
        Select-Object DisplayName, Status, StartType |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "WARN: Services inventory failed. $($_.Exception.Message)"
    }

    # Local Administrators
    try {
        Write-Log "-- Local Administrators Group Members --"
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            Get-LocalGroupMember -Group "Administrators" |
            Select-Object Name, ObjectClass, PrincipalSource |
            Format-Table -AutoSize | Out-String |
            ForEach-Object { Write-Log $_ }
        } else {
            net localgroup administrators |
            ForEach-Object { Write-Log $_ }
        }
    } catch {
        Write-Log "WARN: Local admin enumeration failed. $($_.Exception.Message)"
    }

    # Firewall Profiles
    try {
        Write-Log "-- Firewall Profiles --"
        Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "INFO: Firewall profile query failed or cmdlet unavailable. $($_.Exception.Message)"
    }
}

function Patch-PrePost-Comparison {
    Write-Log "===== PRE/POST PATCH CAPTURE (BASELINE) ====="
    Write-Log "NOTE: This function captures a snapshot. Compare logs or export outputs to CSV/HTML if needed."

    # Services
    try {
        Write-Log "-- Services Snapshot (Running + Auto not running) --"
        $svc = Get-Service
        $autoNotRunning = $svc | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -ne "Running" }
        $running = $svc | Where-Object { $_.Status -eq "Running" }

        Write-Log "Running services count: $($running.Count)"
        Write-Log "Auto-start NOT running count: $($autoNotRunning.Count)"

        $autoNotRunning |
        Select-Object DisplayName, Status, StartType |
        Sort-Object DisplayName |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "WARN: Services snapshot failed. $($_.Exception.Message)"
    }

    # Ports
    try {
        Write-Log "-- Listening TCP Ports --"
        Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Sort-Object LocalPort |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "WARN: Port snapshot failed. $($_.Exception.Message)"
    }

    # CPU/Mem
    try {
        Write-Log "-- CPU/Memory Snapshot --"
        $os = Get-CimInstance Win32_OperatingSystem
        $cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
        $mem = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100,2)

        Write-Log "CPU Usage: $([math]::Round($cpu,2)) %"
        Write-Log "Memory Usage: $mem %"
    } catch {
        Write-Log "WARN: CPU/Mem snapshot failed. $($_.Exception.Message)"
    }
}

function Critical-Services-Watchdog {
    Write-Log "===== CRITICAL SERVICES WATCHDOG ====="

    # Customize this list for your environment
    $CriticalServices = @(
        "W32Time",
        "LanmanServer",
        "LanmanWorkstation",
        "Dnscache"
    )

    foreach ($svcName in $CriticalServices) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction Stop
            if ($svc.Status -ne "Running") {
                Write-Log "WARN: $svcName is $($svc.Status). Attempting restart..."
                Restart-Service -Name $svcName -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
                $svc2 = Get-Service -Name $svcName
                Write-Log "INFO: $svcName status after action: $($svc2.Status)"
            } else {
                Write-Log "INFO: $svcName is Running"
            }
        } catch {
            Write-Log "ERROR: Watchdog failed for $svcName. $($_.Exception.Message)"
        }
    }
}

function Unauthorized-LocalAdmin-Detector {
    Write-Log "===== UNAUTHORIZED LOCAL ADMIN DETECTOR ====="

    # Define approved admins (edit as needed)
    $Approved = @(
        "BUILTIN\Administrators",
        "NT AUTHORITY\SYSTEM"
        # Add your approved accounts/groups here:
        # "DOMAIN\Domain Admins",
        # "$Hostname\SomeLocalAdmin"
    )

    try {
        $members = @()

        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            $members = Get-LocalGroupMember -Group "Administrators" |
                Select-Object Name, ObjectClass, PrincipalSource
        } else {
            $raw = net localgroup administrators
            $lines = $raw | Where-Object { $_ -and $_ -notmatch "command completed successfully|Alias name|Comment|Members|---" }
            $members = $lines | ForEach-Object { [pscustomobject]@{ Name = $_.Trim(); ObjectClass = "Unknown"; PrincipalSource="Unknown" } }
        }

        Write-Log "-- Current Local Admin Members --"
        $members | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_ }

        $unauthorized = $members | Where-Object { $Approved -notcontains $_.Name }

        if ($unauthorized.Count -gt 0) {
            Write-Log "WARN: Unauthorized local admins detected:"
            $unauthorized | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_ }
        } else {
            Write-Log "INFO: No unauthorized local admins detected based on current Approved list."
        }
    } catch {
        Write-Log "ERROR: Local admin audit failed. $($_.Exception.Message)"
    }
}

function Scheduled-Task-Auditor {
    Write-Log "===== SCHEDULED TASK AUDITOR ====="

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        $taskInfo = foreach ($t in $tasks) {
            $info = $null
            try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch {}
            [pscustomobject]@{
                TaskName       = $t.TaskName
                TaskPath       = $t.TaskPath
                State          = $t.State
                LastRunTime    = $info.LastRunTime
                LastTaskResult = $info.LastTaskResult
                NextRunTime    = $info.NextRunTime
                Author         = $t.Author
                RunAsUser      = $t.Principal.UserId
            }
        }

        $problem = $taskInfo | Where-Object { $_.State -eq "Disabled" -or ($_.LastTaskResult -ne $null -and $_.LastTaskResult -ne 0) }

        Write-Log "-- Problem Tasks (Disabled / LastResult != 0) --"
        $problem |
        Sort-Object TaskPath, TaskName |
        Select-Object TaskPath, TaskName, State, LastRunTime, LastTaskResult, RunAsUser |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }

        Write-Log "Total tasks: $($taskInfo.Count) | Problem tasks: $($problem.Count)"
    } catch {
        Write-Log "ERROR: Scheduled task audit failed. $($_.Exception.Message)"
    }
}

function Resource-Spike-Monitor {
    Write-Log "===== RESOURCE SPIKE MONITOR (SNAPSHOT) ====="

    try {
        $cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
        Write-Log "CPU Usage: $([math]::Round($cpu,2)) %"
    } catch {
        Write-Log "WARN: CPU counter failed. $($_.Exception.Message)"
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $memUsedPct = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100,2)
        Write-Log "Memory Usage: $memUsedPct %"
    } catch {
        Write-Log "WARN: Memory CIM query failed. $($_.Exception.Message)"
    }

    try {
        Write-Log "-- Top 10 Processes by CPU --"
        Get-Process |
        Sort-Object CPU -Descending |
        Select-Object -First 10 Name, Id, CPU, WS |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "WARN: Process listing failed. $($_.Exception.Message)"
    }
}

function SMB-Network-Security-Audit {
    Write-Log "===== SMB & NETWORK SECURITY AUDIT ====="

    try {
        Write-Log "-- SMB Server Configuration --"
        $smb = Get-SmbServerConfiguration
        $out = [pscustomobject]@{
            EnableSMB1Protocol        = $smb.EnableSMB1Protocol
            EnableSMB2Protocol        = $smb.EnableSMB2Protocol
            RequireSecuritySignature  = $smb.RequireSecuritySignature
            EnableSecuritySignature   = $smb.EnableSecuritySignature
        }
        $out | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "INFO: SMB server config not accessible. $($_.Exception.Message)"
    }

    try {
        Write-Log "-- SMB Shares --"
        Get-SmbShare |
        Select-Object Name, Path, Description, EncryptData, ContinuouslyAvailable |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "INFO: Share enumeration failed or cmdlet unavailable. $($_.Exception.Message)"
    }
}

function Windows-Firewall-Rule-Auditor {
    Write-Log "===== WINDOWS FIREWALL RULE AUDIT ====="

    try {
        Write-Log "-- Firewall Profiles --"
        Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "INFO: Firewall profile query failed. $($_.Exception.Message)"
    }

    try {
        Write-Log "-- Inbound Allow Rules (Enabled) - Quick Risk Review --"
        Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
        Select-Object DisplayName, Profile, Direction, Action |
        Sort-Object DisplayName |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "INFO: Firewall rule query failed. $($_.Exception.Message)"
    }
}

function Disk-Cleanup-GrowthForecast {
    Write-Log "===== DISK CLEANUP & GROWTH FORECAST (INVENTORY) ====="

    try {
        Write-Log "-- Disk Utilization --"
        Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
        Select-Object DeviceID,
            @{N="Free(GB)";E={[math]::Round($_.FreeSpace/1GB,2)}},
            @{N="Size(GB)";E={[math]::Round($_.Size/1GB,2)}},
            @{N="Free%";E={[math]::Round(($_.FreeSpace/$_.Size)*100,2)}} |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "ERROR: Disk query failed. $($_.Exception.Message)"
    }

    Write-Log "INFO: Cleanup actions are intentionally NOT automatic in this menu."
}

function Domain-Trust-SecureChannel-Validator {
    Write-Log "===== DOMAIN TRUST & SECURE CHANNEL VALIDATOR ====="

    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        Write-Log "Domain: $($cs.Domain)"
        Write-Log "PartOfDomain: $($cs.PartOfDomain)"
    } catch {
        Write-Log "WARN: Unable to determine domain membership. $($_.Exception.Message)"
    }

    try {
        $test = Test-ComputerSecureChannel -Verbose -ErrorAction Stop
        Write-Log "Secure Channel OK: $test"
    } catch {
        Write-Log "WARN: Secure channel test failed. $($_.Exception.Message)"
        Write-Log "TIP: Repair with: Test-ComputerSecureChannel -Repair -Credential (Get-Credential)"
    }

    try {
        Write-Log "-- Time Source --"
        w32tm /query /status | ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "INFO: w32tm query failed. $($_.Exception.Message)"
    }
}

function RDP-Access-Security-Audit {
    Write-Log "===== RDP ACCESS & SECURITY AUDIT ====="

    # NLA Status (1 = Enabled)
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        $nla = (Get-ItemProperty -Path $regPath -Name "UserAuthentication" -ErrorAction Stop).UserAuthentication
        Write-Log "NLA (UserAuthentication) Value: $nla  (1=Enabled)"
    } catch {
        Write-Log "WARN: Unable to read NLA setting. $($_.Exception.Message)"
    }

    # Who can RDP (Remote Desktop Users group)
    try {
        Write-Log "-- Remote Desktop Users Group Members --"
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            Get-LocalGroupMember -Group "Remote Desktop Users" |
            Select-Object Name, ObjectClass, PrincipalSource |
            Format-Table -AutoSize | Out-String |
            ForEach-Object { Write-Log $_ }
        } else {
            net localgroup "Remote Desktop Users" |
            ForEach-Object { Write-Log $_ }
        }
    } catch {
        Write-Log "WARN: Remote Desktop Users enumeration failed. $($_.Exception.Message)"
    }

    # Recent failed logons (Security 4625)
    try {
        Write-Log "-- Recent Failed Logons (4625) - Top 10 --"
        Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625 } -MaxEvents 10 |
        Select-Object TimeCreated, Id, Message |
        Format-Table -Wrap -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "INFO: Security log query failed (may require admin rights). $($_.Exception.Message)"
    }
}

function Windows-Update-Health-Tool {
    Write-Log "===== WINDOWS UPDATE HEALTH ====="

    try {
        $pendingReboot = $false
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        )
        foreach ($p in $paths) {
            if (Test-Path $p) { $pendingReboot = $true }
        }
        Write-Log "Pending Reboot: $pendingReboot"
    } catch {
        Write-Log "WARN: Pending reboot detection failed. $($_.Exception.Message)"
    }

    try {
        Write-Log "-- Last 10 HotFix --"
        Get-HotFix | Sort-Object InstalledOn -Descending |
        Select-Object -First 10 HotFixID, Description, InstalledOn, InstalledBy |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "WARN: HotFix query failed. $($_.Exception.Message)"
    }
}

function Event-Log-Smart-Triage {
    Write-Log "===== EVENT LOG SMART TRIAGE ====="

    try {
        Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 20 |
        Select TimeCreated, ProviderName, Id, Message |
        Format-Table -Wrap -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "ERROR: System log triage failed. $($_.Exception.Message)"
    }
}

function App-Dependency-Mapper {
    Write-Log "===== APPLICATION DEPENDENCY MAPPER (LIGHT) ====="

    try {
        Write-Log "-- Listening Ports -> Process --"
        $ports = Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Sort-Object LocalPort

        $joined = foreach ($p in $ports) {
            $procName = $null
            try { $procName = (Get-Process -Id $p.OwningProcess -ErrorAction Stop).ProcessName } catch { $procName = "N/A" }
            [pscustomobject]@{
                LocalAddress = $p.LocalAddress
                LocalPort    = $p.LocalPort
                PID          = $p.OwningProcess
                ProcessName  = $procName
            }
        }

        $joined | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "ERROR: Dependency map failed. $($_.Exception.Message)"
    }
}

function Certificate-Expiry-Scanner {
    Write-Log "===== CERTIFICATE EXPIRY SCANNER ====="

    $days = 45
    $cutoff = (Get-Date).AddDays($days)

    try {
        Write-Log "-- LocalMachine\My expiring within $days days (Before $cutoff) --"
        Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.NotAfter -lt $cutoff } |
        Select-Object Subject, Issuer, NotAfter, Thumbprint |
        Sort-Object NotAfter |
        Format-Table -AutoSize | Out-String |
        ForEach-Object { Write-Log $_ }
    } catch {
        Write-Log "ERROR: Cert scan failed. $($_.Exception.Message)"
    }
}

function Run-All {
    Logging-Wrapper
    Server-Baseline-DriftDetection
    Patch-PrePost-Comparison
    Critical-Services-Watchdog
    Unauthorized-LocalAdmin-Detector
    Scheduled-Task-Auditor
    Resource-Spike-Monitor
    SMB-Network-Security-Audit
    Windows-Firewall-Rule-Auditor
    Disk-Cleanup-GrowthForecast
    Domain-Trust-SecureChannel-Validator
    RDP-Access-Security-Audit
    Windows-Update-Health-Tool
    Event-Log-Smart-Triage
    App-Dependency-Mapper
    Certificate-Expiry-Scanner
}

# ---------------- MENU ----------------

do {
    Clear-Host
    Write-Host "====================================="
    Write-Host " SYSADMIN TOOLKIT MENU - $Hostname"
    Write-Host "====================================="
    Write-Host "1.  Logging Wrapper"
    Write-Host "2.  Server Baseline & Drift Detection"
    Write-Host "3.  Pre/Post Patch Capture (Baseline)"
    Write-Host "4.  Critical Services Watchdog"
    Write-Host "5.  Unauthorized Local Admin Detector"
    Write-Host "6.  Scheduled Task Auditor"
    Write-Host "7.  Resource Spike Monitor (Snapshot)"
    Write-Host "8.  SMB & Network Security Audit"
    Write-Host "9.  Windows Firewall Rule Auditor"
    Write-Host "10. Disk Cleanup & Growth Forecast (Inventory)"
    Write-Host "11. Domain Trust & Secure Channel Validator"
    Write-Host "12. RDP Access & Security Audit"
    Write-Host "13. Windows Update Health Tool"
    Write-Host "14. Event Log Smart Triage"
    Write-Host "15. Application Dependency Mapper"
    Write-Host "16. Certificate Expiry Scanner"
    Write-Host "A.  Run ALL Checks (Recommended)"
    Write-Host "Q.  Quit"
    Write-Host "====================================="
    $choice = Read-Host "Select an option"

    switch ($choice.ToUpper()) {
        "1"  { Logging-Wrapper }
        "2"  { Server-Baseline-DriftDetection }
        "3"  { Patch-PrePost-Comparison }
        "4"  { Critical-Services-Watchdog }
        "5"  { Unauthorized-LocalAdmin-Detector }
        "6"  { Scheduled-Task-Auditor }
        "7"  { Resource-Spike-Monitor }
        "8"  { SMB-Network-Security-Audit }
        "9"  { Windows-Firewall-Rule-Auditor }
        "10" { Disk-Cleanup-GrowthForecast }
        "11" { Domain-Trust-SecureChannel-Validator }
        "12" { RDP-Access-Security-Audit }
        "13" { Windows-Update-Health-Tool }
        "14" { Event-Log-Smart-Triage }
        "15" { App-Dependency-Mapper }
        "16" { Certificate-Expiry-Scanner }
        "A"  { Run-All }
        "Q"  { break }
        default { Write-Host "Invalid selection" }
    }

    if ($choice.ToUpper() -ne "Q") {
        Write-Host "`nOutput logged to:"
        Write-Host $LogFile -ForegroundColor Green
        Pause
    }

} while ($true)
