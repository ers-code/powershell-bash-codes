<# 
.SYNOPSIS
  Windows Server 2016 -> 2025 Upgrade Pre-check (v2)

.DESCRIPTION
  Collects upgrade readiness signals and exports:
   - Summary.txt (human readable)
   - Report.json (structured)
   - Optional CSVs (features, drivers, hotfixes, event warnings/errors)

.NOTES
  Run as Administrator.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = "C:\Temp\preCheckLogs",
    [int]$MinFreeGB_SystemDrive = 60,
    [int]$EventLookbackHours = 48,
    [int]$MaxEvents = 300,
    [switch]$RunIntegrityChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]::new($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator."
    }
}

function New-OutputFolder {
    param([Parameter(Mandatory)][string]$Root)
    if (-not (Test-Path -LiteralPath $Root)) { New-Item -Path $Root -ItemType Directory -Force | Out-Null }
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $folder = Join-Path $Root "WS2016_to_WS2025_Precheck_v2_$stamp"
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
    $folder
}

function Try-Get {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )
    try {
        [pscustomobject]@{
            Name   = $Name
            Ok     = $true
            Value  = & $ScriptBlock
            Error  = $null
        }
    } catch {
        [pscustomobject]@{
            Name   = $Name
            Ok     = $false
            Value  = $null
            Error  = $_.Exception.Message
        }
    }
}

function Get-PendingReboot {
    $pending = $false
    $indicators = @()

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    )

    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p) {
            if ($p -like "*Session Manager") {
                $val = (Get-ItemProperty -Path $p -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
                if ($null -ne $val) { $pending = $true; $indicators += "PendingFileRenameOperations" }
            } else {
                $pending = $true
                $indicators += (Split-Path $p -Leaf)
            }
        }
    }

    [pscustomobject]@{
        Pending    = $pending
        Indicators = $indicators
    }
}

function Run-Integrity {
    param([Parameter(Mandatory)][string]$OutputPath)

    "=== SFC /SCANNOW ===" | Out-File -FilePath $OutputPath -Encoding UTF8
    cmd.exe /c "sfc /scannow" | Out-File -FilePath $OutputPath -Append -Encoding UTF8

    "" | Out-File -FilePath $OutputPath -Append -Encoding UTF8
    "=== DISM /Online /Cleanup-Image /RestoreHealth ===" | Out-File -FilePath $OutputPath -Append -Encoding UTF8
    cmd.exe /c "dism /online /cleanup-image /restorehealth" | Out-File -FilePath $OutputPath -Append -Encoding UTF8
}

# ---------------- MAIN ----------------
Assert-Admin
$out = New-OutputFolder -Root $OutputRoot

$paths = [pscustomobject]@{
    Folder          = $out
    SummaryTxt      = (Join-Path $out "Summary.txt")
    ReportJson      = (Join-Path $out "Report.json")
    FeaturesCsv     = (Join-Path $out "InstalledFeatures.csv")
    DriversCsv      = (Join-Path $out "Drivers.csv")
    HotfixesCsv     = (Join-Path $out "Hotfixes.csv")
    EventsCsv       = (Join-Path $out "EventWarningsErrors.csv")
    IntegrityTxt    = (Join-Path $out "IntegrityChecks.txt")
}

$sections = @()

$sections += Try-Get -Name "System" -ScriptBlock {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $bios = Get-CimInstance Win32_BIOS

    [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        Caption        = $os.Caption
        Version        = $os.Version
        BuildNumber    = $os.BuildNumber
        InstallDate    = $os.InstallDate
        LastBootUpTime = $os.LastBootUpTime
        Manufacturer   = $cs.Manufacturer
        Model          = $cs.Model
        TotalRAM_GB    = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
        CPU_Name       = $cpu.Name
        CPU_Cores      = $cpu.NumberOfCores
        CPU_Logical    = $cpu.NumberOfLogicalProcessors
        BIOS_Version   = ($bios.SMBIOSBIOSVersion -join "; ")
        BIOS_Date      = $bios.ReleaseDate
    }
}

$sections += Try-Get -Name "DomainJoin" -ScriptBlock {
    $cs = Get-CimInstance Win32_ComputerSystem
    [pscustomobject]@{
        PartOfDomain = [bool]$cs.PartOfDomain
        Domain       = $cs.Domain
        Workgroup    = $cs.Workgroup
    }
}

$sections += Try-Get -Name "Disk" -ScriptBlock {
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
        Select-Object DeviceID, VolumeName,
            @{n="SizeGB";e={[math]::Round($_.Size/1GB,2)}},
            @{n="FreeGB";e={[math]::Round($_.FreeSpace/1GB,2)}},
            @{n="FreePct";e={ if ($_.Size -gt 0) {[math]::Round(($_.FreeSpace/$_.Size)*100,2)} else { $null } }}
}

$sections += Try-Get -Name "PendingReboot" -ScriptBlock {
    Get-PendingReboot
}

$sections += Try-Get -Name "WindowsUpdateSignals" -ScriptBlock {
    $svc = Get-Service -Name wuauserv,bits,cryptsvc -ErrorAction SilentlyContinue |
        Select-Object Name, Status, StartType

    $auKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $wuKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

    $policy = [ordered]@{
        WUPolicyPresent = (Test-Path -LiteralPath $wuKey)
        AUOptions       = $null
        UseWUServer     = $null
        WUServer        = $null
        WUStatusServer  = $null
    }

    if (Test-Path -LiteralPath $auKey) {
        $p = Get-ItemProperty -Path $auKey -ErrorAction SilentlyContinue
        if ($p) {
            if ($p.PSObject.Properties.Name -contains "AUOptions")   { $policy.AUOptions = $p.AUOptions }
            if ($p.PSObject.Properties.Name -contains "UseWUServer") { $policy.UseWUServer = $p.UseWUServer }
        }
    }
    if (Test-Path -LiteralPath $wuKey) {
        $p2 = Get-ItemProperty -Path $wuKey -ErrorAction SilentlyContinue
        if ($p2) {
            if ($p2.PSObject.Properties.Name -contains "WUServer")       { $policy.WUServer = $p2.WUServer }
            if ($p2.PSObject.Properties.Name -contains "WUStatusServer") { $policy.WUStatusServer = $p2.WUStatusServer }
        }
    }

    [pscustomobject]@{ Services = $svc; Policy = [pscustomobject]$policy }
}

$sections += Try-Get -Name "InstalledFeatures" -ScriptBlock {
    Import-Module ServerManager -ErrorAction Stop
    Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName, FeatureType, Installed
}

$sections += Try-Get -Name "Drivers" -ScriptBlock {
    Get-CimInstance Win32_PnPSignedDriver |
        Select-Object DeviceName, DriverVersion, DriverProviderName, DriverDate, Manufacturer, InfName
}

$sections += Try-Get -Name "Hotfixes" -ScriptBlock {
    Get-HotFix | Sort-Object InstalledOn -Descending |
        Select-Object HotFixID, Description, InstalledOn, InstalledBy
}

$sections += Try-Get -Name "RecentEvents" -ScriptBlock {
    $start = (Get-Date).AddHours(-1 * $EventLookbackHours)
    $all = @()

    foreach ($l in @("System","Application")) {
        try {
            $all += Get-WinEvent -FilterHashtable @{ LogName=$l; Level=2,3; StartTime=$start } -ErrorAction Stop |
                Select-Object TimeCreated, LogName, LevelDisplayName, ProviderName, Id, Message
        } catch { }
    }

    $all | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents
}

# Compute key readiness flags
$disk = ($sections | Where-Object Name -eq "Disk").Value
$sysDrive = $disk | Where-Object { $_.DeviceID -eq "$($env:SystemDrive)" } | Select-Object -First 1
$sysFreeGB = if ($sysDrive) { $sysDrive.FreeGB } else { $null }
$sysFreeOk = if ($sysDrive) { $sysDrive.FreeGB -ge $MinFreeGB_SystemDrive } else { $false }

$pending = ($sections | Where-Object Name -eq "PendingReboot").Value

# Integrity checks (optional)
$integrityResult = $null
if ($RunIntegrityChecks) {
    $integrityResult = Try-Get -Name "IntegrityChecks" -ScriptBlock {
        Run-Integrity -OutputPath $paths.IntegrityTxt
        "Completed. See $($paths.IntegrityTxt)"
    }
    $sections += $integrityResult
}

# Exports
# CSVs where applicable
($sections | Where-Object Name -eq "InstalledFeatures").Value | ForEach-Object { $_ } |
    Export-Csv -Path $paths.FeaturesCsv -NoTypeInformation -Encoding UTF8

($sections | Where-Object Name -eq "Drivers").Value | ForEach-Object { $_ } |
    Export-Csv -Path $paths.DriversCsv -NoTypeInformation -Encoding UTF8

($sections | Where-Object Name -eq "Hotfixes").Value | ForEach-Object { $_ } |
    Export-Csv -Path $paths.HotfixesCsv -NoTypeInformation -Encoding UTF8

($sections | Where-Object Name -eq "RecentEvents").Value | ForEach-Object { $_ } |
    Export-Csv -Path $paths.EventsCsv -NoTypeInformation -Encoding UTF8

# JSON report
$report = [pscustomobject]@{
    Timestamp = (Get-Date).ToString("o")
    Paths     = $paths
    Readiness = [pscustomobject]@{
        SystemDriveFreeGB           = $sysFreeGB
        MinFreeGB_SystemDrive       = $MinFreeGB_SystemDrive
        SystemDriveFreeSpace_OK     = $sysFreeOk
        PendingReboot               = $pending.Pending
        PendingRebootIndicators     = $pending.Indicators
    }
    Sections  = $sections
}

$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $paths.ReportJson -Encoding UTF8

# Text summary
$summary = @()
$summary += "Windows Server Upgrade Pre-check (2016 -> 2025)"
$summary += "Timestamp: $($report.Timestamp)"
$summary += "Computer : $env:COMPUTERNAME"
$summary += ""
$summary += "Readiness Flags:"
$summary += (" - System drive free space OK: {0} (FreeGB={1}, RequiredGB={2})" -f $sysFreeOk, $sysFreeGB, $MinFreeGB_SystemDrive)
$summary += (" - Pending reboot: {0} ({1})" -f $pending.Pending, ([string]::Join(", ", $pending.Indicators)))
$summary += ""
$summary += "Outputs:"
$summary += " - Folder     : $($paths.Folder)"
$summary += " - Summary    : $($paths.SummaryTxt)"
$summary += " - JSON Report: $($paths.ReportJson)"
$summary += " - CSVs       : Features, Drivers, Hotfixes, Events"
if ($RunIntegrityChecks) { $summary += " - Integrity  : $($paths.IntegrityTxt)" }
$summary | Out-File -FilePath $paths.SummaryTxt -Encoding UTF8

Write-Host ""
Write-Host "PRE-CHECK COMPLETE"
Write-Host "Output Folder: $($paths.Folder)"
Write-Host "Summary     : $($paths.SummaryTxt)"
Write-Host "JSON Report : $($paths.ReportJson)"
if ($RunIntegrityChecks) { Write-Host "Integrity   : $($paths.IntegrityTxt)" }
Write-Host ("System Drive Free OK: {0} (FreeGB={1}, RequiredGB={2})" -f $sysFreeOk, $sysFreeGB, $MinFreeGB_SystemDrive)
Write-Host ("Pending Reboot      : {0}" -f $pending.Pending)
