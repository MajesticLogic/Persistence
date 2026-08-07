# Windows Persistence Hunting Playbook

## Overview

This playbook provides detection and hunting procedures for persistence techniques in Windows environments. Follow these steps to systematically hunt for both common and advanced persistence methods.

## Quick Hunt Commands (Run as Administrator)

### 1. Registry Run Key Audit
```powershell
# Comprehensive registry run key scan
Write-Host "=== HKCU Run Keys ===" -ForegroundColor Cyan
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-List *
Write-Host "`n=== HKLM Run Keys ===" -ForegroundColor Cyan
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-List *
Write-Host "`n=== RunOnce Keys ===" -ForegroundColor Cyan
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" | Format-List *
```

### 2. Scheduled Task Audit
```powershell
# Find all scheduled tasks with unusual trigger patterns
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | ForEach-Object {
    $actions = $_.Actions | Select-Object -ExpandProperty Execute
    if ($actions -match ".exe|cmd\.exe|powershell\.exe") {
        Write-Host "TASK: $($_.TaskName) -> $($actions)" 
    }
}

# Check for tasks created in last 7 days (recently added persistence)
Get-ScheduledTask | Where-Object { $_.DateCreated -gt (Get-Date).AddDays(-7) } | Select TaskName, DateCreated
```

### 3. Service Audit
```powershell
# Find all services with unusual paths or disabled signatures
Get-WmiObject Win32_Service | Where-Object { 
    $_.PathName -match "\.exe" -and 
    (-not (Test-Path $_.PathName)) -or
    (-not (Get-AuthenticodeSignature $_.PathName -ErrorAction SilentlyContinue).Status -eq "Valid")
} | Select Name, PathName, State, StartMode

# Check for services set to boot start (most persistent)
Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.State -eq "Running" }
```

### 4. Driver Integrity Verification
```powershell
# Check all loaded drivers for signature issues
Get-WmiObject Win32_SystemDriver | ForEach-Object {
    $path = $_.PathName
    if (Test-Path $path) {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
        Write-Host "$($_.Name) : $($_.StartMode) | Sig: $($sig.Status)"
    }
}

# Compare against known-good Microsoft hashes (run this periodically to establish baseline)
Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -match "C:\\Windows\\System32\\drivers\\" } | 
    ForEach-Object { Get-FileHash $_.PathName } | Format-List
```

### 5. UEFI/Boot Configuration Audit
```powershell
# Check for unauthorized boot entries
bcdedit /enum firmware | Select-String "identifier|description|path"

# Verify Secure Boot state
tpm.msc  # Or: Get-Tpm | Select *
Get-WinEvent -LogName "Microsoft-Windows-DriverFrameworks-UserMode/Operational" | 
    Where-Object { $_.Id -eq 213 } | Format-List
```

### 6. WMI Subscription Audit (Hidden Persistence)
```powershell
# Check for WMI event subscriptions (often used as persistence)
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Select Name, Query
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Select Name, CommandLineTemplate

# If any are found, check who created them:
Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer | Select Name, ScriptFileName
```

### 7. Startup Folder & AppInit DLLs Audit
```powershell
# Check all startup folders for unusual entries
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($path in $startupPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path | ForEach-Object { 
            Write-Host "STARTUP: $($_.FullName)" 
        }
    }
}

# Check AppInit DLLs (deprecated but still used)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs 2>$null
```

## Sysmon-Based Hunting Queries

### New Service Installation (Event ID 7045 in Windows Event Log, mapped to Sysmon)
```kql
// Hunt for new services installed with boot start or kernel driver type
SecurityEvent 
| where EventID == 7045
| extend ServiceType = tostring(EventData["serviceType"]), StartMode = tostring(EventData["startMode"])
| where ServiceType == "16" or StartMode == "3"  // Kernel driver or boot start
| project StartTime, Computer, AccountName, serviceName, pathName, ImagePath
```

### Process Created — Persistence Binary Execution (Event ID 4688)
```kql
// Look for suspicious processes executing persistence mechanisms
SecurityEvent 
| where EventID == 4688
| extend CommandLine = tostring(EventData["CommandLine"])
| where CommandLine contains "reg add" or CommandLine contains "schtasks" or 
        CommandLine contains "sc.exe create" or CommandLine contains "bcdedit"
| project StartTime, Computer, AccountName, ProcessName, ParentProcessName, CommandLine
```

### WMI Subscription Creation (Event ID 5861/5857)
```kql
// Hunt for WMI filter/consumer creation events
SecurityEvent 
| where EventID == 5861 or EventID == 5857
| project StartTime, Computer, AccountName, OperationType, NamespacePath
```

### Driver Load Event (Sysmon Event ID 6)
```kql
// Sysmon driver load event — check for new/unsigned drivers
SecurityEvent 
| where EventID == 6
| extend Image = tostring(EventData["Image"])
| where not (Image startswith "C:\\Windows\\System32\\drivers\\" or Image startswith "C:\\Windows\\SysWOW64\\")
| project StartTime, Computer, Image, ImageLoaded, Signature, SignatureStatus
```

## PowerShell-Based Comprehensive Hunt Script

```powershell
Write-Host "=== COMPREHENSIVE WINDOWS PERSISTENCE HUNT ===" -ForegroundColor Cyan
$findings = @()

# 1. Registry Run Keys
Write-Host "`n[1/8] Checking Registry Run Keys..." -ForegroundColor Yellow
@("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", 
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run") | ForEach-Object {
    $keys = Get-ItemProperty $_ -ErrorAction SilentlyContinue
    foreach ($key in $keys.PSObject.Properties) {
        if ($key.Value -match "\.exe" -or $key.Value -match "cmd\.") {
            $findings += "REG RUN KEY: $($_)$($key.Name) = $($key.Value)"
        }
    }
}

# 2. Scheduled Tasks
Write-Host "`n[2/8] Checking Scheduled Tasks..." -ForegroundColor Yellow
$tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" }
foreach ($task in $tasks) {
    $actions = $task.Actions.Execute
    if ($actions -match ".exe|cmd\.exe|powershell\.exe") {
        $findings += "SCHEDULED TASK: $($task.TaskName) -> $($actions)"
    }
}

# 3. Services
Write-Host "`n[3/8] Checking Services..." -ForegroundColor Yellow
$services = Get-WmiObject Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.State -eq "Running" }
foreach ($service in $services) {
    if (Test-Path $service.PathName) {
        $sig = Get-AuthenticodeSignature $service.PathName -ErrorAction SilentlyContinue
        if ($null -eq $sig -or $sig.Status -ne "Valid") {
            $findings += "UNSIGNED SERVICE: $($service.Name) -> $($service.PathName)"
        }
    }
}

# 4. Driver Integrity
Write-Host "`n[4/8] Checking Drivers..." -ForegroundColor Yellow
Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -match "C:\\Windows\\System32\\drivers\\" } | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.PathName -ErrorAction SilentlyContinue
    if ($null -eq $sig -or $sig.Status -ne "Valid") {
        $findings += "DRIVER ISSUE: $($_.Name) -> $($_.PathName)"
    }
}

# 5. WMI Subscriptions
Write-Host "`n[5/8] Checking WMI Subscriptions..." -ForegroundColor Yellow
$wmiFilters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
if ($wmiFilters) {
    foreach ($filter in $wmiFilters) {
        $findings += "WMI FILTER: $($filter.Name) -> $($filter.Query)"
    }
}

# 6. Startup Folders
Write-Host "`n[6/8] Checking Startup Folders..." -ForegroundColor Yellow
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | ForEach-Object {
    $findings += "STARTUP FILE: $($_.FullName)"
}

# 7. Boot Configuration
Write-Host "`n[7/8] Checking Boot Configuration..." -ForegroundColor Yellow
$bootEntries = bcdedit /enum firmware
if ($bootEntries) {
    $bootLines = $bootEntries | Select-String "description|path"
    if ($bootLines -match "malicious\|backdoor\|unknown") {
        $findings += "BOOT ENTRY: $($bootLines.Line)"
    }
}

# 8. AppInit DLLs & Other Legacy Keys
Write-Host "`n[8/8] Checking Legacy Persistence..." -ForegroundColor Yellow
$appInit = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -ErrorAction SilentlyContinue
if ($appInit.AppInit_DLLs) {
    $findings += "APPINIT DLLS: $($appInit.AppInit_DLLs)"
}

# Report findings
Write-Host "`n=== HUNT RESULTS ===" -ForegroundColor Cyan
if ($findings.Count -gt 0) {
    Write-Host "FINDINGS: $($findings.Count)`n" -ForegroundColor Red
    $findings | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
} else {
    Write-Host "No persistence indicators found." -ForegroundColor Green
}
```

## Defense Recommendations

1. **File Integrity Monitoring** on registry keys, startup folders, and driver directories
2. **Application Control** via AppLocker or WDAC policies
3. **Sysmon with comprehensive configuration** (monitor service creation, driver loads, WMI events)
4. **Baseline configurations** for BCD store, boot order, and loaded drivers
5. **Regular automated scans** using the PowerShell hunt script above

## References
- Microsoft Sysmon Configuration Guide: https://github.com/Sysinternals/Sysmon
- MITRE ATT&CK Persistence Tactics: https://attack.mitre.org/tactics/TA0003/
