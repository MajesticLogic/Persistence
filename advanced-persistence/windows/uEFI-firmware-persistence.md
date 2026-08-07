# UEFI Firmware Persistence

## MITRE ATT&CK Mapping
- **ID**: T1542.001 — Pre-OS Boot: System Firmware
- **Tactic**: TA0005 (Defense Evasion) / TA0003 (Persistence)
- **Platforms**: UEFI BIOS firmware (x86/x64 systems)

## Overview

UEFI firmware persistence is one of the most sophisticated and persistent techniques available to adversaries. By modifying the system firmware, an attacker can survive OS reinstalls, full disk wipes, SSD secure erases, and even motherboard replacements (if they target removable UEFI modules). This technique requires physical access or a vulnerable driver exploit to implement but once established, it's virtually impossible for endpoint defenders to detect without specialized hardware tools.

## How It Works in Practice

### Architecture Context
UEFI firmware contains several exploitable components:
- **SPI Flash Chip** — Stores boot manager, runtime drivers, and OS boot scripts
- **Variable Store (NV Ram)** — UEFI variables like BootOrder, BootNext, SecureBootPolicy
- **Capsule Update Interface** — Legitimate mechanism for firmware updates that can be abused
- **PEI/DXE Drivers** — Early boot phases where execution occurs before any OS hooks

### Attack Vectors

#### 1. Boot Manager Modification (Most Common)
The adversary modifies the UEFI boot manager to insert a malicious payload into the chain of loaded images:

```bash
# Legitimate-looking UEFI variable manipulation (requires SMM access or Ring -0)
SetUefiVariable("Boot000F", "{bootmgr}\malicious.efi", 0x7)  # 0x7 = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS

# The malicious EFI stub runs during boot, loads into memory, and executes before Windows
```

#### 2. Boot Order Manipulation
Changes the UEFI BootOrder variable to load a custom bootloader first:

```c
// Exploiting vulnerability in firmware update mechanism
UINT16 newBootOrder[] = {0x00FF, 0x0001, 0x0002, 0x0003};  // Custom boot entry first
SetVariable("BootOrder", &gEfiGlobalVariableGuid, EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_READ_WRITE, sizeof(newBootOrder), newBootOrder);
```

#### 3. UEFI Driver Implant (Capsule Update Abuse)
Most enterprise firmware update mechanisms use the UEFI Capsule API. An adversary can:
1. Craft a fake signed firmware capsule containing modified DXE drivers
2. Deliver it via email or network share as "driver update.exe"
3. The legitimate BIOS/UEFI update mechanism loads and executes the malicious driver at boot

```powershell
# Abusing WMI to trigger a malicious firmware capsule (requires high privileges)
$namespace = "root\wmi"
$capsuleClass = Get-WmiClass -Namespace $namespace -ClassName "WmiMonitorBrightNessBasicOutput"
# Trigger capsule update with crafted payload in the .bin file
```

#### 4. Runtime Services Exploitation (SMM/BIOS)
- Modifies SMI handlers during firmware initialization
- Inserts code into the System Management Mode (ring -2 execution, invisible to OS)
- Triggers on specific power events or hardware interrupts

## Real-World Examples

### APT29 / Cozy Bear (WinPWN / SolarWION variants)
- Modified GRUB bootloader on Linux systems (similar technique adapted for UEFI on Windows hosts)
- Used pre-bootloader modifications to establish persistence before OS loaded
- Survived multiple forensic investigations that showed "clean" disks

### Equation Group / DiamondFire (2017 - Washington Post investigation)
- Created firmware-level rootkits embedded in server motherboards
- Targeted network appliances (Cisco, Dell, IBM servers) shipped with infected firmware
- Included "backdoor shell" accessible via SMB at boot time
- Could survive any OS or disk wipe

### UEFI:Threat (2019 - Kaspersky research)
- Modified the UEFI NV Ram variable store to add malicious boot entries
- Used legitimate-looking PE images signed with stolen certificates
- Persisted across Windows 10/11 reinstallations on tested testbeds

### BlackLotus / LockPenguin (CVE-2022-21459, CVE-2022-21461)
- UEFI bootloader vulnerabilities allowing boot before Secure Boot validation
- Exploited Microsoft UEFI secure boot implementation bugs
- Targeted the shim loader in the Microsoft-signed bootloader path

## Forensic Artifacts & Indicators

### Boot Configuration Artifacts
```powershell
# Check for unusual UEFI boot entries (requires admin)
Get-WmiObject -Namespace root\wmi -ClassName BCD_BcdObject | Select BcdObjectId, EntryName

# Export current boot manager state (PowerShell 5+ with appropriate modules)
bcdedit /enum firmware
```

### Registry Artifacts (if Windows interacts with UEFI vars)
```
HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State  -> SecureBootEnabled value
HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Policies -> Policy enforcement state
```

### Sysmon Equivalent Artifacts (conceptual — firmware doesn't have Sysmon)
- SPI Flash chip contents via DMA attack or physical flasher
- UEFI variable store dumps (requires rootkits to read from NVRAM directly)
- Boot order comparisons between known-good and current state
- Capsule update event logs in Windows Event ID 12 / firmware update history

### Network Indicators
- Outbound DNS queries for firmware update check URLs (especially non-OEM domains)
- HTTPS connections to UEFI capsule update endpoints with malformed certificates
- HTTP traffic during boot phase (pre-OS network access via PXE or UEFI TCP/IP stack)

### Behavioral Anomalies
- Boot time increases by 5-30 seconds (malicious driver loading time)
- POST/BIOS splash screens modified to include custom text/logo (rare but seen)
- Secure Boot state changes without authorized firmware update event
- New boot entries appearing in BCD/Firmware boot manager

## Hunting Queries

### Sysmon-based Detection (Event ID: 4688 with parent checks — indirect)
```kql
// Hunt for processes executing at boot that shouldn't run
SecurityEvent 
| where EventID == 4688
| where ProcessCommandLine contains ".efi" or ProcessCommandLine contains "bootmgfw"
| where ParentProcessName != "winlogon.exe" and ParentProcessName != "system process"
```

### PowerShell-based Boot Order Audit
```powershell
# Compare current boot order against known good baseline
$baseline = Get-Content "C:\baseline\boot_order.txt"  # Known-good UEFI vars
$current = bcdedit /enum firmware | Select-String "identifier" | ForEach-Object { $_.Line }
if ($baseline -ne $current) { Write-Host "BOOT ORDER TAMPERING DETECTED" }
```

### UEFI Variable Audit Script (Conceptual — requires kernel-mode or SMM access to read NV Ram)
```powershell
# This requires a ring-0 driver to actually read the variables. Standard PowerShell cannot do this.
# Instead, monitor for variable write events via ETW:
Register-WinEvent -ProviderName "Microsoft-Windows-Kernel-Nt" -EventId 32 | Where-Object { $_.Message -match "VariableStore" }
```

### Memory Forensics (Volatility 3)
```bash
# Use volatility3 to scan for UEFI variable structures in memory dump
vol -f memdump.win ntvars
vol -f memdump.win uefi.nvram

# Look for EFI_VARIABLE_NON_VOLATILE flags set outside of legitimate firmware drivers
```

## Defense & Mitigation

### Primary Defenses
1. **Enable Secure Boot** with known-good PK (Platform Key) — prevents unauthorized boot entries from loading
2. **Configure BIOS password** and disable USB/PCIe boot options
3. **Disable UEFI Capsule updates** in environments where remote firmware updates aren't needed
4. **Regularly audit boot order** using baseline comparison tools (UEFI-FI, Coreboot checks)
5. **Implement TPM 2.0 with PCR7 extension for Secure Boot verification**

### Incident Response
1. **Physical inspection** of the SPI flash chip — may need SOIC clip or CH341A programmer
2. **Replace the motherboard** if firmware-level persistence is confirmed (only sure way to remove)
3. **Flash known-good firmware** from verified vendor media using hardware programmer
4. **Verify Secure Boot PK state** matches organization baseline
5. **Check all network-connected devices** on that subnet — UEFI compromise of one host may indicate lateral movement

### Detection Tools
- **UEFI-FI** — Firmware introspection and monitoring (Coreboot community tool)
- **EDK2-based forensic plugins** for volatility3
- **SPI flash readers** (CH341A, TL866) for physical firmware extraction
- **Intel ME Explorer / mei_exploit** for Management Engine analysis
- **UEFI Secure Boot PCR monitors** via TPM event logs

## Limitations & Caveats
- Requires either physical access to the device or a high-privilege exploit chain (typically 2-3 vulnerabilities deep)
- Detection requires out-of-band tools — standard EDR cannot read UEFI NVRAM
- Firmware persistence is rare in most campaigns; typically reserved for nation-state or very targeted operations
- Newer firmware protections (UEFI Secure Boot, TPM-backed attestation) significantly raise the bar

## References
- Microsoft Docs: UEFI Secure Boot Overview
- Coreboot Project: https://www.coreboot.org/
- Kaspersky: "UEFI:Threat – A Novel Malware Family" (2019)
- Washington Post: "The Equation Group" firmware investigation (2017)
- MITRE ATT&CK: T1542.001 — https://attack.mitre.org/techniques/T1542/001/
