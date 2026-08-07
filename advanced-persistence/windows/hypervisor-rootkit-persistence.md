# Hypervisor & VM Persistence

## MITRE ATT&CK Mapping
- **ID**: T1055.014 — Process/Hypervisor from Virtual Machine Escape
- **Tactic**: TA0003 (Persistence) / TA0005 (Defense Evasion)
- **Platforms**: VMware ESXi, Hyper-V, KVM/QEMU, ProxMox

## Overview

Hypervisor-level persistence involves implanting code into the virtual machine monitor itself. This technique allows an attacker to persist across guest OS changes, complete VM recreation, and hypervisor snapshots. It represents a very advanced attack surface — typically only seen in targeted operations by nation-states or extremely sophisticated threat actors.

## How It Works in Practice

### Method 1: Hypervisor Configuration Persistence (VMware ESXi)
The adversary modifies the ESXi host configuration to load malicious code at boot:

```bash
# Check for unauthorized VIBs (VMware Installed Bundles)
esxcli software vib list | grep -i "unknown\|malicious"

# Modify /etc/rc.local or /sbin/init.d to load custom modules
echo "/opt/malware/payload.sh &" >> /etc/rc.local

# Hijack vmware-hostd to load malicious libraries
LD_PRELOAD=/opt/lib/inspector.so vmware-hostd
```

### Method 2: VM Configuration File Tampering
Modify the .vmx configuration file of a target VM to execute code during boot:

```bash
# Add persistence entry to VMX config
echo 'guestOS.alt = "windows10-64"' >> /vmfs/volumes/datastore/malicious_vm/malicious.vmx
echo 'prefvmx.minimumMEM = "100"' >> /vmfs/volumes/datastore/malicious_vm/malicious.vmx

# Add a custom script that runs before the VM OS boots
echo '!this' > /vmfs/volumes/datastore/.hidden/preload.bin
```

### Method 3: Hyper-V Integration Services Persistence
Abuse the Hyper-V guest service infrastructure to implant persistence in the host:

```powershell
# Abusing WMI hyper-v classes to create a malicious management process
gwmi -Namespace root\virtualization\v2 Msvm_ComputerSystem | Where-Object { $_.ElementName -eq "TargetVM" } | Invoke-WmiMethod -Name StartVM

# Monitor for unauthorized VMs being created
Get-WmiObject -Namespace "root\Virtualization\v2" -Query "SELECT * FROM Msvm_VirtualSystemManagementService"
```

### Method 4: Snapshot/Restore Abuse
After establishing persistence in a guest VM, the adversary creates a snapshot that includes their malicious state:

```bash
# Take a snapshot that captures the compromised state
vim-cmd vmsvc/snapshot.create vmid "123" "BackdoorSnapshot" "Malware saved here" 1 1

# Even if someone reverts to the original, they revert back TO the malware
vim-cmd vmsvc/snapshot.revert vmid "123" "snapshot-id-here"
```

## Real-World Examples

### APT29 / CozyDuke
- Used ESXi host-level persistence across VMware environments in European government networks
- Modified hypervisor management interfaces to create hidden VMs that survived snapshot reverts

### DarkHydrus (APT34)
- Implanted a backdoor into the ProxMox virtualization platform configuration
- Created unauthorized KVM instances on compromised hosts
- Used VM snapshots to maintain persistence across host reboots

## Forensic Artifacts & Indicators

### ESXi-Specific
```bash
# Check for unauthorized VIBs
esxcli software vib list | awk '{print $1, $2, $3}'

# Review /var/log/vmware/hostd.log for unusual configuration changes
grep -i "modify\|create\|install" /var/log/vmware/hostd.log

# Check for unexpected VMs on the host
vim-cmd vmsvc/getallvms | awk '{print $1, $2}'
```

### Hyper-V-Specific
```powershell
# Check for unauthorized virtual machines
Get-VM | Where-Object { $_.State -eq "Running" } | Select Name, State, Uptime

# Check for unauthorized management operations
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Hyper-V-VMMS-Admin'; Id=10}
```

### Common Artifacts
- Unauthorized snapshot creation timestamps vs. authorized backup schedules
- New VM configurations with suspicious memory/CPU allocations
- Management API access logs showing unusual operations (create, destroy, snapshot)
- Memory forensics of the hypervisor process looking for injected code

## Defense & Mitigation

1. **Enable ESXi secure boot** and firmware TPM attestation
2. **Restrict management API access** — monitor all vCenter/Hyper-V management activity
3. **Snapshot policy enforcement** — alert on any snapshot creation outside maintenance windows
4. **VIB package integrity monitoring** — verify against known-good catalog before installation
5. **Network segmentation of hypervisor management networks**

## References
- MITRE ATT&CK T1055.014: https://attack.mitre.org/techniques/T1055/014/
- VMware ESXi Security Hardening Guide
