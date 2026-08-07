# Persistence Technique Index

## Quick Reference Guide

**Detection Difficulty Scale:** Easy | Moderate | Hard | Very Hard | Stealthy

| Category         | File                                                                                          | MITRE ID(s)              | Severity | Detection Difficulty |
|------------------|-----------------------------------------------------------------------------------------------|--------------------------|----------|---------------------|
| **Windows**      |                                                                                               |                          |          |                     |
| UEFI Firmware    | advanced-persistence/windows/uefi-firmware-persistence.md                                     | T1542.001               | Critical | Very Hard           |
| Kernel Driver    | advanced-persistence/windows/kernel-mode-driver-persistence.md                                | T1546.009, T1546.013     | Critical | Hard                |
| Boot Config      | advanced-persistence/windows/boot-configuration-bcd-hijack.md                                 | T1546.007               | Critical | Moderate            |
| Signed Binary    | advanced-persistence/windows/signed-binary-abuse.md                                           | T1218.003, T1218         | High     | Moderate            |
| Hypervisor       | advanced-persistence/windows/hypervisor-rootkit-persistence.md                                | T1055.014               | Critical | Very Hard           |
| **Linux**        |                                                                                               |                          |          |                     |
| eBPF Rootkit     | advanced-persistence/linux/ebpf-rootkit-persistence.md                                        | T1053.008               | Critical | Very Hard           |
| Systemd Backdoor | advanced-persistence/linux/systemd-backdoor-services.md                                       | T1543.002               | High     | Moderate            |
| LD Preload       | advanced-persistence/linux/ld-preload-attacks.md                                              | T1574.007               | High     | Hard                |
| Uncommon Linux   | advanced-persistence/linux/uncommon-linux-tactics.md                                          | T1034, T1205, T1027      | High     | Very Hard           |
| **Network Infra**|                                                                                               |                          |          |                     |
| Cisco IOS/NXOS   | advanced-persistence/network-infrastructure/cisco-ios-nxos-persistence.md                     | T1098.004, T1546.015     | Critical | Hard                |
| Juniper JUNOS    | advanced-persistence/network-infrastructure/juniper-junos-persistence.md                      | T1098, T1562.006         | High     | Very Hard           |
| F5 BIG-IP        | advanced-persistence/network-infrastructure/f5-bigip-nginx-persistence.md                     | T1071.003, T1059.004     | Critical | Hard                |
| FW Config        | advanced-persistence/network-infrastructure/firewall-policy-backdoors.md                      | T1571, T1572             | Critical | Moderate            |
| DNS Server       | advanced-persistence/network-infrastructure/dns-server-compromise.md                          | T1071.004, T1098         | High     | Hard                |
| DHCP Server      | advanced-persistence/network-infrastructure/dhcp-server-backdoors.md                          | T1590, T1021             | High     | Moderate            |
| Uncommon Network | advanced-persistence/network-infrastructure/uncommon-network-tactics.md                       | T1497, T1586, T1589      | Critical | Very Hard           |
| **Cloud**        |                                                                                               |                          |          |                     |
| Azure AD         | advanced-persistence/cloud/azure-ad-entrenchment.md                                           | T1098.004, T1528         | Critical | Moderate            |
| AWS IAM          | advanced-persistence/cloud/aws-iam-policy-abuse.md                                            | T1098.002, T1528         | Critical | Easy-Moderate       |
| Uncommon Cloud   | advanced-persistence/cloud/uncommon-cloud-tactics.md                                          | T1136, T1136.004         | High     | Hard                |

## Detection Priority Matrix (by likelihood in real breaches)

### Hunt These First
1. **Windows Registry Run Keys** — Most common post-exploitation method
2. **Scheduled Tasks** — Standard persistence with hunting value
3. **Azure AD Entrenchment** — Cloud attack chain enabler
4. **Signed Binary Abuse** — WIPER, Black Basta, and LockBit use this

### Hunt These Second  
5. **Kernel Driver Persistence** — Advanced persistent threats
6. **Cisco EEM Applets** — Network infrastructure backdoors
7. **Systemd Service Backdoors** — Linux APT persistence
8. **Firewall Config Manipulation** — Lateral movement enabler

### Hunt These Rare but Impactful
9. **UEFI Firmware Persistence** — Nation-state level (APT29, Equation Group)
10. **eBPF Rootkit** — Emerging technique, very stealthy
11. **Hypervisor Rootkit** — VM escape potential, extremely rare
12. **Config Register Manipulation** — Cisco-specific survival technique

## Technique Cross-Reference by MITRE Tactic

### TA0003 - Persistence (Windows/Linux services, scheduled tasks)
| ID        | Technique                                          | Platforms      |
|-----------|----------------------------------------------------|----------------|
| T1547.001 | Registry Run Key                                   | Windows        |
| T1547.002 | Authentication Package                             | Windows        |
| T1543.002 | Create/Modify System Process (Systemd)             | Linux          |
| T1053.003 | Scheduled Task/Job                                 | Windows        |
| T1053.008 | Embedded Scripts/Scheduler (eBPF)                  | Linux          |

### TA0004 - Privilege Escalation via Persistence
| ID        | Technique                                          | Platforms      |
|-----------|----------------------------------------------------|----------------|
| T1546.002 | COM Hijacking                                      | Windows        |
| T1546.007 | Boot or Logon Autostart Execution (BCD)            | Windows        |
| T1546.009 | Kernel Module/Hook                                 | Windows/Linux  |
| T1546.013 | Invalid Security Descriptor                      | Windows        |

### TA0005 - Defense Evasion via Persistence
| ID        | Technique                                          | Platforms      |
|-----------|----------------------------------------------------|----------------|
| T1542.001 | Pre-OS Boot (UEFI)                                | Firmware       |
| T1055.014 | Memory from Hypervisor                            | VM/Hypervisor  |
| T1218.003 | Systemwide Signed Binary Proxy                    | Windows        |

### TA0006 - Collection via Network Persistence
| ID        | Technique                                          | Platforms      |
|-----------|----------------------------------------------------|----------------|
| T1071.003 | Application Layer Protocol (DNS/DHCP)             | Network        |
| T1098.004 | SSH Authorized Keys                                | Linux/Network  |
| T1590      | Gather Victim Network TRs                          | Network        |

### TA0040 - Specific to Network Infrastructure
| ID        | Technique                                          | Platforms      |
|-----------|----------------------------------------------------|----------------|
| T1562.006 | Disable or Modify Tools (SNMP config)            | Cisco/Juniper  |
| T1571      | Non-Standard Port                                  | Firewalls      |
| T1572      | Protocol Tunneling                                | Routers/Switches |
