# Advanced Persistence Techniques Reference

## A Hunter's Guide to Adversary Persistence Methods & Detection

This repository documents advanced persistence techniques used by adversaries across Windows, Linux, cloud infrastructure, and network devices (routers, switches, firewalls). Each technique includes MITRE ATT&CK mapping, adversary case studies, forensic indicators, and specific detection/hunting queries.

## Repository Structure

```
advanced-persistence/          → Technique documentation
├── windows/                   → OS-level persistence (registry, services, boot)
├── linux/                     → Kernel & service-level persistence
├── network-infrastructure/    → Routers, switches, firewalls, DNS/DHCP servers
├── cloud/                     → Azure AD, AWS IAM, GCP persistence

detection-hunting/             → Detection playbooks
├── windows-hunting-playbook.md
├── linux-hunting-playbook.md
├── network-device-hunting.md
└── cloud-hunting-playbook.md
```

## What Makes This Different

Most persistence documentation stops at surface-level techniques. This repo covers:

- **Advanced & uncommon methods** rarely documented in public research
- **Network infrastructure persistence** (routers, switches, firewalls) — heavily under-documented
- **Hunter-focused** content with detection logic, not just attack descriptions
- **Real adversary case studies** from actual breach reports and red team engagements
- **Detection artifacts** specific to each technique (log sources, registry keys, file artifacts)

## MITRE ATT&CK Coverage

| Tactic       | Techniques Covered                                                                 |
|--------------|------------------------------------------------------------------------------------|
| TA0003       | Registry Run Keys, Scheduled Tasks, Services, Boot Configuration Hijack           |
| TA0004       | COM Hijacking, DLL Side-Loading, Kernel Driver Injection                          |
| TA0005       | UEFI Firmware Persistence, Hypervisor Rootkits, Boot Sector                     |
| TA0006       | SSH Backdoors, SNMP Configuration Abuse, DHCP/DNS Tampering                       |
| TA0040       | Network Device Config Register Manipulation, EEM Applets, Port Forwarding         |

## Quick Start for Hunters

1. Navigate to the category you want to hunt in (`advanced-persistence/`)
2. Read the technique document for indicators
3. Apply the hunting queries from `detection-hunting/<category>.md`
4. Cross-reference with our [INDEX.md](./INDEX.md) for full coverage

## Notes on Network Device Persistence

The network infrastructure section is deliberately detailed because:
- Most organizations have **zero monitoring** on router/switch/firewall configs
- These devices persist across host-level purges — if your edge router is owned, you own the network
- Detection in this layer requires config diffs, syslog analysis, and SNMP trap auditing

## Contributing

If you discover new uncommon persistence methods or detection bypasses, open an issue with:
1. Technique description & MITRE ID
2. Real-world examples (if any)
3. Suggested detection approaches
4. References/threat intel sources

## Disclaimer

This repository is for **educational and defensive purposes only**. All content should be used in authorized testing environments.
