# Network Device Hunting Playbook

## Overview

This playbook provides detection and hunting procedures for persistence techniques in network infrastructure devices (routers, switches, firewalls, DNS/DHCP servers). Unlike host-based hunting, network device hunting requires specialized tools and configuration auditing.

## Prerequisites

- Read access to all network device management interfaces (SSH/SNMP/TACACS+)
- Syslog access from all network devices
- SNMP community strings or API credentials for config queries
- Network TAP or SPAN port access for traffic analysis
- Time synchronization (NTP) across all network devices

## Hunting Methodology

### Phase 1: Configuration Baseline Comparison

```bash
#!/bin/bash
# daily_config_audit.sh — Run this daily against all devices
devices="router1 router2 switch1 switch2 fw1 fw2 dns1 dhcp1"

for device in $devices; do
    # Pull current config via SSH
    ssh $device "show run" > /tmp/configs/${device}_$(date +%Y%m%d).txt
    
    # Compare against last-known-good baseline
    diff /tmp/configs/${device}_baseline.txt /tmp/configs/${device}_$(date +%Y%m%d).txt > /tmp/diffs/${device}_diff.txt || true
    
    # Alert if differences found
    if [ -s /tmp/diffs/${device}_diff.txt ]; then
        mail -s "CONFIG DIFF: $device" security@yourdomain.com < /tmp/diffs/${device}_diff.txt
    fi
done
```

### Phase 2: EEM Applet Detection

EEM applets are hidden by default in Cisco devices and often contain persistence backdoors:

```bash
# Check for EEM applets on all Cisco devices
for device in $devices; do
    echo "=== $device EEM APPLET CHECK ===" >> /tmp/eem_audit.txt
    ssh $device "show event manager policy" 2>&1 >> /tmp/eem_audit.txt
done

# Look for suspicious patterns in EEM applets
grep -E "username|secret|snmp-server|access-list|vlan|route|boot system" /tmp/eem_audit.txt
```

### Phase 3: SNMP Configuration Audit

Check all SNMP settings across network devices for unauthorized configurations:

```bash
for device in $devices; do
    echo "=== $device SNMP CONFIG ===" >> /tmp/snmp_audit.txt
    ssh $device "show snmp community" 2>&1 >> /tmp/snmp_audit.txt
    ssh $device "show snmp mib" 2>&1 >> /tmp/snmp_audit.txt
done

# Look for: unauthorized community strings, new trap receivers, modified MIB entries
grep -E "community|trap|host|mib" /tmp/snmp_audit.txt | grep -v "^$" 
```

### Phase 4: Boot Configuration Verification

Check config-register settings and boot parameters on all Cisco devices:

```bash
for device in $devices; do
    echo "=== $device BOOT CONFIG ===" >> /tmp/boot_audit.txt
    ssh $device "show version | include Config|Register" 2>&1 >> /tmp/boot_audit.txt
    ssh $device "show boot" 2>&1 >> /tmp/boot_audit.txt
done

# Look for config-register values that are not standard (0x2102, 0x2142)
grep -E "Config register is|Register|boot" /tmp/boot_audit.txt | awk '{print $NF}'
```

### Phase 5: Firewall Policy Auditing

Check firewall rules for unauthorized allow-all or suspicious patterns:

```bash
# Palo Alto specific — check for recently modified policies
for fw in ${firewalls[@]}; do
    echo "=== $fw POLICY AUDIT ===" >> /tmp/fw_audit.txt
    ssh $fw "show rulebase access-policy" 2>&1 | grep -E "name|source|destination|action|from to" >> /tmp/fw_audit.txt
done

# Look for: 
# - Policies with source/destination = any/any
# - Recently modified policies (last 30 days)
# - Policies allowing traffic to unexpected destinations
```

### Phase 6: DHCP Server Audit

Check DHCP configurations for unauthorized options, servers, or static bindings:

```bash
for dhcp in ${dhcp_servers[@]}; do
    echo "=== $dhcp DHCP AUDIT ===" >> /tmp/dhcp_audit.txt
    ssh $dhcp "show running-config section dhcp-server" 2>&1 >> /tmp/dhcp_audit.txt
    ssh $dhcp "show ip dhcp binding" 2>&1 >> /tmp/dhcp_audit.txt
done

# Look for: option-66/43 injection, rogue DHCP servers, unusual static bindings
grep -E "option|server|binding|default-router|dns-server" /tmp/dhcp_audit.txt
```

### Phase 7: DNS Server Audit

Check DNS configurations for zone file modifications and forwarder changes:

```bash
for dns in ${dns_servers[@]}; do
    echo "=== $dns DNS AUDIT ===" >> /tmp/dns_audit.txt
    ssh $dns "cat /etc/bind/named.conf.options | grep forwarders\|forward-only" 2>&1 >> /tmp/dns_audit.txt
    ssh $dns "cat /var/log/named/security.log | grep last 30 days" 2>&1 >> /tmp/dns_audit.txt
done

# Look for: modified forwarder IPs, unexpected zone files, unusual DNS query patterns
```

### Phase 8: BGP Session Verification

Check BGP configurations and neighbor relationships for unauthorized peers:

```bash
for router in ${routers[@]}; do
    echo "=== $router BGP AUDIT ===" >> /tmp/bgp_audit.txt
    ssh $router "show bgp summary" 2>&1 >> /tmp/bgp_audit.txt
    ssh $router "show run | section bgp" 2>&1 >> /tmp/bgp_audit.txt
done

# Look for: unexpected BGP peers, modified route policies, unauthorized AS numbers
```

## Real-Time Detection Rules

### Syslog-Based Alerts (SIEM Queries)

#### EEM Applet Creation Alert
```kql
// Splunk query — detect EEM applet creation via syslog
index=syslog sourcetype:cisco:ios "event manager applet" OR "EEM-applet" | stats count by src_ip, host, raw
| where count > 0
| sort -count

// SIEM alert action: notify SOC of unauthorized config change
```

#### Config Register Change Alert
```kql
// Splunk query — detect config register modifications
index=syslog sourcetype:cisco:ios "config-register" | table _time, host, src_ip, raw
| sort -_time

// Alert if config-register value is 0x2142 (skip startup-config) or any non-standard value
```

#### New User Account Creation on Network Devices
```kql
// Splunk query — detect new admin/backdoor accounts created on network devices
index=syslog sourcetype:cisco:ios "username" AND ("configured by" OR "configuration") | table _time, host, raw
| where raw match "*privilege 15*" OR raw match "*secret*"

// Alert if user was created on a non-management device
```

#### SNMP Trap Receiver Addition
```kql
// Splunk query — detect new SNMP trap receivers being configured
index=syslog sourcetype:cisco:ios "snmp-server host" | table _time, host, raw
| stats count by src_ip, raw

// Alert on any new SNMP host entry not in your organization's IP ranges
```

#### DHCP Configuration Change Alert
```kql
// Splunk query — detect DHCP configuration modifications
index=syslog sourcetype:f5:bigip "dhcp.*option" OR "DHCP.*config" | table _time, host, raw
| where raw match "*option-66*" OR raw match "*option-43*"

// Alert immediately — these are common persistence injection points
```

### SNMP Trap Monitoring Script

```python
#!/usr/bin/env python3
"""Monitor SNMP traps for network device persistence indicators."""
import socket
import sys

def handle_trap(community, trap_data):
    # Parse trap OIDs for persistence indicators
    oid_checks = {
        '1.3.6.1.4.1.9.9.41': 'CONFIG_CHANGE',  # Cisco config change OID
        '1.3.6.1.4.1.9.2.1.56': 'SNMP_CONFIG_CHANGE',  # SNMP community change
        '1.3.6.1.4.1.9.9.170.1.1.1.1': 'DHCP_CONFIG_CHANGE',  # DHCP config change
    }
    
    for oid, category in oid_checks.items():
        if oid in trap_data:
            print(f"[ALERT] {category} detected on device")
            # Alert to SIEM/monitoring system
            alert_to_siem(category, trap_data)

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 162))  # SNMP trap port
    print("Listening for SNMP traps...")
    
    while True:
        data, addr = sock.recvfrom(4096)
        community, trap_info = parse_snmp_trap(data)
        
        # Verify source is authorized
        if not is_authorized_snmp_source(addr[0]):
            print(f"[WARN] Untrusted SNMP trap from {addr[0]}")
        
        handle_trap(community, trap_info)

if __name__ == "__main__":
    main()
```

## Configuration Diff Tool

```bash
#!/bin/bash
# config_diff_tool.sh — Generate detailed diffs of network device configs
DEVICE_CONFIGS_DIR="/tmp/device_configs"
BASELINE_DIR="/baseline/known_good"

for device_file in $DEVICE_CONFIGS_DIR/*; do
    device_name=$(basename $device_file .txt)
    baseline="$BASELINE_DIR/${device_name}_baseline.txt"
    
    if [ -f "$baseline" ]; then
        diff --color=always -u "$baseline" "$device_file" > "/tmp/diffs/${device_name}_$(date +%Y%m%d).diff" || true
        
        # Check for specific persistence indicators in the diff
        grep -E "(username|secret|snmp-server|config-register|boot system|archive)" /tmp/diffs/${device_name}_$(date +%Y%m%d).diff && \
            echo "PERSISTENCE INDICATOR FOUND: $device_name" | mail -s "ALERT" security@yourdomain.com
    fi
done
```

## Defense-in-Depth Recommendations

1. **Centralized Logging** — Forward all config changes, SNMP traps, and syslog to a SIEM with retention of 90+ days
2. **Automated Config Backup** — Daily automated backups of all running-configs to immutable storage
3. **TACACS+ Authentication** — Require TACACS+ for ALL device access with no local accounts
4. **Network Device FIM** — Deploy file integrity monitoring on all network device filesystems
5. **Configuration Management Tooling** — Use Ansible/Puppet/Terraform to enforce and detect drift
6. **Regular Audits** — Weekly manual audits of EEM applets, SNMP configs, user accounts, and firewall rules
7. **SNMPv3 with AuthPriv** — Never use SNMPv1/v2c community strings; require authentication and encryption
8. **Physical Security** — Protect physical access to all network devices; config-register manipulation requires CLI/physical access

## Incident Response Checklist for Network Device Persistence

- [ ] Identify compromised device(s) from syslog/SIEM alerts
- [ ] Isolate affected device from production network (do not reboot!)
- [ ] Dump running-config immediately before any remediation: `show run > /tmp/preserve_running_config.txt`
- [ ] Check EEM applets, config register, and archive settings
- [ ] Audit all user accounts with privilege 15 access
- [ ] Review all firewall rules for unauthorized entries (last 90 days)
- [ ] Verify DHCP options 66/43 haven't been modified
- [ ] Check BGP configurations for unauthorized peers
- [ ] Restore device from known-good backup or re-image entirely
- [ ] Rotate all credentials (SNMP communities, TACACS+ keys, API tokens) on affected devices
- [ ] Verify network traffic patterns have returned to normal

## References
- Cisco IOS Security Configuration Guide
- MITRE ATT&CK Network Infrastructure Tactics: https://attack.mitre.org/tactics/TA0040/
- NIST SP 800-153: Network Device Security Guidelines
