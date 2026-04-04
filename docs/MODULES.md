# hardbox — Module Reference

Each module is self-contained, independently enabled/disabled, and maps every check to one or more compliance framework controls.

---

## Module: SSH Hardening

**ID:** `ssh`  
**Severity Coverage:** Critical, High, Medium

### Checks

| ID | Check | Default | Severity | CIS | NIST | STIG |
|---|---|---|---|---|---|---|
| ssh-001 | Disable root login (`PermitRootLogin no`) | ✓ | Critical | 5.2.8 | AC-6 | V-238218 |
| ssh-002 | Disable password authentication | ✓ | Critical | 5.2.12 | IA-5 | V-238219 |
| ssh-003 | Set `MaxAuthTries` ≤ 4 | 3 | High | 5.2.7 | AC-7 | V-238220 |
| ssh-004 | Set `LoginGraceTime` ≤ 60 | 30 | Medium | 5.2.16 | AC-2 | — |
| ssh-005 | Disable X11 forwarding | ✓ | Medium | 5.2.6 | — | V-238222 |
| ssh-006 | Disable TCP forwarding | ✓ | Medium | 5.2.21 | — | — |
| ssh-007 | Set `ClientAliveInterval` + `CountMax` | 300/3 | Medium | 5.2.16 | SC-10 | V-238233 |
| ssh-008 | Restrict `AllowUsers` / `AllowGroups` | ✓ | High | 5.2.22 | AC-17 | — |
| ssh-009 | Enforce strong ciphers only | ✓ | High | 5.2.14 | SC-8 | V-238234 |
| ssh-010 | Enforce strong MACs only | ✓ | High | 5.2.15 | SC-8 | V-238235 |
| ssh-011 | Enforce strong KexAlgorithms | ✓ | High | 5.2.15 | SC-8 | — |
| ssh-012 | Set `LogLevel` VERBOSE | ✓ | Medium | 5.2.5 | AU-12 | V-238225 |
| ssh-013 | Disable `IgnoreRhosts` | ✓ | Medium | 5.2.9 | — | — |
| ssh-014 | Set `StrictModes yes` | ✓ | Medium | — | — | — |
| ssh-015 | Disable empty passwords | ✓ | Critical | 5.2.11 | IA-5 | — |
| ssh-016 | Set `MaxSessions` ≤ 10 | 4 | Low | 5.2.20 | — | — |
| ssh-017 | Non-default port (optional) | configurable | Info | — | — | — |

---

## Module: Firewall

**ID:** `firewall`  
**Backends:** UFW (Ubuntu/Debian), firewalld (RHEL/Rocky), nftables (all)

### Checks

| ID | Check | Severity | CIS | NIST |
|---|---|---|---|---|
| fw-001 | Firewall service is enabled and active | Critical | 3.5.1 | SC-7 |
| fw-002 | Default inbound policy: DROP | Critical | 3.5.1.1 | SC-7 |
| fw-003 | Default outbound policy: DROP or ACCEPT (profile-configurable) | High | 3.5.1.2 | SC-7 |
| fw-004 | Loopback traffic explicitly allowed | Medium | 3.5.1.3 | SC-7 |
| fw-005 | No overly permissive rules (0.0.0.0/0 on sensitive ports) | High | 3.5.1.4 | SC-7 |
| fw-006 | IPv6 rules present if IPv6 is enabled | High | 3.5.2 | SC-7 |

---

## Module: Kernel Hardening

**ID:** `kernel`  
**Method:** `/etc/sysctl.d/99-hardbox.conf`

### Network Protection

| ID | sysctl Key | Value | Severity | CIS |
|---|---|---|---|---|
| kn-001 | `net.ipv4.ip_forward` | 0 | High | 3.1.1 |
| kn-002 | `net.ipv4.conf.all.send_redirects` | 0 | Medium | 3.1.2 |
| kn-003 | `net.ipv4.conf.all.accept_source_route` | 0 | High | 3.2.1 |
| kn-004 | `net.ipv4.conf.all.accept_redirects` | 0 | Medium | 3.2.2 |
| kn-005 | `net.ipv4.conf.all.secure_redirects` | 0 | Medium | 3.2.3 |
| kn-006 | `net.ipv4.conf.all.log_martians` | 1 | Medium | 3.2.4 |
| kn-007 | `net.ipv4.icmp_echo_ignore_broadcasts` | 1 | Low | 3.2.5 |
| kn-008 | `net.ipv4.icmp_ignore_bogus_error_responses` | 1 | Low | 3.2.6 |
| kn-009 | `net.ipv4.conf.all.rp_filter` | 1 | Medium | 3.2.7 |
| kn-010 | `net.ipv4.tcp_syncookies` | 1 | High | 3.2.8 |
| kn-011 | `net.ipv6.conf.all.accept_ra` | 0 | Medium | 3.1.2 |

### Memory Protection

| ID | sysctl Key | Value | Severity | NIST |
|---|---|---|---|---|
| km-001 | `kernel.randomize_va_space` | 2 | High | SI-16 |
| km-002 | `kernel.dmesg_restrict` | 1 | Medium | SI-3 |
| km-003 | `kernel.kptr_restrict` | 2 | High | SI-3 |
| km-004 | `kernel.yama.ptrace_scope` | 1 | High | SI-3 |
| km-005 | `fs.protected_hardlinks` | 1 | Medium | AC-3 |
| km-006 | `fs.protected_symlinks` | 1 | Medium | AC-3 |
| km-007 | `fs.suid_dumpable` | 0 | High | AC-6 |
| km-008 | `kernel.core_uses_pid` | 1 | Low | — |

---

## Module: NTP / Time Synchronization

**ID:** `ntp`  
**Method:** `systemctl`, `timedatectl`, `/etc/chrony.conf`

### Checks

| ID | Check | Target | Severity | CIS | NIST |
|---|---|---|---|---|---|
| ntp-001 | Time synchronization service installed | at least one of `chronyd`, `systemd-timesyncd`, `ntpd` | High | 2.2.1 | AU-8 |
| ntp-002 | Only one time synchronization service active | exactly 1 active service | Medium | 2.2.2 | CM-7 |
| ntp-003 | `chrony` `makestep` configured | `makestep 1.0 3` | Low | 2.3.1 | AU-8 |
| ntp-004 | `chrony` `maxdistance` configured | `maxdistance 16.0` | Low | 2.3.2 | AU-8 |
| ntp-005 | Timezone set to UTC | `UTC` (or `Etc/UTC`) | Info | 2.2.3 | AU-8 |

---

## Module: Users & PAM

**ID:** `users`  
**Files:** `/etc/login.defs`, `/etc/pam.d/`, `/etc/security/pwquality.conf`

### Checks

| ID | Check | Severity | CIS | PCI-DSS |
|---|---|---|---|---|
| usr-001 | `PASS_MAX_DAYS` ≤ 90 | High | 5.4.1.1 | 8.3.9 |
| usr-002 | `PASS_MIN_DAYS` ≥ 1 | Medium | 5.4.1.2 | — |
| usr-003 | `PASS_WARN_AGE` ≥ 7 | Low | 5.4.1.3 | — |
| usr-004 | Minimum password length ≥ 14 | High | 5.4.1.4 | 8.3.6 |
| usr-005 | Password complexity: uppercase, lowercase, digit, symbol | High | 5.4.1 | 8.3.6 |
| usr-006 | Password history ≥ 5 | Medium | 5.4.3 | 8.3.7 |
| usr-007 | Account lockout after ≤ 5 failures | High | 5.3.2 | 8.3.4 |
| usr-008 | Lockout duration ≥ 900 seconds | Medium | 5.3.2 | 8.3.4 |
| usr-009 | Root account lockout (PAM pam_faillock) | Critical | 5.6.6 | — |
| usr-010 | No accounts with UID 0 except root | Critical | 5.4.2.1 | — |
| usr-011 | All systems accounts have non-interactive shell | High | 5.4.2.3 | — |
| usr-012 | Sudo: use of sudoers.d for custom rules | Medium | 5.3.6 | — |
| usr-013 | Sudo: `NOPASSWD` not allowed | High | 5.3.5 | — |
| usr-014 | Sudo: `!authenticate` not present | High | 5.3.5 | — |
| usr-015 | `umask` set to 027 or more restrictive | Medium | 5.4.4 | — |
| usr-016 | PATH does not include `.` or writable dirs | High | 5.4.5 | — |
| usr-017 | Inactive accounts disabled after 30 days | Medium | 5.4.1.5 | — |

---

## Module: Filesystem Security

**ID:** `filesystem`  
**Categories:** Mount options, permissions, world-writable files

### Mount Options

| ID | Mount Point | Required Options | Severity | CIS |
|---|---|---|---|---|
| fs-001 | `/tmp` | `nodev,nosuid,noexec` | High | 1.1.2 |
| fs-002 | `/dev/shm` | `nodev,nosuid,noexec` | High | 1.1.6 |
| fs-003 | `/home` | `nodev,nosuid` | Medium | 1.1.10 |
| fs-004 | `/var` | separate partition | Medium | 1.1.12 |
| fs-005 | `/var/log` | separate partition | Medium | 1.1.16 |
| fs-006 | `/var/log/audit` | separate partition | Medium | 1.1.17 |
| fs-007 | `/boot` | `nodev,nosuid,noexec` | Medium | 1.1.3 |

### File Permissions

| ID | Check | Severity | CIS |
|---|---|---|---|
| fs-010 | `/etc/passwd` permissions: 644 | High | 6.1.2 |
| fs-011 | `/etc/shadow` permissions: 640 or 000 | Critical | 6.1.3 |
| fs-012 | `/etc/group` permissions: 644 | High | 6.1.4 |
| fs-013 | `/etc/gshadow` permissions: 640 or 000 | High | 6.1.5 |
| fs-014 | `/etc/passwd-`, `/etc/shadow-` backup perms | Medium | 6.1.6–6.1.9 |
| fs-015 | No world-writable files outside /tmp | High | 6.1.10 |
| fs-016 | No unowned files | High | 6.1.11 |
| fs-017 | No ungrouped files | High | 6.1.12 |
| fs-018 | SUID/SGID executable audit and review | High | 6.1.13 |
| fs-019 | Sticky bit on all world-writable directories | High | 6.1.14 |

---

## Module: Audit Logging (auditd)

**ID:** `auditd`  
**Framework:** Linux Audit Framework + auditd daemon

### Rules Configured

| ID | Category | Events Captured | CIS | STIG |
|---|---|---|---|---|
| aud-001 | System calls | `execve` by non-root users | 4.1.3 | V-238287 |
| aud-002 | File access | Unauthorized access attempts | 4.1.4 | V-238288 |
| aud-003 | User/group changes | `/etc/passwd`, `/etc/shadow`, `/etc/group` modifications | 4.1.5 | V-238289 |
| aud-004 | Sudo usage | All `sudo` invocations | 4.1.6 | V-238290 |
| aud-005 | Login events | `login`, `logout`, `ssh` | 4.1.7 | V-238291 |
| aud-006 | Kernel modules | `insmod`, `rmmod`, `modprobe` | 4.1.16 | V-238292 |
| aud-007 | System admin scope changes | `chown`, `chmod`, `setuid` | 4.1.9 | V-238293 |
| aud-008 | Network configuration changes | `sethostname`, `setdomainname` | 4.1.10 | — |
| aud-009 | Audit log tampering protection | `auditctl -e 2` (immutable) | 4.1.17 | V-238294 |
| aud-010 | auditd config: max log file size | ≥ 8 MB | 4.1.1.1 | — |
| aud-011 | auditd config: action on full | `keep_logs` or `rotate` | 4.1.1.2 | — |
| aud-012 | auditd config: `space_left_action` | `email` or `exec` | 4.1.1.3 | — |
| aud-013 | auditd service enabled and active | — | Critical | 4.1.1 |

---

## Module: Services Hardening

**ID:** `services`  
**Method:** `systemctl disable --now`

### Services Reviewed

| ID | Service | Disable If | Severity | CIS |
|---|---|---|---|---|
| svc-001 | `xinetd` | Always | High | 2.1.1 |
| svc-002 | `inetd` | Always | High | 2.1.2 |
| svc-003 | `avahi-daemon` | Not required for service discovery | Medium | 2.1.3 |
| svc-004 | `cups` | Not a print server | Medium | 2.1.4 |
| svc-005 | `dhcpd` | Not a DHCP server | Medium | 2.1.5 |
| svc-006 | `slapd` | Not an LDAP server | Medium | 2.1.6 |
| svc-007 | `nfs-server` | Not an NFS server | Medium | 2.1.7 |
| svc-008 | `bind` / `named` | Not a DNS server | Medium | 2.1.8 |
| svc-009 | `vsftpd` | Not an FTP server | High | 2.1.9 |
| svc-010 | `httpd` / `apache2` / `nginx` | Not a web server | Medium | 2.1.10 |
| svc-011 | `dovecot` / `sendmail` / `postfix` | Not a mail server | Medium | 2.1.11–12 |
| svc-012 | `samba` | Not a file server | High | 2.1.13 |
| svc-013 | `squid` | Not a proxy | Medium | 2.1.14 |
| svc-014 | `snmpd` | Not using SNMP | High | 2.1.15 |
| svc-015 | `rsync` | Unless required | Medium | 2.1.16 |
| svc-016 | `nis` / `ypbind` | Always | High | 2.1.17 |
| svc-017 | `telnet` | Always | Critical | 2.1.18 |
| svc-018 | `rsh`, `rlogin`, `rcp` | Always | Critical | — |

---

## Module: Network Protocol Hardening

**ID:** `network`

| ID | Check | Severity | CIS |
|---|---|---|---|
| net-001 | IPv6 disabled (if not used) | Medium | 3.1.1 |
| net-002 | DCCP kernel module disabled | Medium | 3.4.1 |
| net-003 | SCTP kernel module disabled | Medium | 3.4.2 |
| net-004 | RDS kernel module disabled | Medium | 3.4.3 |
| net-005 | TIPC kernel module disabled | Medium | 3.4.4 |
| net-006 | Wireless interfaces disabled (server context) | Medium | 3.1.2 |
| net-007 | `hosts.allow` / `hosts.deny` configured (TCP Wrappers) | Low | — |
| net-008 | No `.rhosts` / `.netrc` files in user homes | High | — |

---

## Module: Cryptography

**ID:** `crypto`

| ID | Check | Severity | NIST | PCI |
|---|---|---|---|---|
| cry-001 | System crypto policy set to `DEFAULT` or stronger | High | SC-17 | 4.2.1 |
| cry-002 | TLS 1.0 and 1.1 disabled system-wide | High | SC-8 | 4.2.1 |
| cry-003 | SSLv2/SSLv3 disabled | Critical | SC-8 | 4.2.1 |
| cry-004 | Weak cipher suites removed (RC4, DES, 3DES, export) | Critical | SC-8 | 4.2.1 |
| cry-005 | FIPS 140-2 mode available (optional, for regulated envs) | High | SC-13 | — |
| cry-006 | GnuPG keyid format is long | Low | — | — |

---

## Module: Mandatory Access Control

**ID:** `mac`  
**Backends:** AppArmor (Ubuntu/Debian), SELinux (RHEL/Rocky/Amazon Linux)

| ID | Check | Severity | CIS | STIG |
|---|---|---|---|---|
| mac-001 | AppArmor / SELinux is installed | Critical | 1.6.1 | V-238332 |
| mac-002 | AppArmor / SELinux is enabled at boot | Critical | 1.6.2 | V-238333 |
| mac-003 | All profiles/policies are in enforcing mode | High | 1.6.3 | V-238334 |
| mac-004 | No unconfined processes (AppArmor) | High | 1.6.4 | — |
| mac-005 | SELinux policy type is `targeted` or `mls` | High | — | V-238335 |

---

## Module: System Logging

**ID:** `logging`  
**Components:** rsyslog, systemd-journald

| ID | Check | Severity | CIS |
|---|---|---|---|
| log-001 | rsyslog or syslog-ng installed and active | High | 4.2.1.1 |
| log-002 | rsyslog configured to send logs to remote server | Medium | 4.2.1.5 |
| log-003 | rsyslog file permissions restricted | Medium | 4.2.1.3 |
| log-004 | journald persistent storage enabled | Medium | 4.2.2.1 |
| log-005 | journald sending to rsyslog | Medium | 4.2.2.2 |
| log-006 | `logrotate` configured for all logs | Medium | 4.2.3 |
| log-007 | Log files not world-readable | High | 4.2.4 |

---

## Module: Time Synchronization

**ID:** `ntp`  
**Backends:** chrony (recommended), systemd-timesyncd, ntpd

| ID | Check | Severity | CIS | PCI |
|---|---|---|---|---|
| ntp-001 | Time synchronization service installed | High | 2.1.1.1 | 10.6.1 |
| ntp-002 | Only one time sync service active | Medium | 2.1.1.3 | — |
| ntp-003 | chrony: `makestep` configured | Low | 2.1.1.2 | — |
| ntp-004 | chrony: `maxdistance` configured | Low | — | — |
| ntp-005 | Time zone set to UTC (recommended for cloud servers) | Info | — | — |

---

## Module: Automatic Updates

**ID:** `updates`

| ID | Check | Severity | CIS | NIST |
|---|---|---|---|---|
| upd-001 | Package manager GPG keys configured | Critical | 1.2.1 | SI-2 |
| upd-002 | Security updates repository enabled | High | 1.2.2 | SI-2 |
| upd-003 | Unattended security upgrades configured | High | 1.9 | SI-2 |
| upd-004 | Auto-reboot after kernel updates (configurable) | Medium | — | — |
| upd-005 | `apt-get update` via local mirror (optional) | Info | — | — |

---

## Module: Container Host Hardening

**ID:** `containers`  
**Scope:** Docker daemon, Podman, container runtime security  
**Reference:** CIS Docker Benchmark v1.6

| ID | Check | Severity | CIS Docker |
|---|---|---|---|
| cnt-001 | Docker daemon not running as root (rootless mode) | High | 1.1.2 |
| cnt-002 | `--icc=false` (disable inter-container communication) | Medium | 2.1 |
| cnt-003 | `--userns-remap` enabled | High | 2.8 |
| cnt-004 | Docker daemon TLS enabled (if remote API) | Critical | 2.6 |
| cnt-005 | Seccomp default profile enabled | High | 5.22 |
| cnt-006 | AppArmor/SELinux profile applied to containers | High | 5.1 |
| cnt-007 | No `--privileged` flag in production containers | Critical | 5.4 |
| cnt-008 | Docker socket not mounted in containers | Critical | 5.31 |
| cnt-009 | Container images scanned (advisory) | High | — |
| cnt-010 | Audit rules for Docker daemon socket | Medium | 1.2.1 |

---

## Module: Mount & Partition Hardening

**ID:** `mount`
**Method:** `/proc/mounts`, `/etc/modprobe.d/hardbox.conf`

### Partition Checks

| ID | Check | Required | Severity | CIS | STIG |
|---|---|---|---|---|---|
| mnt-001 | `/tmp` on a dedicated partition | separate partition | High | 1.1.2 | V-238149 |
| mnt-002 | `/var` on a dedicated partition | separate partition | Medium | 1.1.6 | — |
| mnt-003 | `/var/tmp` on a dedicated partition | separate partition | Medium | 1.1.7 | V-238149 |
| mnt-004 | `/var/log` on a dedicated partition | separate partition | Medium | 1.1.11 | — |
| mnt-005 | `/var/log/audit` on a dedicated partition | separate partition | Medium | 1.1.12 | — |
| mnt-006 | `/home` on a dedicated partition | separate partition | Medium | 1.1.14 | — |
| mnt-007 | `/dev/shm` mounted with `nodev,nosuid,noexec` | required options | High | 1.1.8 | — |
| mnt-008 | `/tmp` mounted with `nodev,nosuid,noexec` | required options | High | 1.1.3 | — |
| mnt-009 | Sticky bit set on all world-writable directories | mode 1xxx | High | 1.1.18 | — |

### Kernel Module Blacklist

| ID | Module | Reason | Severity | CIS |
|---|---|---|---|---|
| mnt-010 | `cramfs` | Obsolete filesystem — no legitimate use on servers | Medium | 1.1.1.1 |
| mnt-011 | `squashfs` | Unneeded compressed filesystem | Medium | 1.1.1.2 |
| mnt-012 | `udf` | Uncommon optical filesystem | Medium | 1.1.1.3 |
| mnt-013 | `usb-storage` | Prevent unauthorized USB mass storage | High | 1.1.1.4 |
| mnt-014 | `freevxfs` | Obsolete filesystem | Low | 1.1.1.5 |
| mnt-015 | `jffs2` | Flash filesystem — no use on servers | Low | 1.1.1.6 |

**Remediation:** Blacklist entries are written to `/etc/modprobe.d/hardbox.conf`.
