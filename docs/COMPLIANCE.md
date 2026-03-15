# hardbox — Compliance Framework Reference

hardbox maps every hardening check to one or more compliance framework controls.
This document is the authoritative cross-reference index.

> **How to read this table:** Each row is a hardbox check ID. The columns show the
> corresponding control identifiers in each framework. "—" means the control has no
> direct equivalent in that framework for this check.

---

## Framework Abbreviations

| Abbreviation | Framework | Version |
|---|---|---|
| **CIS** | CIS Benchmarks (Ubuntu 22.04 LTS) | v1.0.0 |
| **NIST** | NIST SP 800-53 Security Controls | Rev. 5 |
| **STIG** | DoD STIG for Red Hat / Ubuntu | V1R1 |
| **PCI** | PCI-DSS | v4.0 |
| **HIPAA** | HIPAA Security Rule | 45 CFR Part 164 |
| **ISO** | ISO/IEC 27001:2022 | Annex A |

---

## SSH Module

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| ssh-001 | Disable root login | 5.2.8 | AC-6 | V-238218 | 7.2.1 | 164.312(a)(1) | A.9.4.4 |
| ssh-002 | Disable password auth | 5.2.12 | IA-5 | V-238219 | 8.3.1 | 164.312(d) | A.9.4.3 |
| ssh-003 | MaxAuthTries ≤ 4 | 5.2.7 | AC-7 | V-238220 | 8.3.4 | 164.312(a)(2)(iii) | A.9.4.2 |
| ssh-004 | LoginGraceTime ≤ 60s | 5.2.16 | AC-2 | — | — | — | A.9.4.2 |
| ssh-005 | Disable X11 forwarding | 5.2.6 | — | V-238222 | — | — | A.13.1.2 |
| ssh-007 | ClientAlive timeout | 5.2.16 | SC-10 | V-238233 | 8.2.8 | 164.312(a)(2)(iii) | A.9.4.2 |
| ssh-009 | Strong ciphers only | 5.2.14 | SC-8 | V-238234 | 4.2.1 | 164.312(e)(2)(ii) | A.14.1.3 |
| ssh-010 | Strong MACs only | 5.2.15 | SC-8 | V-238235 | 4.2.1 | 164.312(e)(2)(ii) | A.14.1.3 |
| ssh-012 | LogLevel VERBOSE | 5.2.5 | AU-12 | V-238225 | 10.2.2 | 164.312(b) | A.12.4.1 |
| ssh-015 | Disable empty passwords | 5.2.11 | IA-5 | — | 8.3.6 | 164.312(d) | A.9.4.3 |

---

## Firewall Module

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| fw-001 | Firewall enabled | 3.5.1 | SC-7 | V-238270 | 1.3.1 | 164.312(e)(1) | A.13.1.1 |
| fw-002 | Default inbound DROP | 3.5.1.1 | SC-7 | V-238270 | 1.3.2 | 164.312(e)(1) | A.13.1.1 |
| fw-003 | Default outbound DROP or ACCEPT | 3.5.1.2 | SC-7 | — | 1.3.3 | 164.312(e)(1) | A.13.1.1 |
| fw-004 | Loopback traffic explicitly allowed | 3.5.1.3 | SC-7 | — | 1.3.2 | 164.312(e)(1) | A.13.1.1 |
| fw-005 | No overly permissive rules | 3.5.1.4 | SC-7 | — | 1.3.4 | 164.312(e)(1) | A.13.1.1 |
| fw-006 | IPv6 rules present when IPv6 enabled | 3.5.2 | SC-7 | — | 1.3.1 | 164.312(e)(1) | A.13.1.1 |

---

## Kernel Module

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| kn-001 | No IP forwarding | 3.1.1 | CM-7 | V-238327 | 1.3.3 | — | A.13.1.3 |
| kn-004 | No ICMP redirects | 3.2.2 | SC-5 | V-238328 | — | — | A.13.1.3 |
| kn-006 | Log martian packets | 3.2.4 | AU-12 | — | 10.6.1 | 164.312(b) | A.12.4.1 |
| kn-010 | TCP SYN cookies | 3.2.8 | SC-5 | V-238329 | 6.3.3 | — | A.13.1.3 |
| km-001 | ASLR enabled (RVSA=2) | — | SI-16 | V-238296 | 6.3.3 | — | A.14.2.5 |
| km-002 | dmesg restricted | — | SI-3 | — | — | — | A.14.2.5 |
| km-003 | kptr restricted | — | SI-3 | V-238297 | — | — | A.14.2.5 |
| km-004 | ptrace scope 1 | — | SI-3 | — | — | — | A.14.2.5 |
| km-007 | No SUID core dumps | — | AC-6 | V-238298 | — | — | A.9.4.1 |

---

## Network Protocol Hardening Module

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| net-001 | IPv6 disabled if not used | 3.1.1 | CM-7 | — | 1.3.1 | — | A.13.1.1 |
| net-002 | DCCP kernel module blacklisted | 3.4.1 | CM-7 | — | 2.2.4 | — | A.13.1.1 |
| net-003 | SCTP kernel module blacklisted | 3.4.2 | CM-7 | — | 2.2.4 | — | A.13.1.1 |
| net-004 | RDS kernel module blacklisted | 3.4.3 | CM-7 | — | 2.2.4 | — | A.13.1.1 |
| net-005 | TIPC kernel module blacklisted | 3.4.4 | CM-7 | — | 2.2.4 | — | A.13.1.1 |
| net-006 | Wireless interfaces disabled | 3.1.2 | CM-7 | — | 2.2.1 | — | A.13.1.1 |
| net-007 | hosts.allow / hosts.deny configured | — | AC-4 | — | — | — | A.13.1.1 |
| net-008 | No .rhosts / .netrc files in home dirs | — | AC-6 | — | 2.2.2 | — | A.9.4.4 |

---

## NTP Module

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| ntp-001 | Time sync service installed | 2.2.1 | AU-8 | — | 10.4.1 | 164.312(b) | A.8.16 |
| ntp-002 | Single active time sync service | 2.2.2 | CM-7 | — | 2.2.1 | — | A.8.9 |
| ntp-003 | chrony makestep configured | 2.3.1 | AU-8 | — | 10.4.1 | 164.312(b) | A.8.17 |
| ntp-004 | chrony maxdistance configured | 2.3.2 | AU-8 | — | 10.4.1 | 164.312(b) | A.8.17 |
| ntp-005 | Timezone set to UTC | 2.2.3 | AU-8 | — | 10.4.1 | 164.312(b) | A.8.16 |

---

## Automatic Updates Module

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| upd-001 | Package manager GPG keys configured | 1.2.1 | SI-2 | — | 6.3.3 | — | A.12.6.1 |
| upd-002 | Security updates repository enabled | 1.2.2 | SI-2 | — | 6.3.3 | — | A.12.6.1 |
| upd-003 | Unattended security upgrades configured | 1.9 | SI-2 | — | 6.3.3 | — | A.12.6.1 |
| upd-004 | Auto-reboot after kernel updates (configurable) | — | SI-2 | — | — | — | — |
| upd-005 | apt-get update via local mirror (optional) | — | — | — | — | — | — |

---

## Users & PAM Module

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| usr-001 | Password max age ≤ 90d | 5.4.1.1 | IA-5 | V-238218 | 8.3.9 | 164.312(d) | A.9.4.3 |
| usr-002 | Password min age ≥ 1d | 5.4.1.2 | IA-5 | — | — | — | A.9.4.3 |
| usr-003 | Password warning age ≥ 7d | 5.4.1.3 | IA-5 | — | — | — | A.9.4.3 |
| usr-004 | Password min length ≥ 14 | 5.4.1.4 | IA-5 | V-238349 | 8.3.6 | 164.312(d) | A.9.4.3 |
| usr-005 | PAM password complexity | 5.4.1 | IA-5 | V-238349 | 8.3.6 | 164.312(d) | A.9.4.3 |
| usr-006 | PAM password history ≥ 5 | 5.4.3 | IA-5 | — | — | — | A.9.4.3 |
| usr-007 | PAM lockout ≤ 5 attempts | 5.3.2 | AC-7 | V-238351 | 8.3.4 | 164.312(a)(2)(iii) | A.9.4.2 |
| usr-008 | PAM unlock time ≥ 900s | 5.3.3 | AC-7 | — | — | — | A.9.4.2 |
| usr-009 | PAM root lockout enabled | 5.6.6 | AC-7 | — | — | — | A.9.4.4 |
| usr-010 | Only root has UID 0 | 5.4.2.1 | AC-6 | V-238218 | 7.2.1 | 164.312(a)(1) | A.9.4.4 |
| usr-011 | No interactive shell for system accounts | 5.4.2.2 | AC-6 | V-238220 | — | — | A.9.4.4 |
| usr-012 | sudoers includes sudoers.d | 5.3.1 | CM-6 | — | — | — | A.9.4.4 |
| usr-013 | No sudo NOPASSWD | 5.3.5 | AC-6 | V-238352 | 7.2.1 | 164.312(a)(1) | A.9.4.4 |
| usr-014 | No sudo !authenticate | 5.3.6 | AC-6 | — | — | — | A.9.4.4 |
| usr-015 | Default umask ≤ 027 | 5.4.4 | AC-3 | V-238327 | — | — | A.9.4.1 |
| usr-016 | PATH does not contain '.' | 5.4.5 | CM-6 | — | — | — | A.9.4.5 |
| usr-017 | Inactive account expiry ≤ 30d | 5.4.1.5 | AC-2 | V-238229 | 8.1.4 | 164.312(a)(1) | A.9.2.5 |

---

## Filesystem Module

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| fs-001 | /tmp nodev,nosuid,noexec | 1.1.2 | CM-7 | V-238306 | 5.2.5 | — | A.14.2.5 |
| fs-002 | /dev/shm hardened | 1.1.6 | CM-7 | V-238307 | 5.2.5 | — | A.14.2.5 |
| fs-011 | /etc/shadow 640 | 6.1.3 | AC-3 | V-238316 | 7.2.4 | 164.312(a)(1) | A.9.4.1 |
| fs-015 | No world-writable files | 6.1.10 | AC-3 | V-238319 | 7.2.4 | — | A.9.4.1 |
| fs-018 | SUID/SGID audit | 6.1.13 | AC-6 | — | 7.2.1 | — | A.9.4.4 |

---

## Audit Logging Module

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| aud-001 | Log execve | 4.1.3 | AU-12 | V-238287 | 10.3.1 | 164.312(b) | A.12.4.1 |
| aud-003 | Log user/group changes | 4.1.5 | AU-12 | V-238289 | 10.3.1 | 164.312(b) | A.12.4.1 |
| aud-004 | Log sudo usage | 4.1.6 | AU-12 | V-238290 | 10.2.5 | 164.312(b) | A.12.4.1 |
| aud-005 | Log login events | 4.1.7 | AU-12 | V-238291 | 10.2.1 | 164.312(b) | A.12.4.1 |
| aud-009 | Audit log tamper protection | 4.1.17 | AU-9 | V-238294 | 10.3.3 | 164.312(b) | A.12.4.2 |
| aud-013 | auditd active | 4.1.1 | AU-12 | V-238276 | 10.5.1 | 164.312(b) | A.12.4.1 |

---

## Services Module

| Check ID | Title | CIS | NIST | STIG | PCI |
|---|---|---|---|---|---|
| svc-017 | Telnet disabled | 2.1.18 | CM-7 | V-238241 | 2.2.1 |
| svc-018 | rsh/rlogin disabled | — | CM-7 | V-238242 | 2.2.1 |
| svc-009 | FTP (vsftpd) disabled | 2.1.9 | CM-7 | V-238243 | 2.2.1 |
| svc-014 | SNMP disabled | 2.1.15 | CM-7 | — | 2.2.1 |

---

## Cryptography Module

| Check ID | Title | CIS | NIST | PCI | HIPAA |
|---|---|---|---|---|---|
| cry-001 | System crypto policy DEFAULT or stronger | — | SC-17 | 4.2.1 | 164.312(e)(2)(ii) |
| cry-002 | TLS 1.0/1.1 disabled | — | SC-8 | 4.2.1 | 164.312(e)(2)(ii) |
| cry-003 | SSLv2/v3 disabled | — | SC-8 | 4.2.1 | 164.312(e)(2)(ii) |
| cry-004 | Weak ciphers removed | — | SC-8 | 4.2.1 | 164.312(e)(2)(ii) |
| cry-005 | FIPS 140-2 mode | — | SC-13 | — | 164.312(a)(2)(iv) |
| cry-006 | GnuPG keyid format long | — | — | — | — |

---

## Containers Module

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| cnt-001 | Docker daemon runs in rootless mode | 2.1 | CM-6 | — | — | — | A.14.2.5 |
| cnt-002 | Inter-container communication disabled | 2.1 | SC-7 | — | 1.3.2 | — | A.13.1.1 |
| cnt-003 | User namespace remapping enabled | 2.8 | AC-6 | — | — | — | A.9.4.1 |
| cnt-004 | Docker remote API protected by TLS | 2.6 | SC-8 | — | 4.2.1 | 164.312(e)(2)(ii) | A.14.1.3 |
| cnt-005 | Default seccomp profile applied | 5.21 | SI-3 | — | — | — | A.14.2.5 |
| cnt-006 | AppArmor or SELinux profile active | 5.25 | AC-3 | V-235805 | — | — | A.9.4.5 |
| cnt-007 | No running containers with --privileged | 5.4 | AC-6 | — | 2.2.1 | — | A.9.4.1 |
| cnt-008 | Docker socket not mounted in containers | 5.31 | AC-3 | — | — | — | A.9.4.1 |
| cnt-009 | Container images scanned for CVEs | 5.1 | RA-5 | — | 6.3.3 | — | A.12.6.1 |
| cnt-010 | Audit rules for Docker daemon socket | 1.1.18 | AU-12 | — | 10.2.5 | 164.312(b) | A.12.4.1 |

---

## Mandatory Access Control

| Check ID | Title | CIS | NIST | STIG | ISO |
|---|---|---|---|---|---|
| mac-001 | AppArmor/SELinux installed | 1.6.1 | AC-3 | V-238332 | A.9.4.5 |
| mac-002 | Enabled at boot | 1.6.2 | AC-3 | V-238333 | A.9.4.5 |
| mac-003 | Enforcing mode | 1.6.3 | AC-3 | V-238334 | A.9.4.5 |
| mac-004 | No unconfined processes (AppArmor) | 1.6.4 | AC-3 | — | A.9.4.5 |
| mac-005 | SELinux policy type targeted or mls | — | AC-3 | V-238335 | A.9.4.5 |

---

## Auditd Module (Linux Audit Framework)

| Check ID | Title | CIS | NIST | STIG | PCI |
|---|---|---|---|---|---|
| aud-001 | execve syscall auditing by non-root | 4.1.3 | AU-12 | — | 10.2.7 |
| aud-002 | Unauthorized file access attempts audited | 4.1.5 | AU-12 | V-238285 | — |
| aud-003 | User/group identity file modifications audited | 4.1.6 | AU-12 | V-238286 | — |
| aud-004 | sudo usage logging | 4.1.11 | AU-12 | — | 10.2.5 |
| aud-005 | Login/logout/SSH events audited | 4.1.8 | AC-17 | — | 10.2.4 |
| aud-006 | Kernel module loading audited | 4.1.17 | CM-7 | V-238289 | — |
| aud-007 | chown/chmod/setuid operations audited | 4.1.7 | AU-12 | V-238287 | — |
| aud-008 | Network config changes audited | 4.1.16 | AU-12 | — | — |
| aud-009 | Audit log immutability enabled | 4.1.18 | AU-9 | V-238291 | 10.5.2 |
| aud-010 | Audit log file size configured | 4.1.1.1 | AU-11 | — | 10.7.1 |
| aud-011 | Audit log full action configured | 4.1.1.2 | AU-5 | — | 10.7.1 |
| aud-012 | Audit space_left_action configured | 4.1.1.3 | AU-5 | — | — |
| aud-013 | auditd service enabled and active | 4.1.1 | AU-12 | V-238283 | 10.6.3 |

---

## System Logging Module (rsyslog / journald)

| Check ID | Title | CIS | NIST | STIG | PCI | HIPAA | ISO |
|---|---|---|---|---|---|---|---|
| log-001 | Syslog service installed and active | 4.2.1.1 | AU-9 | — | 10.5.3 | — | A.12.4.1 |
| log-002 | Rsyslog forwards logs to remote server | 4.2.1.5 | AU-4 | — | 10.5.3 | 164.312(b) | A.12.4.1 |
| log-003 | Rsyslog config file permissions restricted | 4.2.1.4 | AU-9 | — | — | — | A.12.4.2 |
| log-004 | Journald persistent storage enabled | 4.2.2.1 | AU-11 | — | — | — | A.12.4.1 |
| log-005 | Journald forwarding to syslog enabled | 4.2.2.2 | AU-12 | — | — | — | A.12.4.1 |
| log-006 | Logrotate configured for all logs | 4.2.3 | AU-11 | — | 10.7.1 | — | A.12.4.1 |
| log-007 | Log files not world-readable | 4.2.1.3 | AU-9 | V-238302 | — | 164.312(b) | A.12.4.2 |

---

## Profile → Framework Coverage Matrix

This table shows which compliance frameworks each built-in profile satisfies.

| Profile | CIS L1 | CIS L2 | STIG | PCI-DSS | HIPAA | NIST 800-53 | ISO 27001 |
|---|---|---|---|---|---|---|---|
| `cis-level1` | ✓ Full | — | Partial | Partial | Partial | Partial | Partial |
| `cis-level2` | ✓ Full | ✓ Full | Partial | Partial | Partial | Partial | Partial |
| `stig` | ✓ Full | ✓ Full | ✓ Full | Partial | Partial | ✓ Full | Partial |
| `pci-dss` | ✓ Full | ✓ Full | Partial | ✓ Full | Partial | Partial | Partial |
| `hipaa` | ✓ Full | ✓ Full | Partial | Partial | ✓ Full | Partial | Partial |
| `nist-800-53` | ✓ Full | ✓ Full | ✓ Full | Partial | Partial | ✓ Full | Partial |
| `iso27001` | ✓ Full | ✓ Full | Partial | Partial | Partial | Partial | ✓ Full |
| `production` | ✓ Full | Partial | Partial | Partial | Partial | Partial | Partial |
| `development` | Partial | — | — | — | — | — | — |

> **Partial** = significant coverage with some controls requiring manual evidence or configuration beyond OS-level hardening (e.g., application-layer controls, physical security).

---

## Generating a Compliance Report

```bash
# Full compliance audit against PCI-DSS profile
sudo hardbox audit --profile pci-dss --format html --output pci-audit.html

# JSON output for SIEM/GRC tool import
sudo hardbox audit --profile cis-level2 --format json --output cis-audit.json

# Fail CI/CD pipeline if critical findings exist
sudo hardbox audit --profile production --format json
# exits 1 if audit.fail_on_critical = true and critical findings found
```
