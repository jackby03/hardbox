<div align="center">

<img src=".github/assets/hardbox-logo.png" alt="hardbox logo" width="100%" />

**The definitive Linux hardening toolkit for IT, Cloud, Infrastructure, and Security teams.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white)](go.mod)
[![CIS Benchmarks](https://img.shields.io/badge/CIS-Level%201%20%26%202-2563EB?style=flat-square)](docs/COMPLIANCE.md)
[![Build](https://img.shields.io/github/actions/workflow/status/jackby03/hardbox/ci.yaml?style=flat-square&label=CI)](https://github.com/jackby03/hardbox/actions)
[![Platforms](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian%20%7C%20RHEL%20%7C%20Rocky%20%7C%20Amazon%20Linux-475569?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![Code of Conduct](https://img.shields.io/badge/conduct-Contributor%20Covenant-5865F2?style=flat-square)](CODE_OF_CONDUCT.md)
[![ACS compatible](https://img.shields.io/badge/ACS-compatible%20v1.0-4CAF50?style=flat-square)](https://acs.jackby03.com)


</div>

---

## What is hardbox?

**hardbox** is an open-source, TUI-driven Linux server hardening toolkit designed for modern infrastructure teams. It transforms the complex, error-prone process of securing Linux servers into a **guided, auditable, and repeatable workflow** — whether you're locking down a cloud VM, a bare-metal server, a Kubernetes node, or a developer workstation.

It covers every layer of the security stack: kernel parameters, SSH, firewall, PAM, filesystem permissions, audit logging, cryptography, service hardening, and full compliance mapping against industry frameworks (CIS, NIST, STIG, PCI-DSS, ISO 27001).

---

## Why hardbox?

| Pain Point | hardbox Solution |
|:---|:---|
| Hardening is manual, slow, and inconsistent | Automated modules with dry-run and rollback |
| Scripts break across distros | Distro-aware engine with a unified API |
| No visibility into what was changed | Full audit trail + structured HTML/JSON reports |
| Compliance frameworks are overwhelming | Built-in profiles: CIS L1, production, dev (more on roadmap) |
| Requires deep security expertise | Modern TUI — zero expertise needed to start |
| Cloud environments have unique requirements | Cloud-native profiles for AWS, GCP, Azure (roadmap) |

---

## Key Features

| Feature | Description |
|:---|:---|
| **Modern TUI** | Interactive terminal UI (Bubble Tea). Navigate, configure, and apply hardening without memorizing commands |
| **Modular Architecture** | Enable or disable any module independently. Mix and match profiles at will |
| **3 Built-in Profiles** | `cis-level1`, `production`, `development` — more profiles on roadmap |
| **Dry Run Mode** | Preview every exact change before it's applied. Safe to run on live servers |
| **One-command Rollback** | Every change is snapshotted. Revert any module or an entire session instantly |
| **Audit Reports** | JSON, HTML, and Markdown output — machine-readable and CI/CD-friendly |
| **Compliance Mapping** | 100+ checks mapped to CIS, NIST 800-53, STIG, PCI-DSS, HIPAA, and ISO 27001 |
| **Headless / CI Mode** | Unattended runs via config file — Ansible, Terraform, cloud-init, GitHub Actions |
| **Distro-aware** | Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux, Amazon Linux, Fedora |

---

## Quick Start

### Install

```bash
# One-liner installer (Linux, requires sudo)
curl -sSL https://hardbox.jackby03.com/install.sh | bash

# Or download a pre-built binary from GitHub Releases
# https://github.com/jackby03/hardbox/releases
```

### Usage

```bash
# Launch the interactive TUI
sudo hardbox

# Audit your system — no changes made
sudo hardbox audit --profile cis-level1 --format html --output ~/audit.html

# Preview all changes before applying (dry run)
sudo hardbox apply --profile production --dry-run

# Apply hardening and generate a report
sudo hardbox apply --profile production --report ./hardbox-$(date +%Y%m%d).html

# Headless / CI-CD mode
sudo hardbox apply --config /etc/hardbox/config.yaml --non-interactive

# Rollback the last session
sudo hardbox rollback --last
```

---

<!--
## Preview

> Screenshot coming soon.

---
-->

## Hardening Modules

| Module | Description | Controls Covered |
|---|---|---|
| **SSH** | SSH daemon configuration, key management, port hardening | CIS 5.2, STIG SSH |
| **Firewall** | UFW / nftables / firewalld — allowlist-based rules | CIS 3.5, NIST SC-7 |
| **Kernel** | sysctl network, memory, and filesystem protections | CIS 3.1–3.3, STIG |
| **Users & PAM** | Password policy, account lockout, sudo, privilege review | CIS 5.3–5.6, PCI 8 |
| **Filesystem** | Partition options, /tmp, SUID/SGID audit, world-writable | CIS 1.1, NIST SC-28 |
| **Audit Logging** | auditd rules covering all STIG/CIS required audit events | CIS 4.1, NIST AU-12 |
| **Services** | Disable unnecessary services, inetd, xinetd, avahi, cups | CIS 2.1–2.2 |
| **Network** | IPv6, uncommon protocols, broadcast, redirects, spoofing | CIS 3.1–3.4 |
| **Cryptography** | TLS versions, cipher suites, FIPS mode, entropy | NIST SC-17 |
| **Logging** | rsyslog / journald — remote logging, log integrity, rotation | CIS 4.2, NIST AU |
| **AppArmor/SELinux** | Mandatory Access Control policy enforcement | CIS 1.6, STIG |
| **Time (NTP/chrony)** | Time synchronization and integrity for audit trails | CIS 2.2.1, PCI 10.6 |
| **Updates** | Unattended upgrades, security repos, version pinning | CIS 1.9, NIST SI-2 |
| **Containers** | Docker/Podman daemon hardening, seccomp, namespace isolation | CIS Docker Benchmark |

---

## Compliance Profiles

### Available now

<div align="center">

| Profile | Framework | Best For |
|:---:|:---|:---|
| `cis-level1` | CIS Benchmarks Level 1 | Minimum baseline — low disruption |
| `production` | hardbox curated | Cloud production servers |
| `development` | hardbox curated | Dev/staging — security + developer usability |

</div>

### Roadmap — coming in future releases

<div align="center">

| Profile | Framework | Target Release |
|:---:|:---|:---:|
| `cis-level2` | CIS Benchmarks Level 2 | v0.2 |
| `stig` | DoD STIG | v0.2 |
| `pci-dss` | PCI-DSS v4.0 | v0.2 |
| `hipaa` | HIPAA Security Rule | v0.3 |
| `nist-800-53` | NIST SP 800-53 Rev. 5 | v0.3 |
| `iso27001` | ISO/IEC 27001:2022 | v0.3 |
| `cloud-aws` | hardbox + CIS | v0.3 |
| `cloud-gcp` | hardbox + CIS | v0.3 |
| `cloud-azure` | hardbox + CIS | v0.3 |

</div>

---

## Supported Platforms

<div align="center">

| Distribution | Versions | Cloud |
|:---:|:---:|:---|
| Ubuntu | 20.04 · 22.04 · 24.04 LTS | AWS · GCP · Azure · DigitalOcean |
| Debian | 11 · 12 | ✓ |
| RHEL / CentOS Stream | 8 · 9 | ✓ |
| Rocky Linux | 8 · 9 | ✓ |
| AlmaLinux | 8 · 9 | ✓ |
| Amazon Linux | 2 · 2023 | AWS |
| Fedora | 39 · 40 | ✓ |

</div>

---

## Architecture

<div align="center">
  <img src=".github/assets/architecture.png" alt="hardbox architecture diagram" width="100%" />
</div>

---

## Roadmap

### v0.1 — Foundation
- [ ] Core engine with dry-run and rollback
- [ ] SSH, Firewall, Kernel, Users/PAM modules
- [ ] CIS Level 1 & 2 profiles
- [ ] TUI dashboard + module navigator
- [ ] JSON audit reports

### v0.2 — Coverage
- [ ] All 14 hardening modules
- [ ] STIG and PCI-DSS profiles
- [ ] HTML and Markdown reports
- [ ] Ubuntu, Debian, RHEL, Rocky support

### v0.3 — Ecosystem
- [ ] Headless/CI mode
- [ ] Ansible role integration
- [ ] Terraform provisioner
- [ ] cloud-init support
- [ ] GitHub Actions workflow

### v1.0 — Production Ready
- [ ] Full compliance framework coverage
- [ ] Plugin SDK for custom modules
- [ ] Remote fleet hardening (SSH agent)
- [ ] Web dashboard (optional)
- [ ] Enterprise profile management

---

## Contributing

hardbox is open source and community-driven. Contributions of all kinds are welcome — bug reports, new modules, profile improvements, and documentation.

```bash
git clone https://github.com/jackby03/hardbox
cd hardbox
go mod download
go build ./...
sudo go run ./cmd/hardbox
```

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.  
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines, module development guide, and test conventions.

---

## Support the Project

If hardbox saves you time or helps keep your infrastructure secure, consider supporting its development:

<div align="center">

<a href="https://ko-fi.com/jackby03"><img src="https://img.shields.io/badge/Ko--fi-Support_on_Ko--fi-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white" alt="Ko-fi" /></a>
&nbsp;
<a href="https://publishers.basicattentiontoken.org/en/c/jackby03"><img src="https://img.shields.io/badge/BAT-Brave_Rewards-FB542B?style=for-the-badge&logo=brave&logoColor=white" alt="BAT" /></a>

</div>

---

## License

[MIT License](LICENSE) — free for personal, commercial, and government use.

---

<div align="center">

**Built for the engineers who know that security is not a feature — it's a foundation.**

</div>
