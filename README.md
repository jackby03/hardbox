<div align="center">

**Audit, harden, and monitor Linux servers — guided, automated, auditable.**

[![Pre-release](https://img.shields.io/github/v/release/jackby03/hardbox?display_name=tag&include_prereleases&sort=semver&style=flat-square&label=pre-release&color=3b82f6)](https://github.com/jackby03/hardbox/releases)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPLv3-blue.svg?style=flat-square)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white)](go.mod)
[![Build](https://img.shields.io/github/actions/workflow/status/jackby03/hardbox/quality-gates.yaml?style=flat-square&label=quality)](https://github.com/jackby03/hardbox/actions)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

</div>

---

## What is hardbox?

**hardbox** is an open-source CLI toolkit that transforms Linux server hardening into a guided, auditable, and repeatable workflow. Audit your system against industry benchmarks, preview every change, apply hardening automatically, and roll back if needed — all from the command line.

**21 hardening modules. 12 compliance profiles. 200+ checks. 7 Linux distros.**

---

## Quick Start

```bash
# Install
curl -fsSL https://hardbox.jackby03.com/install.sh | bash

# Audit — no changes made
sudo hardbox audit --profile cis-level1 --format html -o audit.html

# Preview changes before applying
sudo hardbox apply --profile production --dry-run

# Apply hardening with rollback safety
sudo hardbox apply --profile production

# CI / headless mode
sudo hardbox apply --config /etc/hardbox/config.yaml --non-interactive

# Compare two audit reports, fail on regressions
hardbox diff before.json after.json
```

See the full command reference: `hardbox --help`

---

## Features

| Category | Capabilities |
|---|---|
| **Hardening** | 21 modules: SSH, firewall, kernel, users, filesystem, auditd, crypto, AppArmor/SELinux, NTP, updates, containers, boot, storage, integrity, malware, shells, processes, and more |
| **Compliance** | 12 built-in profiles: CIS L1/L2, STIG, PCI-DSS, HIPAA, NIST 800-53, ISO 27001, cloud-aws/gcp/azure, production, development |
| **Safety** | Dry-run mode, atomic file writes, one-command rollback, snapshot/restore |
| **Reports** | JSON, HTML, Markdown, Text, SARIF — CI/CD-friendly and human-readable |
| **Operations** | `hardbox watch` daemon, `hardbox fleet` multi-host over SSH, `hardbox serve` web dashboard, `hardbox diff` audit comparison |
| **Integrations** | Ansible role, Terraform provider, cloud-init templates, Slack/HTTP webhook alerts |
| **Platforms** | Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux, Amazon Linux, Fedora |
| **Extensibility** | Plugin SDK for custom modules, YAML-based profiles with `extends` inheritance |

> Full module reference: [`docs/MODULES.md`](docs/MODULES.md) | Compliance mappings: [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md)

---

## Architecture

<div align="center">
  <img src=".github/assets/architecture.png" alt="hardbox architecture diagram" width="100%" />
</div>

---

## Roadmap

| Version | What shipped |
|---|---|
| v0.4 ✅ | Core engine, 15 modules, 12 profiles, fleet, diff, serve, plugin SDK |
| v0.5 ✅ | Watch daemon, Slack/webhook alerts, SARIF export, profile inheritance, fleet dashboard, trend sparklines |
| v0.6 ✅ | 6 new modules (boot, storage, integrity, malware, shells, processes) — 21 total, all with remediation |
| v0.7 | 4 modules: hardware (USB/bluetooth), nameservices (DNS), webserver (Apache/nginx), databases (MySQL/PG) |
| v0.8 | Custom YAML checks, compliance PDFs, native .deb/.rpm, plugin SDK freeze, full docs |
| v1.0 | 300+ checks, 25+ modules, GA stable release |

Full roadmap with SaaS/enterprise deferrals: [`docs/ROADMAP.md`](docs/ROADMAP.md)

---

## Operations

| Resource | Link |
|---|---|
| Contributing | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Module development | [`docs/MODULES.md`](docs/MODULES.md) |
| Integrations (Ansible, Terraform, cloud-init) | [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) |
| Watch daemon | [`docs/WATCH.md`](docs/WATCH.md) |
| Web dashboard | [`docs/SERVE.md`](docs/SERVE.md) |
| DevSecOps & CI | [`docs/DEVSECOPS.md`](docs/DEVSECOPS.md) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |

---

## Contributing

```bash
git clone https://github.com/jackby03/hardbox
cd hardbox
go mod download && go build ./...
```

PRs welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

hardbox is free software licensed under [AGPL v3](LICENSE).  
For commercial use without AGPL obligations: jackby03@protonmail.com

---

<div align="center">

**Built for engineers who know that security is not a feature — it's a foundation.**

</div>
