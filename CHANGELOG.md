# Changelog

All notable changes to **hardbox** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-03-15 🎉 _First pre-release_

### Added

#### Core engine
- Orchestration engine with plan → snapshot → execute → verify → report lifecycle
- `--dry-run` mode — preview every change before applying
- Full session rollback via `hardbox rollback apply --last` or `--session <id>`
- Atomic file write pattern — no partial writes, safe on live servers
- Distro detection (Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux, Amazon Linux, Fedora)
- `--non-interactive` flag for headless CI/CD runs
- `--log-level debug|info|warn|error` global flag (zerolog)

#### Hardening modules — 13 shipped
| Module | Checks | Highlights |
|---|---|---|
| `ssh` | 17 | PermitRootLogin, PasswordAuth, X11Forwarding, MaxAuthTries, AllowUsers |
| `firewall` | 6 | UFW / firewalld — default deny, rule audit, port exposure |
| `kernel` | 8 | ASLR, IP forwarding, SYN cookies, core dumps via sysctl |
| `users` | 7 | Password policy, root account, sudo config, inactive accounts |
| `pam` | 5 | Lockout policy, password complexity, session limits |
| `auditd` | 6 | Audit daemon, log integrity, space_left_action |
| `filesystem` | 8 | Mount options (`noexec`, `nosuid`), SUID/SGID, world-writable |
| `services` | 5 | Disable unnecessary network services |
| `logging` | 4 | rsyslog, journald, remote log forwarding |
| `network` | 6 | IPv6, ICMP, source routing, TCP timestamps |
| `ntp` | 3 | Time synchronisation, NTP sources |
| `mac` | 4 | AppArmor / SELinux enforcement mode |
| `containers` | 5 | Docker daemon hardening, seccomp, namespace isolation |

#### Profiles — 3 shipped
- `cis-level1` — CIS Benchmarks Level 1 baseline (low disruption)
- `production` — hardbox curated for cloud production servers
- `development` — dev/staging with security + developer usability

#### CLI
- `hardbox audit` — audit system state, no changes made
- `hardbox apply` — apply hardening with dry-run and rollback support
- `hardbox rollback list` / `rollback apply` — restore from snapshots
- `--format json|html|text|markdown` — multiple report output formats
- `--output <file>` — write report to file

#### Reports
- JSON renderer — machine-readable, CI/CD friendly
- HTML renderer — self-contained, browser-ready
- Text renderer — terminal-friendly tabular output
- Markdown renderer — GitHub/Confluence compatible

#### Visual identity & web
- Midnight Shield brand — dark `#0f172a` / electric blue `#3b82f6` / cyan `#06b6d4`
- Landing page — [hardbox.jackby03.com](https://hardbox.jackby03.com)
- Hero banner for README (`docs/hero.png`)
- OG image for GitHub social preview (`docs/og-image.png`)
- `install.sh` — one-liner binary installer with checksum verification

#### CI / governance
- `ci.yaml` — build, vet, test (race), lint (golangci-lint), self-audit dry-run
- `github-flow.yaml` — branch name and PR title validation, PR size check, auto-label
- `profile-check.yaml` — assert every shipped profile is documented
- `link-check.yaml` — validate internal markdown links in README and docs
- `pages.yaml` — GitHub Pages deploy to hardbox.jackby03.com
- GoReleaser v2 — `linux/amd64` and `linux/arm64` binaries + checksums
- `AGENTS.md` — ACS v1.0 compatible governance document

### Fixed
- SSH module was implemented but not registered in the runtime registry — all SSH checks were silently skipped ([#62](https://github.com/jackby03/hardbox/issues/62))
- HTML report format fell back to plain text silently — proper HTML renderer now implemented ([#63](https://github.com/jackby03/hardbox/issues/63))
- GoReleaser config pointed to `hardbox-io/hardbox` instead of canonical `jackby03/hardbox` ([#64](https://github.com/jackby03/hardbox/issues/64))
- GoReleaser config used deprecated v0 format — upgraded to v2 ([#64](https://github.com/jackby03/hardbox/issues/64))
- `--log-level` flag referenced in CONTRIBUTING.md but missing from CLI ([#66](https://github.com/jackby03/hardbox/issues/66))
- README badges and contributing section linked to non-existent `docs/CONTRIBUTING.md` ([#68](https://github.com/jackby03/hardbox/issues/68))

### Changed
- README Compliance Profiles table split into "Available now" (3 shipped) and "Roadmap" sections — previously advertised 12 non-existent profiles ([#65](https://github.com/jackby03/hardbox/issues/65))
- `docs/COMPLIANCE.md` coverage matrix updated with shipped vs roadmap status; CLI examples corrected to use shipped profiles ([#65](https://github.com/jackby03/hardbox/issues/65))
- `AGENTS.md` branch prefixes and PR title types aligned with `github-flow.yaml` enforcement — `perf` and `ci` added as canonical types ([#67](https://github.com/jackby03/hardbox/issues/67))
- README install section updated to use direct binary download and `go install` (no curl-pipe-to-bash) ([#66](https://github.com/jackby03/hardbox/issues/66))

---

## [Unreleased]

### Added
- `release-smoke.yaml` workflow to validate published release artifacts, installation, and minimal runtime behavior.
- `cis-level2` compliance profile — CIS Benchmarks Level 2, high-security baseline for sensitive-data servers ([#84](https://github.com/jackby03/hardbox/issues/84))
- `pci-dss` compliance profile — PCI-DSS v4.0, full cardholder data environment hardening with per-control requirement annotations ([#86](https://github.com/jackby03/hardbox/issues/86))
- `stig` compliance profile — DISA STIG for Ubuntu 22.04 LTS V1R1, DoD-grade hardening with V-number annotations for every control ([#85](https://github.com/jackby03/hardbox/issues/85))
- `distro-parity` job matrix in `quality-gates.yaml` — builds, tests, and smoke-audits hardbox inside Rocky Linux 9 and RHEL UBI 9 containers on every PR ([#87](https://github.com/jackby03/hardbox/issues/87))
- `Distro Parity Gate` required check — blocks merge if any distro leg fails; `docs/DEVSECOPS.md` documents parity scope and how to add distros
- Filesystem module check `fs-008` — `/var/tmp` must be mounted `nodev,nosuid,noexec` (CIS 1.1.8–1.1.10, STIG V-238149); this control was present in all compliance profiles but absent from the audit check list ([#88](https://github.com/jackby03/hardbox/issues/88))
- `hipaa` compliance profile — HIPAA Security Rule (45 CFR Part 164), full ePHI environment hardening with per-section annotations (§164.308/310/312); 6-year log retention per §164.316(b)(2)(i) ([#103](https://github.com/jackby03/hardbox/issues/103))
- `iso27001` compliance profile — ISO/IEC 27001:2022, ISMS-aligned OS hardening with Annex A control annotations (A.5–A.8) covering access control, cryptography, logging, network security, and vulnerability management ([#105](https://github.com/jackby03/hardbox/issues/105))
- `cloud-aws` compliance profile — CIS AWS Foundations Benchmark v2.0, OS hardening for Amazon EC2 with AWS-specific annotations (IAM, Security Groups, CloudTrail, EBS encryption, KMS); includes guidance for AWS Security Hub and AWS Config validation ([#106](https://github.com/jackby03/hardbox/issues/106))
- `cloud-gcp` compliance profile — CIS GCP Foundations Benchmark v2.0, OS hardening for GCP Compute Engine with GCP-specific annotations (OS Login, IAP, Cloud Audit Logs, CMEK, Shielded VM); includes guidance for Security Command Center validation ([#107](https://github.com/jackby03/hardbox/issues/107))
- `cloud-azure` compliance profile — CIS Azure Foundations Benchmark v2.1, OS hardening for Azure VMs with Azure-specific annotations (NSG, Defender for Cloud, Azure Policy, Disk Encryption, AAD login); includes guidance for Defender for Cloud Secure Score validation ([#108](https://github.com/jackby03/hardbox/issues/108))
- cloud-init user-data templates for AWS EC2, GCP Compute Engine, and Azure VMs — each template installs hardbox with checksum verification, applies the provider-matched compliance profile on first boot, uploads the HTML audit report to cloud-native object storage (S3 / GCS / Blob), and configures a daily systemd re-hardening timer ([#111](https://github.com/jackby03/hardbox/issues/111))
- `docs/CLOUD-INIT.md` — usage guide covering quick-start commands, IAM/RBAC requirements, configuration reference, timer management, and troubleshooting for all three cloud-init templates
- Ansible role (`ansible-role/hardbox/`) — Galaxy-compatible role wrapping the hardbox CLI; supports all profiles, audit-only mode, report fetching, rollback on failure, custom profile upload, and systemd re-hardening timer; includes Molecule integration tests for Ubuntu 22.04, Debian 12, and Rocky Linux 9 ([#109](https://github.com/jackby03/hardbox/issues/109))
- `docs/ANSIBLE.md` — Ansible role documentation covering installation, variable reference, example playbooks, CI/CD integration, and Molecule test instructions
- Terraform provider (`terraform-provider/`) — `jackby03/hardbox` provider for the Terraform Registry; exposes `hardbox_apply` resource with SSH-based install, checksum verification, profile selection, findings capture in state, and automatic rollback on destroy; examples for AWS EC2, GCP Compute Engine, and Azure VMs ([#110](https://github.com/jackby03/hardbox/issues/110))
- `docs/TERRAFORM.md` — provider documentation covering installation, provider/resource schema, per-cloud examples, CI/CD snippets, and build-from-source instructions
- `nist-800-53` compliance profile — NIST SP 800-53 Rev 5 High baseline; 15-char minimum password, 24-password history, 3-attempt lockout with 1-hour duration, immutable auditd logs, 3-year log retention, `deny_unknown: true` MAC policy, `fail_on_medium: true` threshold; per-control annotations for AC-2, AC-7, AU-8, AU-9(3), AU-11, CM-6, CM-7, IA-5(1), SC-8(1), SC-13, SI-2, SI-16 ([#104](https://github.com/jackby03/hardbox/issues/104))

### Changed
- `install.sh` now resolves release assets via GitHub API instead of hardcoded filenames, improving compatibility across release archive naming formats.
- `install.sh` now returns explicit errors when a tag exists without a published GitHub Release or missing linux/checksum artifacts.
- README Quick Start now uses the one-command installer and corrected rollback example (`hardbox rollback apply --last`).
- Workflow files were renamed for clearer operational intent: `quality-gates.yaml`, `release-publish.yaml`, `release-smoke.yaml`, and `docs-publish.yaml`.
- Removed `contribution-governance.yaml` — branch/PR enforcement rules are unnecessary overhead for a solo-maintainer project.

---

## [0.4.0] — Unreleased — Architecture & Scale

### Planned

#### P0 — Must Ship
- CLI refactor — extract all cobra command definitions to `internal/cli/`; `cmd/hardbox/main.go` becomes a ≤15-line entry point ([#120](https://github.com/jackby03/hardbox/issues/120))
- `hardbox fleet` — concurrent remote multi-host hardening via SSH; `fleet apply` and `fleet audit` with unified multi-host HTML report ([#121](https://github.com/jackby03/hardbox/issues/121))
- Mount & partition hardening module (14th module) — 15 checks covering `/tmp`, `/var`, `/var/log`, `/home`, `/dev/shm`, sticky bits, and kernel filesystem modules ([#122](https://github.com/jackby03/hardbox/issues/122))

#### P1 — Should Ship
- Plugin SDK — stable `sdk.Module` interface for third-party custom modules; `.so` plugin loading; `hardbox plugin list/install` ([#123](https://github.com/jackby03/hardbox/issues/123))
- `hardbox diff` — compare two JSON audit reports; highlights regressions and improvements; CI-safe exit code 1 on regressions ([#124](https://github.com/jackby03/hardbox/issues/124))

#### P2 — Nice to Have
- `hardbox serve` — local HTTP dashboard for browsing audit reports; embedded assets; `127.0.0.1`-only by default ([#125](https://github.com/jackby03/hardbox/issues/125))

### Planned for v0.2
- 14th module — mount and partition hardening


---

[0.1.0]: https://github.com/jackby03/hardbox/releases/tag/v0.1.0
[Unreleased]: https://github.com/jackby03/hardbox/compare/v0.1.0...HEAD
