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

### Changed
- `install.sh` now resolves release assets via GitHub API instead of hardcoded filenames, improving compatibility across release archive naming formats.
- `install.sh` now returns explicit errors when a tag exists without a published GitHub Release or missing linux/checksum artifacts.
- README Quick Start now uses the one-command installer and corrected rollback example (`hardbox rollback apply --last`).
- Workflow files were renamed for clearer operational intent: `quality-gates.yaml`, `contribution-governance.yaml`, `release-publish.yaml`, `release-smoke.yaml`, and `docs-publish.yaml`.

### Planned for v0.2
- `cis-level2`, `pci-dss`, `stig` compliance profiles
- 14th module — mount and partition hardening
- Full RHEL / Rocky Linux test parity
- TUI module detail and finding screens
- `install.sh` published to hardbox.jackby03.com

### Planned for v0.3
- `hipaa`, `nist-800-53`, `iso27001` profiles
- `cloud-aws`, `cloud-gcp`, `cloud-azure` profiles
- Ansible role integration
- Terraform provisioner
- cloud-init support

---

[0.1.0]: https://github.com/jackby03/hardbox/releases/tag/v0.1.0
[Unreleased]: https://github.com/jackby03/hardbox/compare/v0.1.0...HEAD
