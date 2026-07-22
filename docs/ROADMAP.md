# hardbox Roadmap — v0.5 → v1.0

This document describes the planned evolution of hardbox from its current state (v0.4) through general availability (v1.0). It covers technical scope, new modules, SaaS architecture, and the commercial model that funds continued development.

---

## Philosophy

hardbox will always be **100% free and open source** for self-hosted use. Every hardening module, compliance profile, CLI command, and the Plugin SDK are OSS — no features locked behind a paywall.

The commercial layer is a **hosted service** (hardbox Cloud) that provides the infrastructure, dashboard, and enterprise controls on top of the same OSS engine. The distinction is _where the platform runs and who maintains it_ — not which features you can access.

---

## Where we are — v0.4

| Category | Count |
|---|---|
| Hardening modules | 15 |
| Compliance profiles | 12 |
| CLI commands | 7 (`audit`, `apply`, `rollback`, `diff`, `fleet`, `plugin`, `serve`) |
| Checks implemented | ~156 |
| Frameworks mapped | CIS L1/L2, NIST SP 800-53, STIG, PCI-DSS, HIPAA, ISO 27001, cloud-aws/gcp/azure |

---

## v0.5 — Observability & Continuous Compliance

**Theme:** hardbox transitions from _reactive_ (run when called) to _proactive_ (detect regressions automatically).
This version also lays the technical foundation for the future SaaS agent.

### P0 — Must Ship

**`hardbox watch`**
Daemon mode. Runs a full audit on a configurable interval, writes JSON results to a directory, and exits non-zero when the compliance score drops compared to the previous run. This is the core of continuous compliance monitoring and the basis for the future telemetry agent.

```bash
hardbox watch --profile production --interval 6h --output /var/lib/hardbox/reports/
```

**Webhook / alerting**
Fires an HTTP POST when a regression or new `critical`/`high` finding is detected. Includes a built-in Slack adapter. Rules are configurable per severity and per module in `config.yaml`.

```yaml
notifications:
  webhook: https://hooks.slack.com/services/...
  on: [regression, critical_finding]
  modules: [ssh, firewall, users]
```

**Fleet overview in `hardbox serve`**
When fleet audit JSON files are present in the reports directory, the dashboard renders an aggregate view: compliance score per host, regressions between runs, per-host timeline. No backend required — reads from local files.

### P1 — Should Ship

**Profile inheritance**
`extends` key in YAML profiles. Inherits all settings from a base profile and overrides only what is declared. Eliminates copy-paste between similar profiles and enables org-specific customisation without forking the built-in profiles.

```yaml
# configs/profiles/my-production.yaml
name: my-production
extends: production
modules:
  ssh:
    allow_users: [deploy, ops, monitoring]
  users:
    pass_max_days: 60
```

**Trend history in `hardbox serve`**
The dashboard renders a compliance score sparkline over time by reading all JSON reports in the configured directory, ordered by timestamp. No database required.

### P2 — Nice to Have

**SARIF export**
`--format sarif` produces a SARIF 2.1.0 document compatible with GitHub Advanced Security code scanning and major SIEMs. Each finding maps to a SARIF `result` with rule metadata, severity, and remediation guidance.

---

## v0.6 — Deep Coverage I

**Theme:** Close the most critical Lynis coverage gaps. Add modules for categories that hardbox does not yet cover.

| Module | Key Checks | Compliance |
|---|---|---|
| `boot` | GRUB2 password, Secure Boot state, `/boot` permissions, bootloader config integrity | CIS 1.4, STIG V-238200 |
| `storage` | LUKS/dm-crypt on sensitive partitions, encrypted swap, `/etc/crypttab`, plain-text swap detection | CIS 1.1, NIST SC-28 |
| `integrity` | AIDE/Tripwire installed and initialised, integrity DB present, verification cron/timer configured | CIS 1.3, NIST SI-7 |
| `malware` | rkhunter/chkrootkit installed and clean, suspicious processes, world-writable `PATH` entries | CIS — , NIST SI-3 |
| `shells` | `TMOUT` in `/etc/profile.d/`, `HISTSIZE`/`HISTFILESIZE` limits, `.bashrc`/`.profile` audit | CIS 5.4.4, STIG |
| `processes` | Process accounting enabled, `ulimits` in `/etc/security/limits.conf`, core dumps disabled | CIS 1.5, NIST AU-12 |

**Target after v0.6:** ~240 checks across 21 modules.

---

## v0.7 — Deep Coverage II

**Theme:** Close remaining Lynis category gaps. Reach 25 modules and ~260+ checks.

### New modules

| Module | Key Checks | Compliance |
|---|---|---|
| `hardware` | USB lockdown (usbguard), Bluetooth disabled, FireWire/Thunderbolt DMA protection | CIS 1.1.1, NIST SC-41 |
| `nameservices` | `/etc/hosts` integrity, `nsswitch.conf` review, DNSSEC enabled, no plaintext DNS outbound | CIS 3.4, NIST SC-20 |
| `webserver` | Server tokens hidden, directory listing disabled, TLS 1.2+ enforced, security headers | CIS — , NIST SC-8 |
| `databases` | Remote root login, test databases, anonymous users, password auth enforced | CIS — , PCI-DSS 6.3 |

### Package integrity

`debsums` (Debian/Ubuntu) and `rpm -Va` (RHEL/Rocky) — verifies installed binary checksums against the package manager database. Detects tampered system binaries.

**Target after v0.7:** ~260 checks across 25 modules.

---

## v0.8 — Polish & Ecosystem

**Theme:** Developer experience, packaging, and extensibility.

| Feature | Description |
|---|---|
| Custom checks (YAML) | Define new checks in YAML without writing Go; loaded by the engine at startup |
| Compliance PDF reports | Auto-generated executive reports per framework with real audit evidence |
| `.deb` / `.rpm` packages | Native Linux packages via GoReleaser |
| Plugin SDK v1 | Stable API frozen until v2.0 |
| Full documentation | Module reference, operator runbooks, migration guides |

---

## v1.0 — Production Ready GA

**Theme:** General availability. Stable APIs, full documentation, industry parity.

### Completion criteria

| Criteria | Target |
|---|---|
| Checks | 300+ across 25+ modules |
| Compliance profiles | 12+ (CIS, NIST, STIG, PCI-DSS, HIPAA, ISO 27001, cloud-aws/gcp/azure) |
| Lynis parity | All Lynis audit categories covered |
| Plugin SDK | v1 stable API |
| Packages | `.deb`, `.rpm`, and tarballs via GoReleaser |
| Docs | Full module reference, operator runbooks, migration guides |

---

## Future / Post-v1.0 — SaaS & Enterprise

Deferred until hardbox has validated product-market fit. These features remain on
the long-term roadmap but are not prioritized for v1.0:

- **SaaS platform** — multi-tenant backend API, OAuth2/OIDC, cloud dashboard
- **Telemetry agent** — lightweight daemon wrapping `hardbox watch`
- **Enterprise** — SSO/SAML, RBAC, immutable audit log, billing
- **Multi-host management** — group hosts by tag, apply profiles per group from dashboard

---

## Module roadmap at a glance

| Version | New modules | Running total |
|---|---|---|
| v0.4 ✅ | `mount` | 15 modules, ~156 checks |
| v0.5 ✅ | — (observability infra) | 15 modules, ~169 checks |
| v0.6 ✅ | `boot`, `storage`, `integrity`, `malware`, `shells`, `processes` | 21 modules, ~199 checks |
| v0.7 | `hardware`, `nameservices`, `webserver`, `databases` | 25 modules, ~260+ checks |
| v0.8 | — (polish + ecosystem) | 25 modules |
| v1.0 | polish, gaps, community additions | 25+ modules, 300+ checks |

---

## Competitive position

| | Lynis | hardbox |
|---|---|---|
| License | GPL | AGPL v3 |
| Remediation | Enterprise (paid) | **Always free** |
| Multi-host | No | `hardbox fleet` |
| CI/CD integration | Manual | Native (`diff`, SARIF, exit codes) |
| Plugin system | No | Plugin SDK |
| Cloud-native profiles | No | AWS, GCP, Azure |
| Extensible via YAML | No | v0.8+ |

hardbox is not a Lynis clone. The audit engine is a starting point — the differentiator is **remediation, scale, and ecosystem**.
