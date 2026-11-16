# hardbox Roadmap — v0.7 → v1.0

This document describes what hardbox is, what it deliberately is not, and how work is
prioritised. It is the source of truth for scope decisions: when a proposal is not clearly
covered here, the burden is on the proposal.

---

## What hardbox is

hardbox audits a Linux server against a hardening baseline **and fixes it**, for free, on
rules the operator writes.

That is the whole product. Three claims, in order of importance:

1. **It fixes what it finds.** Audit is table stakes — every tool in this space does it.
   The differentiator is `hardbox apply`: a reviewed plan, a pre-apply snapshot, atomic
   writes, and a one-command rollback.
2. **It costs nothing.** Audit *and* remediation are open source, AGPL v3, self-hosted, no
   tier, no seat count, no feature flag. This is a product decision, not a marketing line.
3. **It runs the operator's rules.** YAML custom checks and the Plugin SDK exist so a team
   can encode its own baseline instead of only consuming built-in profiles.

### The filter question

Before any feature is scheduled, it has to answer yes to this:

> Does this make it easier for someone to audit **and then fix** their Linux server, for
> free, on any of the supported distributions, using rules they control?

If the answer is no, or "not yet", it is not on the critical path — regardless of how
interesting it is.

---

## What hardbox is not

Stated explicitly so the roadmap stops drifting toward them:

| Not this | Why |
|---|---|
| A hosted SaaS with tenancy, SSO/SAML, RBAC or billing | Contradicts claim 2. The audience is teams running their own servers. |
| A telemetry or fleet-management platform | `hardbox fleet` runs over SSH and produces files. There is no backend, no agent, no control plane, and none is planned for v1.0. |
| A desktop or workstation hardening tool | CIS §1.1.1 (USB, Bluetooth, FireWire/Thunderbolt DMA) is a workstation baseline. Servers are the target. |
| An interactive TUI application | Removed. The audience is headless: SSH sessions, cron, and CI. |
| An audit-only scanner | Competing with free audit tools that are more mature is a losing position. Remediation is the reason to pick this. |

Adjacent surfaces that already exist — `hardbox serve` (local report dashboard),
`hardbox fleet`, `hardbox watch` (scheduled re-audit), webhook alerts, the Ansible role,
the Terraform provider, the cloud-init templates — are **add-ons**. They are maintained
and welcome, but they are not the critical path, they do not gate a release, and new work
on them should not displace remediation or coverage work.

---

## Where we are — v0.6

| | Count | Note |
|---|---|---|
| Hardening modules | 21 | registered in `internal/engine/registry.go` |
| Distinct checks | 199 | counted from check-ID literals across `internal/modules`, excluding tests; includes the `services` and `network` checks built from tables |
| Compliance profiles | 12 | CIS L1/L2, NIST 800-53, STIG, PCI-DSS, HIPAA, ISO 27001, AWS/GCP/Azure, production, development |
| Frameworks mapped | 6 | CIS, NIST, STIG, PCI, HIPAA, ISO — rows in `docs/COMPLIANCE.md`, enforced by CI |
| Distributions audited in CI | 6 containers + Ubuntu runner | see [`DEVSECOPS.md`](DEVSECOPS.md) |
| **Distributions with verified remediation** | **1 (Debian)** | everything else is untested, and 4 modules hardcode `apt-get`/`yum` |

That last row is the honest state of the product and the reason v0.7 is what it is. Audit
coverage grew to six distributions across v0.4–v0.6 while remediation was never verified
anywhere but Debian.

---

## How work is prioritised

Three pillars, strictly ordered. A pillar does not advance until the one above it is
covered.

### Pillar 1 — Remediation parity

Every check must have a remediation that works on every supported distribution, or an
explicit, documented reason why it is audit-only (for example a check that can only be
reviewed by a human).

This is a correctness requirement, not a feature. An audit tool that reports a problem and
then silently does nothing is worse than one that never offered to fix it.

### Pillar 2 — Coverage

New modules and checks, in the categories server operators actually run. Breadth is
valuable only where Pillar 1 holds.

### Pillar 3 — Custom rules

YAML-defined checks and a frozen Plugin SDK v1, so operators can encode their own baseline.
This is claim 3 above; it has been scheduled last for three releases and that is now the
main gap in the product's promise.

---

## v0.7 — Remediation parity, then server-native coverage

### P0 — Remediation parity (blocks everything else)

- **Distro-aware package installation.** `integrity`, `malware`, `processes` and `mac`
  invoke `apt-get` or `yum` directly, so `hardbox apply` fails on RHEL, Rocky, AlmaLinux,
  Amazon Linux and Fedora. Introduce a single package-manager resolver over
  `internal/distro` (apt-get / dnf / yum / zypper / pacman, with a `PATH` probe fallback)
  and route every module through it.
- **Fill remediation holes.** `crypto.Plan` returns no changes for its six checks, so
  `hardbox apply` is a silent no-op for that module. Audit remediation coverage across all
  21 modules and close every gap.
- **Verify remediation in CI.** The distro-parity job runs `apply --dry-run`, which
  exercises `Plan()` but never `Apply()`. Add an assertion that a plan produced on an RPM
  image contains no Debian package manager, and that a plan on a Debian image contains no
  RPM one. Cheap, deterministic, and it is the check that would have caught the bug above.
- **Document the audit-only exceptions.** A check that cannot be remediated safely must say
  so in `docs/MODULES.md`, not fail silently.

### P1 — Server-native coverage

**Prerequisite, done:** `services.expected` lets a profile declare the services
the host is supposed to run. Without it the new modules would fight the baseline:
`cis-level1` lists `nginx`, `httpd` and `named` under `disable`, so applying that
profile on a web server stops the web server. `expected` overrides `disable`, and
an expected service is reported as `skipped` rather than silently dropped.

| Module | Key checks | Compliance |
|---|---|---|
| `webserver` | Server tokens hidden, directory listing disabled, TLS 1.2+ enforced, security headers | NIST SC-8 |
| `databases` | Remote root login, anonymous users, test databases, password auth enforced | PCI-DSS 6.3 |
| `nameservices` | `/etc/hosts` integrity, `nsswitch.conf` review, DNSSEC enabled, no plaintext DNS outbound | CIS 3.4, NIST SC-20 |

Each ships with audit **and** remediation, per Pillar 1.

### Dropped

- **`hardware`** (USB lockdown, Bluetooth, FireWire/Thunderbolt DMA). This came from the
  CIS workstation baseline (§1.1.1) and does not fit the audience. The one check that does
  matter on a server — refusing to load `usb-storage` — already lives in the `mount` module
  (`mnt-015`). If physical-access hardening ever returns it will be an opt-in module
  covering kernel module blacklisting and `usbguard` only, never Bluetooth.

---

## v0.8 — Custom hardening

Pillar 3. The promise of "your own rules" has been deferred long enough.

| Feature | Description |
|---|---|
| **YAML custom checks** | Define checks and remediations in YAML, loaded by the engine at startup, no Go required. Custom checks must support remediation, not just detection. |
| **Plugin SDK v1** | Freeze the API until v2.0. |
| **Module and check reference** | Every module and every check documented, with its compliance mapping. Generated or verified by CI, not hand-maintained. |

### Then, and only then — distribution polish

| Feature | Description |
|---|---|
| `.deb` / `.rpm` / tarball packages | GoReleaser, so operators do not build from source |
| Compliance PDF reports | Executive summary per framework, built from real audit evidence |

---

## v1.0 — Production ready

v1.0 is a quality bar, not a check count.

| Criteria | Target |
|---|---|
| Remediation parity | Every remediable check has a tested remediation on every supported distribution |
| Audit-only checks | Every exception documented with its reason in `docs/MODULES.md` |
| CI-verified distribution coverage | Audit **and** remediation asserted on all six container families |
| Documentation | No module, check or compliance mapping undocumented; both invariants enforced by CI |
| Plugin SDK | v1 stable |
| Packages | `.deb`, `.rpm`, tarball via GoReleaser |
| Modules | **24** (the 21 of v0.6 plus the three of v0.7) |
| Checks | Whatever those 24 modules need. A number is not a goal; audit-only modules counted toward parity were the problem in the first place. |

The previous roadmap targeted "300+ checks across 25+ modules" for v1.0. That target
rewarded counting over correctness, and it is why four modules could hardcode the wrong
package manager while the roadmap reported progress.

---

## Module roadmap at a glance

| Version | Modules | Total | Theme |
|---|---|---|---|
| v0.4 ✅ | 15 | 15 | Core engine, profiles, fleet, diff, plugin SDK |
| v0.5 ✅ | — | 15 | Watch daemon, alerts, SARIF, profile inheritance |
| v0.6 ✅ | `boot`, `storage`, `integrity`, `malware`, `shells`, `processes` | 21 | Coverage |
| **v0.7** | `webserver`, `databases`, `nameservices` | **24** | **Remediation parity first, then coverage** |
| v0.8 | — | 24 | Custom hardening: YAML checks, SDK v1, packaging |
| v1.0 | — | 24 | Quality bar: parity, docs, packages |

---

## Competitive position

| | Lynis | hardbox |
|---|---|---|
| License | GPL | AGPL v3 |
| Audit | Free | Free |
| Remediation | Enterprise (paid) | **Free, in the same binary** |
| Operator-defined checks | Shell snippets | YAML checks + Plugin SDK |
| CI/CD integration | Manual | Native (`diff`, SARIF, exit codes) |
| Multi-host | No | `hardbox fleet` over SSH (add-on) |
| Local report dashboard | No | `hardbox serve` (add-on) |
| Cloud-native profiles | No | AWS, GCP, Azure |

hardbox is not a Lynis clone with a nicer CLI. The audit engine is the entry point; the
product is **free remediation plus operator-controlled rules**. Every scope decision should
protect that sentence.
