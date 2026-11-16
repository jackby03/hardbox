# hardbox — Technical Architecture

## Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| Language | **Go 1.22+** | Single static binary, no runtime deps, fast startup, great for system tools |
| CLI Framework | **Cobra** | Industry-standard Go CLI, handles subcommands and flags |
| Config | **Viper** + YAML | Flexible config loading (file, env, flags), supports merging profiles |
| Templating | **text/template** | Config file generation for `/etc` files |
| Logging | **zerolog** | Structured JSON logging for audit trail |
| Testing | **testify** + **gomock** | Unit and integration testing |
| Build | **GoReleaser** | Cross-platform binaries, checksums, GitHub Releases |

---

## Repository Structure

```
hardbox/
│
├── cmd/
│   └── hardbox/
│       └── main.go                  # Entry point — CLI dispatch
│
├── internal/
│   │
│   ├── engine/                      # Core hardening engine
│   │   ├── engine.go                # Plan, Apply, Rollback orchestration
│   │   ├── registry.go              # Module registry — all modules registered here
│   │   └── snapshot.go              # Pre-apply system snapshot and rollback
│   │
│   ├── modules/                     # Individual hardening modules
│   │   ├── module.go                # Module interface, Finding, Change, Check types
│   │   ├── util/
│   │   │   └── atomicwrite.go       # Atomic file write helper
│   │   ├── ssh/
│   │   ├── firewall/
│   │   ├── kernel/
│   │   ├── users/                   # Users, PAM, password policy, sudo
│   │   ├── filesystem/              # Mount options, file permissions, kernel modules
│   │   ├── auditd/
│   │   ├── services/
│   │   ├── network/
│   │   ├── crypto/
│   │   ├── logging/
│   │   ├── mac/                     # AppArmor / SELinux
│   │   ├── ntp/
│   │   ├── updates/
│   │   └── containers/
│   │
│   ├── report/                      # Report generation
│   │   ├── report.go                # Report aggregation and session model
│   │   ├── render_json.go
│   │   ├── render_html.go
│   │   ├── render_markdown.go
│   │   └── render_text.go
│   │
│   ├── distro/                      # Distro detection and abstraction
│   │   └── distro.go                # OS/version detection (Ubuntu, Debian, RHEL, Rocky…)
│   │
│   └── config/                      # Config loading
│       └── config.go                # Root config struct and Viper-based loader
│
├── configs/
│   └── profiles/                    # Hardening profiles
│       ├── cis-level1.yaml          # CIS Benchmarks Level 1 (shipped)
│       ├── cis-level2.yaml          # CIS Benchmarks Level 2 (shipped)
│       ├── pci-dss.yaml             # PCI-DSS v4.0 (shipped)
│       ├── stig.yaml                # DISA STIG Ubuntu 22.04 V1R1 (shipped)
│       ├── production.yaml          # hardbox curated — cloud production (shipped)
│       ├── development.yaml         # hardbox curated — dev/staging (shipped)
│       │
│       │   # Roadmap — not yet shipped:
│       ├── hipaa.yaml               # (v0.3)
│       ├── nist-800-53.yaml         # (v0.3)
│       ├── iso27001.yaml            # (v0.3)
│       ├── cloud-aws.yaml           # (v0.3)
│       ├── cloud-gcp.yaml           # (v0.3)
│       └── cloud-azure.yaml         # (v0.3)
│
├── docs/
│   ├── ARCHITECTURE.md              # This file
│   ├── COMPLIANCE.md                # Compliance mapping tables
│   ├── DEVSECOPS.md                 # CI/CD, release process, distro parity
│   ├── MODULES.md                   # Module reference
│   └── install.sh                   # One-liner installer (served at hardbox.jackby03.com)
│
├── .github/
│   └── workflows/
│       ├── quality-gates.yaml       # Build, test, lint, distro parity, repo checks
│       ├── release-publish.yaml     # GoReleaser on version tags
│       ├── release-smoke.yaml       # Post-release install and runtime smoke
│       └── docs-publish.yaml        # GitHub Pages deploy
│
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── AGENTS.md
└── LICENSE
```

---

## Core Concepts

### Module Interface

Every hardening module implements a single interface. This makes modules trivially testable, composable, and pluggable:

```go
// internal/modules/module.go

type Status string

const (
    StatusCompliant    Status = "compliant"
    StatusNonCompliant Status = "non-compliant"
    StatusManual       Status = "manual"
    StatusSkipped      Status = "skipped"
)

type Check struct {
    ID          string            // e.g. "ssh-001"
    Title       string
    Description string
    Remediation string
    Severity    string            // critical, high, medium, low, info
    Compliance  []ComplianceRef   // CIS, NIST, STIG references
}

type Finding struct {
    Check   Check
    Status  Status
    Current string // current system value
    Target  string // desired value after hardening
    Detail  string // human-readable explanation
}

type Change struct {
    Description string
    Apply        func() error
    Revert       func() error
    DryRunOutput string        // what would happen
}

type Module interface {
    Name()    string
    Version() string

    // Audit checks the system state. Read-only. No side effects.
    Audit(ctx context.Context, cfg ModuleConfig) ([]Finding, error)

    // Plan returns ordered changes to achieve compliance.
    Plan(ctx context.Context, cfg ModuleConfig) ([]Change, error)
}
```

### Engine Lifecycle

```
hardbox apply --profile production

       ┌─────────────┐
       │  Load Config │   Load profile YAML, merge user overrides
       └──────┬──────┘
              ▼
       ┌─────────────┐
       │ Detect Distro│   Identify OS, version, init system
       └──────┬──────┘
              ▼
       ┌─────────────┐
       │  Run Audit   │   All modules audit current state (read-only)
       └──────┬──────┘
              ▼
       ┌─────────────┐
       │  Build Plan  │   Determine non-compliant checks, build change list
       └──────┬──────┘
              ▼
       ┌─────────────┐
       │   Snapshot   │   Backup affected files, sysctl values, service states
       └──────┬──────┘
              ▼
       ┌─────────────┐
       │   Execute    │   Apply changes. On failure: auto-rollback
       └──────┬──────┘
              ▼
       ┌─────────────┐
       │   Verify     │   Re-audit to confirm all checks pass
       └──────┬──────┘
              ▼
       ┌─────────────┐
       │    Report    │   Generate JSON/HTML/Markdown report
       └─────────────┘
```

### Snapshot & Rollback

Before any change is applied, hardbox records the pre-apply state of everything
the selected changes declare they will touch. Each module's `Plan` returns
`Change` values carrying `Files` and `SysctlKeys`; the engine backs those up
before a single byte is written.

```json
// /var/lib/hardbox/snapshots/2024-03-06T143200Z/manifest.json
{
  "session_id": "2024-03-06T143200Z",
  "host": "prod-web-01",
  "timestamp": "2024-03-06T14:32:00Z",
  "files_backed_up": [
    { "path": "/etc/ssh/sshd_config", "sha256": "abc123...", "mode": 384, "existed": true },
    { "path": "/etc/sysctl.d/99-hardbox.conf", "sha256": "", "mode": 0, "existed": false }
  ],
  "sysctl_snapshot": {
    "net.ipv4.ip_forward": "0",
    "kernel.dmesg_restrict": "0"
  }
}
```

`existed: false` marks a path that apply will create: rollback removes it
instead of restoring content that never existed.

Restoring rewrites file contents and modes, deletes paths that were created,
and writes the recorded sysctl values back:

```bash
# List sessions
hardbox rollback list

# Rollback the most recent session
hardbox rollback apply --last

# Rollback a specific session
hardbox rollback apply --session 2024-03-06T143200Z
```

#### What rollback does not cover

Rollback restores **files and sysctl values**. It does **not** reverse:

- packages installed or removed (`apt-get`, `dnf`);
- services enabled, disabled or started (`systemctl`);
- firewall rules pushed through `ufw` or `firewall-cmd`;
- SELinux mode changes applied with `setenforce`, or AppArmor profile loads;
- permissions changed on directories, such as the world-writable sticky-bit and
  `/boot` ownership changes, because a directory's contents are not snapshotted;
- kernel modules loaded at runtime.

Changes of those kinds carry a `Revert` closure that is used when apply fails
mid-session, but it cannot be replayed later: closures are not serialisable, so a
`hardbox rollback` run in a new process has no way to re-run them. Treat package
and service remediation as forward-only, and take your own snapshot (VM, LVM,
or filesystem) before applying it on a host you cannot rebuild.

## Config File Format

```yaml
# /etc/hardbox/config.yaml  (or ~/.config/hardbox/config.yaml)

version: "1"

profile: production          # base profile to load
environment: cloud           # cloud | onprem | container

# Override individual modules
modules:
  ssh:
    enabled: true
    port: 2222               # custom SSH port
    allow_users:
      - deploy
      - admin
    allow_groups:
      - sshusers

  firewall:
    enabled: true
    backend: ufw             # ufw | nftables | firewalld
    allowed_ingress:
      - port: 2222
        proto: tcp
        comment: "SSH"
      - port: 443
        proto: tcp
        comment: "HTTPS"
      - port: 80
        proto: tcp
        comment: "HTTP redirect"

  kernel:
    enabled: true
    # override a specific sysctl value
    overrides:
      net.ipv4.ip_forward: "1"    # needed if this is a router/NAT box

  services:
    # Services this host is supposed to run. They are skipped rather than
    # disabled, even when an inherited profile lists them under disable.
    expected:
      - nginx


  users:
    enabled: true
    password_max_days: 90
    password_min_days: 1
    password_warn_days: 14
    lockout_attempts: 5
    lockout_duration: 900         # seconds

  modules_disabled:
    - containers                  # not running Docker on this host
    - ntp                         # managed by cloud provider

# Reporting
report:
  format: html                    # json | html | markdown | all
  output_dir: /var/lib/hardbox/reports
  include_remediation: true
  include_evidence: true

# Audit-only settings
audit:
  fail_on_critical: true          # exit code 1 if critical findings exist
  fail_on_high: false
```

---

## Security Design Principles

1. **Principle of Least Privilege** — hardbox itself requires root only for the execution phase. Audit mode runs as a normal user where possible.
2. **Immutability** — All generated `/etc` config files are written atomically (write to temp, verify, rename). No partial writes.
3. **No Network Calls** — hardbox is fully offline. No telemetry, no license checks, no update beacons. Profile updates are opt-in via `hardbox profiles update`.
4. **Idempotency** — Running hardbox twice on the same system produces the same result. Safe to include in recurring automation.
5. **Auditability** — Every change is logged with timestamp, user, host, before-value, and after-value. Log is append-only and tamper-evident by chaining SHA-256 hashes.
6. **Transparency** — Dry-run mode shows the exact content of every file that will be written, every sysctl that will change, and every service that will be altered — before anything is touched.
