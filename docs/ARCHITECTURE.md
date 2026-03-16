# hardbox — Technical Architecture

## Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| Language | **Go 1.22+** | Single static binary, no runtime deps, fast startup, great for system tools |
| TUI Framework | **Bubble Tea** (charmbracelet) | Modern Elm-architecture TUI, rich component ecosystem |
| TUI Components | **Lip Gloss** + **Bubbles** | Styling, tables, progress bars, spinners, viewports |
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
│       └── main.go                  # Entry point — TUI or CLI dispatch
│
├── internal/
│   │
│   ├── tui/                         # Terminal UI (Bubble Tea)
│   │   ├── app.go                   # Root model, screen router
│   │   ├── dashboard.go             # Main dashboard screen
│   │   ├── module_list.go           # Module navigator/selector
│   │   ├── module_detail.go         # Per-module config + preview
│   │   ├── audit_view.go            # Audit results viewer
│   │   ├── profile_picker.go        # Profile selection screen
│   │   ├── confirm.go               # Apply confirmation dialog
│   │   ├── progress.go              # Apply progress screen
│   │   └── styles.go                # Centralised Lip Gloss styles
│   │
│   ├── engine/                      # Core hardening engine
│   │   ├── engine.go                # Plan, Apply, Rollback orchestration
│   │   ├── plan.go                  # Builds ordered change plan
│   │   ├── executor.go              # Executes planned changes
│   │   ├── snapshot.go              # Pre-apply system snapshot
│   │   └── rollback.go              # Restores from snapshot
│   │
│   ├── modules/                     # Individual hardening modules
│   │   ├── module.go                # Module interface definition
│   │   ├── ssh/
│   │   ├── firewall/
│   │   ├── kernel/
│   │   ├── users/
│   │   ├── pam/
│   │   ├── filesystem/
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
│   ├── audit/                       # Audit & reporting
│   │   ├── auditor.go               # Runs checks without applying
│   │   ├── finding.go               # Finding / result data model
│   │   ├── report.go                # Report aggregation
│   │   └── renderers/
│   │       ├── json.go
│   │       ├── html.go
│   │       └── markdown.go
│   │
│   ├── distro/                      # Distro detection & abstraction
│   │   ├── detect.go                # OS/version detection
│   │   ├── apt.go                   # Debian/Ubuntu package ops
│   │   ├── dnf.go                   # RHEL/Rocky/Fedora package ops
│   │   └── service.go               # systemd service management
│   │
│   ├── config/                      # Config loading & validation
│   │   ├── config.go                # Root config struct
│   │   ├── loader.go                # Viper-based file + env loading
│   │   └── validator.go             # Config schema validation
│   │
│   └── compliance/                  # Compliance framework mapping
│       ├── frameworks.go            # CIS, NIST, PCI, HIPAA, STIG refs
│       └── mapper.go                # Maps check IDs to controls
│
├── pkg/
│   └── sysutil/                     # Safe system utilities
│       ├── file.go                  # Atomic file writes
│       ├── sysctl.go                # sysctl read/write
│       ├── exec.go                  # Command execution wrapper
│       └── privilege.go             # UID/privilege checks
│
├── configs/
│   ├── hardbox.yaml                 # Default user config
│   └── profiles/
│       ├── cis-level1.yaml          # CIS Benchmarks Level 1 (shipped)
│       ├── production.yaml          # hardbox curated — cloud production (shipped)
│       ├── development.yaml         # hardbox curated — dev/staging (shipped)
│       │
│       │   # Roadmap — not yet shipped:
│       ├── cis-level2.yaml          # (v0.2)
│       ├── stig.yaml                # (v0.2)
│       ├── pci-dss.yaml             # (v0.2)
│       ├── hipaa.yaml               # (v0.3)
│       ├── nist-800-53.yaml         # (v0.3)
│       ├── iso27001.yaml            # (v0.3)
│       ├── cloud-aws.yaml           # (v0.3)
│       ├── cloud-gcp.yaml           # (v0.3)
│       └── cloud-azure.yaml         # (v0.3)
│
├── docs/
│   ├── ARCHITECTURE.md              # This file
│   ├── MODULES.md                   # Module reference
│   ├── COMPLIANCE.md                # Compliance mapping tables
│   ├── PROFILES.md                  # Profile documentation
│   ├── CONTRIBUTING.md              # Contribution guide
│   └── PLUGIN_SDK.md                # Custom module development
│
├── scripts/
│   ├── install.sh                   # One-liner installer
│   └── test-distros.sh              # Multi-distro test runner
│
├── .github/
│   └── workflows/
│       ├── quality-gates.yaml       # Build, lint, audit, repository checks
│       ├── contribution-governance.yaml # Branch, PR, and policy rules
│       ├── release-publish.yaml     # GoReleaser on version tags
│       ├── release-smoke.yaml       # Post-release install and runtime smoke
│       └── docs-publish.yaml        # GitHub Pages deploy
│
├── go.mod
├── go.sum
├── Makefile
├── README.md
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

Before any change is applied, hardbox creates a **change manifest**:

```yaml
# /var/lib/hardbox/snapshots/2024-03-06T143200Z/manifest.yaml
session_id: 2024-03-06T143200Z
host: prod-web-01
profile: production
files_backed_up:
  - path: /etc/ssh/sshd_config
    sha256: abc123...
  - path: /etc/sysctl.d/99-hardbox.conf
    sha256: def456...
sysctl_snapshot:
  net.ipv4.ip_forward: "0"
  kernel.dmesg_restrict: "0"
services_snapshot:
  avahi-daemon: active
  cups: active
```

Rollback restores every backed-up file and re-applies the recorded service/sysctl states:

```bash
# List sessions
hardbox rollback list

# Rollback last session
hardbox rollback --last

# Rollback specific session
hardbox rollback --session 2024-03-06T143200Z
```

---

## TUI Architecture (Bubble Tea)

hardbox uses the **Elm Architecture** pattern via Bubble Tea:

```
         ┌─────────────┐
Message  │    Update   │  Updates model state based on events
────────►│    (pure)   │
         └──────┬──────┘
                │ new model
         ┌──────▼──────┐
         │    View     │  Renders model as a string (no side effects)
         └──────┬──────┘
                │ rendered string
         ┌──────▼──────┐
         │   Terminal  │
         └─────────────┘
```

### Screen Flow

```
                    ┌──────────────┐
          Start ──► │  Profile     │
                    │  Picker      │
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  Dashboard   │◄─────────────────────┐
                    │  (score +    │                       │
                    │   summary)   │                       │
                    └──────┬───────┘                       │
             ┌─────────────┼────────────────┐              │
             ▼             ▼                ▼              │
      ┌────────────┐ ┌──────────┐  ┌─────────────┐        │
      │  Module    │ │  Audit   │  │  Compliance │        │
      │  Navigator │ │  Results │  │  Report     │        │
      └────┬───────┘ └──────────┘  └─────────────┘        │
           ▼                                               │
      ┌────────────┐                                       │
      │  Module    │                                       │
      │  Detail    │                                       │
      │  + Config  │                                       │
      └────┬───────┘                                       │
           ▼                                               │
      ┌────────────┐                                       │
      │  Confirm   │                                       │
      │  Apply     │                                       │
      └────┬───────┘                                       │
           ▼                                               │
      ┌────────────┐                                       │
      │  Progress  │                                       │
      │  + Live Log│                                       │
      └────┬───────┘                                       │
           └───────────────────────────────────────────────┘
```

---

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
