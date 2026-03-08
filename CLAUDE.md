# CLAUDE.md — hardbox

This file gives Claude Code context about the hardbox project. Read it before making any changes.

---

## Project Overview

**hardbox** is an open-source, TUI-driven Linux server hardening toolkit written in Go.
It audits and applies security hardening controls on Linux servers, mapping checks to
compliance frameworks (CIS, STIG, PCI-DSS, HIPAA, NIST 800-53, ISO 27001).

- **Module path:** `github.com/hardbox-io/hardbox`
- **GitHub remote:** `github.com/jackby03/hardbox` ← different from module path
- **Go version:** 1.22+
- **License:** MIT
- **Status:** Pre-release (v0.1 roadmap in progress)

---

## Key Commands

```bash
# Build
make build              # outputs to bin/hardbox

# Run (requires sudo — hardbox modifies system config)
make run                # builds + sudo ./bin/hardbox

# Test
make test               # go test ./... -v -race

# Lint (golangci-lint must be installed separately)
make lint

# Format (requires gofmt + goimports)
make fmt

# Vet
make vet

# Install to /usr/local/bin
make install

# Clean
make clean              # removes bin/ and dist/

# Release (requires goreleaser)
make release
make snapshot           # local snapshot build, no publish
```

> **Important:** hardbox requires `sudo` at runtime because it reads and writes
> system files (`/etc/ssh/sshd_config`, sysctl, auditd rules, etc.).

---

## Project Structure

```
hardbox/
├── cmd/hardbox/main.go          # Cobra CLI entry point + TUI dispatch
├── configs/profiles/            # Built-in YAML hardening profiles
│   ├── cis-level1.yaml
│   ├── production.yaml
│   └── development.yaml
├── internal/
│   ├── config/config.go         # Viper-based config loading
│   ├── engine/
│   │   ├── engine.go            # Audit / Apply / Rollback orchestration
│   │   ├── registry.go          # Module registry (currently all stubs)
│   │   └── snapshot.go          # Pre-apply snapshots + atomic rollback
│   ├── modules/
│   │   ├── module.go            # Module interface + core types
│   │   └── ssh/module.go        # SSH module (only fully-implemented module)
│   └── tui/
│       ├── app.go               # Root Bubble Tea model, screen router
│       └── dashboard.go         # Dashboard screen
├── docs/
│   ├── ARCHITECTURE.md          # Technical design document
│   ├── MODULES.md               # Full module + check reference
│   └── COMPLIANCE.md            # Framework cross-reference matrix
├── .github/workflows/ci.yaml    # CI: build, test, lint, audit dry-run
└── .goreleaser.yaml             # Release pipeline (linux/amd64 + arm64)
```

---

## Current Implementation State

> The codebase is in early development. Only the architecture skeleton and one module exist.

| Component | State |
|:---|:---|
| Core engine (Audit/Apply/Rollback) | Implemented |
| Snapshot / atomic rollback | Implemented |
| Config loading (Viper) | Implemented |
| TUI dashboard | Implemented (basic) |
| TUI module navigator / detail screens | Stub (not wired) |
| SSH module | **Fully implemented** (5 checks) |
| All other modules (13) | Commented-out stubs in `registry.go` |
| Report rendering (`writeReport`) | TODO stub in `engine.go` |
| Distro detection | Not yet implemented |
| CI mode / headless | CLI flags exist, engine supports it |

---

## Module Interface

All hardening modules must implement `internal/modules/module.go`:

```go
type Module interface {
    Name()    string
    Version() string
    Audit(ctx context.Context, cfg config.ModuleConfig) ([]Finding, error)
    Plan(ctx context.Context, cfg config.ModuleConfig)  ([]Change,  error)
}
```

Core types:
- `Severity`: `critical | high | medium | low | info`
- `Status`: `compliant | non-compliant | manual | skipped | error`
- `Finding`: result of an audit check (has `Check`, `Status`, `Current`, `Target`)
- `Change`: a planned remediation (has `Apply func() error`, `Revert func() error`)
- `ComplianceRef`: `Framework + Control` pair (e.g., `CIS 5.2.2`)

Score weights: critical=10, high=6, medium=3, low=1 (see `Severity.ScoreWeight()`).

---

## Adding a New Module

1. Create `internal/modules/<name>/module.go`
2. Define a struct implementing the `Module` interface
3. Implement `Audit()` — reads system state, returns `[]Finding`
4. Implement `Plan()` — returns `[]Change` with `Apply` and `Revert` funcs
5. Use `atomicWrite` pattern for any file modifications (see `snapshot.go`)
6. Register in `internal/engine/registry.go` (uncomment the relevant stub or add a new entry)
7. Add check IDs and compliance mappings to `docs/MODULES.md`

Check ID format: `<module-prefix>-<NNN>` (e.g., `ssh-001`, `fw-001`, `kern-001`).

---

## Config System

Profiles are YAML files loaded via Viper. The `Config` struct:

```go
type Config struct {
    Version        string
    Profile        string
    Environment    string      // "cloud" | "onprem"
    DryRun         bool
    NonInteractive bool
    Modules        map[string]ModuleConfig   // map[string]any per module
    Report         ReportConfig
    Audit          AuditConfig
}
```

Config search order:
1. `--config` / `-c` flag
2. `/etc/hardbox/config.yaml`
3. `~/.config/hardbox/config.yaml`
4. Current directory

Environment variable overrides use the `HARDBOX_` prefix (e.g., `HARDBOX_PROFILE`).

---

## Runtime Paths

| Path | Purpose |
|:---|:---|
| `/var/lib/hardbox/snapshots/` | Pre-apply snapshots (mode 0700) |
| `/var/lib/hardbox/reports/` | Generated audit reports |
| `/etc/hardbox/config.yaml` | System-wide config |
| `~/.config/hardbox/config.yaml` | User config |

---

## Snapshot / Rollback Design

- Every `Apply` run creates a snapshot at `/var/lib/hardbox/snapshots/<sessionID>/`
- `snapshot.BackupFile(path)` copies the original file + records its SHA-256
- `atomicWrite(path, data, mode)` writes via temp file then renames (no partial writes)
- On failure, the engine auto-rolls back the current session
- `hardbox rollback --last` or `--session <id>` for manual rollback

---

## TUI Architecture

Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) (Elm architecture) and [Lipgloss](https://github.com/charmbracelet/lipgloss).

Screens (defined in `internal/tui/app.go`):

| Screen constant | Status |
|:---|:---|
| `screenDashboard` | Implemented |
| `screenModules` | Not wired |
| `screenModuleDetail` | Not wired |
| `screenAudit` | Not wired |
| `screenApplyConfirm` | Not wired |
| `screenApplyProgress` | Not wired |

Color palette (Lipgloss): blue header `#1e40af`, border `#3b82f6`, slate labels.

---

## Dependencies

| Package | Purpose |
|:---|:---|
| `charmbracelet/bubbletea` | TUI framework |
| `charmbracelet/lipgloss` | TUI styling |
| `spf13/cobra` | CLI commands/flags |
| `spf13/viper` | Config loading |
| `rs/zerolog` | Structured JSON logging |

---

## CI/CD

Three GitHub Actions jobs (`.github/workflows/ci.yaml`), triggered on push to `main`/`develop` and PRs to `main`:

1. **build-and-test** — `go vet`, `go build`, `go test -race`
2. **lint** — `golangci-lint`
3. **hardbox-audit** — builds binary and runs `audit --profile cis-level1 --format json` as a dry-run smoke test

Releases via `goreleaser` — builds for `linux/amd64` and `linux/arm64` only (`CGO_ENABLED=0`).
Configs (`configs/**`) are bundled in release archives.

---

## Important Notes

- **The Go module path (`github.com/hardbox-io/hardbox`) differs from the GitHub remote (`github.com/jackby03/hardbox`).** Always use the module path for internal imports.
- **`registry.go` returns an empty slice** — running `hardbox apply` currently does nothing. Adding a new module requires registering it there.
- **`writeReport()` in `engine.go` is a TODO stub.** Report rendering infrastructure is not yet built.
- **`docs/ARCHITECTURE.md` describes a planned structure** (e.g., `pkg/sysutil/`, `internal/distro/`) that does not yet exist on disk. Do not assume those packages are available.
- All file writes in modules should use the atomic write pattern from `snapshot.go` — never write config files directly.
- The binary must be run as root. Do not add network calls or phone-home behavior; the security design principles require the tool to be fully offline.
