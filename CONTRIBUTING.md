# Contributing to hardbox

Thank you for your interest in contributing! hardbox is an open-source Linux server hardening toolkit and we welcome contributions of all kinds — new modules, bug fixes, documentation, and tests.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Implementing a Module](#implementing-a-module)
  - [Improving the TUI](#improving-the-tui)
  - [Documentation](#documentation)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/hardbox.git
   cd hardbox
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/jackby03/hardbox.git
   ```

---

## Development Setup

**Requirements:**
- Go 1.22+
- Linux (hardbox reads/writes system files — most tests require Linux)
- `golangci-lint` for linting
- `goimports` for formatting
- `make`

```bash
# Build
make build

# Run tests
make test

# Lint
make lint

# Format code
make fmt
```

> **Note:** Running hardbox itself requires `sudo` because it modifies system configuration files. Tests that don't touch the filesystem can run without root.

---

## Project Structure

```
hardbox/
├── cmd/hardbox/main.go          # CLI entry point
├── configs/profiles/            # Built-in YAML hardening profiles
├── internal/
│   ├── config/                  # Config loading (Viper)
│   ├── engine/                  # Audit/Apply/Rollback orchestration
│   │   ├── engine.go
│   │   ├── registry.go          # Module registry ← register new modules here
│   │   └── snapshot.go          # Atomic file writes + rollback
│   ├── modules/
│   │   ├── module.go            # Module interface
│   │   └── <name>/module.go    # One directory per module
│   └── tui/                     # Bubble Tea UI
└── docs/
    ├── ARCHITECTURE.md
    ├── MODULES.md               # Check IDs and compliance mappings
    └── COMPLIANCE.md
```

---

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/jackby03/hardbox/issues/new?template=bug_report.md) and include:
- hardbox version (`hardbox --version`)
- Linux distro and version (`cat /etc/os-release`)
- Steps to reproduce
- Expected vs. actual behavior
- Relevant log output — capture debug logs with the global `--log-level` flag:
  ```
  hardbox --log-level debug audit --profile cis-level1 2>&1 | tee hardbox-debug.log
  ```
  Supported levels: `debug`, `info`, `warn`, `error` (default: `info`).

### Suggesting Features

Open a [GitHub Issue](https://github.com/jackby03/hardbox/issues/new?template=feature_request.md) with:
- Problem statement (what you're trying to solve)
- Proposed solution
- Compliance framework mapping if relevant (CIS, STIG, NIST, etc.)

### Implementing a Module

This is the most impactful contribution. See the [v0.1 milestone](https://github.com/jackby03/hardbox/milestone/1) for a list of unimplemented modules.

Each module lives in `internal/modules/<name>/module.go` and must implement the `Module` interface:

```go
type Module interface {
    Name()    string
    Version() string
    Audit(ctx context.Context, cfg config.ModuleConfig) ([]Finding, error)
    Plan(ctx context.Context, cfg config.ModuleConfig)  ([]Change,  error)
}
```

**Step-by-step:**

1. Create `internal/modules/<name>/module.go`
2. Implement `Name()`, `Version()`, `Audit()`, and `Plan()`
   - `Audit()` reads system state and returns findings without making changes
   - `Plan()` returns `Change` structs with `Apply` and `Revert` functions
3. Use `atomicWrite` for any file modifications (never write directly)
4. Register your module in `internal/engine/registry.go`
5. Add check IDs to `docs/MODULES.md` following the existing format
6. Write table-driven unit tests in `internal/modules/<name>/module_test.go`

**Check ID format:** `<prefix>-<NNN>` — e.g., `fw-001`, `kern-001`

See the [SSH module](internal/modules/ssh/module.go) as the reference implementation.

### Improving the TUI

The TUI is built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) (Elm architecture) and [Lipgloss](https://github.com/charmbracelet/lipgloss). Currently several screens are stubs — see [open TUI issues](https://github.com/jackby03/hardbox/labels/tui).

Color palette:
- Header blue: `#1e40af`
- Border: `#3b82f6`
- Labels: slate tones

### Documentation

Docs live in `docs/`. If you add checks, update `docs/MODULES.md` with the check ID, description, severity, and compliance references.

---

## Code Standards

- Follow standard Go conventions (`gofmt`, `goimports`)
- Run `make lint` and fix all warnings before submitting
- No network calls — hardbox is a fully offline tool
- No CGO — all builds must compile with `CGO_ENABLED=0`
- All file writes must use the atomic write pattern from `internal/engine/snapshot.go`
- Prefer table-driven tests with `t.Run` subtests
- Log with `zerolog` (`github.com/rs/zerolog/log`), never `fmt.Printf` for runtime output

---

## Testing

```bash
# All tests with race detector
make test

# Single package
go test ./internal/modules/ssh/... -v

# With coverage
go test ./... -coverprofile=coverage.out && go tool cover -html=coverage.out
```

Tests that write system files should use `t.TempDir()` and mock paths instead of real system paths.

---

## Submitting a Pull Request

1. Create a branch from `main`:
   ```bash
   git checkout -b feat/firewall-module
   ```
2. Make your changes, ensuring `make test` and `make lint` pass.
3. Commit with a clear message:
   ```
   feat(firewall): implement fw-001 through fw-006 checks
   ```
4. Push and open a PR against `main`.
5. Fill in the PR template — link the relevant issue with `Closes #<n>`.

Recommended merge-blocking checks:
- `Quality Gates / Build and Test`
- `Quality Gates / Lint`
- `Quality Gates / Self-Audit`
- `Contribution Governance / Branch Naming`
- `Contribution Governance / PR Title Convention`
- `Contribution Governance / Policy Alignment`

Recommended informational checks:
- `Quality Gates / Documentation Links`
- `Quality Gates / Profile Documentation`
- `Quality Gates / Release Configuration`
- `Contribution Governance / Change Volume`
- `Contribution Governance / Branch Freshness`

**Commit message format** (conventional commits):
- `feat(module):` — new module or check
- `fix(module):` — bug fix
- `feat(tui):` — TUI change
- `docs:` — documentation only
- `test:` — tests only
- `refactor:` — internal restructuring, no behavior change
- `chore:` — tooling, deps, CI

Operational guidance for branch protection, release publication, and smoke validation lives in [docs/DEVSECOPS.md](docs/DEVSECOPS.md).

---

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** Please follow the process in [SECURITY.md](SECURITY.md).

---

## License

By contributing you agree that your contributions will be licensed under the [GNU Affero General Public License v3](LICENSE).
