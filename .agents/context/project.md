# Project Context — hardbox

## What is hardbox?

`hardbox` is an open-source, TUI-driven Linux server hardening toolkit written in Go.
It is designed for infrastructure and security teams to run guided, auditable, and repeatable
hardening workflows across multiple Linux distributions.

## Stack

- **Language:** Go 1.22+ (`CGO_ENABLED=0`, pure Go binaries)
- **TUI:** [Bubble Tea](https://github.com/charmbracelet/bubbletea) + Lipgloss
- **Logging:** [zerolog](https://github.com/rs/zerolog) (structured, leveled)
- **Build:** Makefile + [goreleaser](https://goreleaser.com/) for Linux amd64/arm64 binaries
- **CI:** GitHub Actions (`.github/workflows/`)
- **Config format:** YAML profiles in `configs/profiles/`

## Architecture

```
cmd/hardbox/main.go          — CLI entrypoint (cobra)
internal/
  engine/                    — orchestration, registry, snapshots/rollback
  modules/<name>/            — hardening modules (one package per check domain)
  tui/                       — Bubble Tea UI components and state
configs/
  profiles/                  — built-in hardening profiles (CIS, STIG, etc.)
docs/                        — architecture, module reference, compliance mapping
.agents/                     — ACS agent configuration (this folder)
```

## Core Product Goals

- Secure Linux hosts using modular, composable checks.
- Safe operations: dry-run mode, atomic file writes, rollback via snapshots.
- Compliance-oriented: CIS, STIG, NIST, PCI-DSS, ISO 27001, HIPAA.
- Works both interactively (TUI) and headless (CI/pipeline mode).

## Key Technical Constraints

| Constraint | Rule |
|---|---|
| Network | No network calls in runtime hardening logic |
| CGO | `CGO_ENABLED=0` — pure Go builds only |
| File writes | Must use atomic write pattern (`internal/engine/snapshot.go`) |
| Logging | Always use `zerolog`, never `fmt.Print*` for structured output |
| Go version | 1.22+ |

## Conventions

- **Branch naming:** `<type>/<short-description>` kebab-case (e.g. `feat/firewall-module`)
- **Commits:** Conventional Commits — `feat(ssh): add PermitRootLogin check`
- **Merge strategy:** Squash-and-merge to `main`; merge commit for `release/vX.Y.Z`
- **Tests:** Table-driven, race-detector enabled (`go test ./... -race`)
- **Error handling:** Always wrap with context; no bare `errors.New` in public APIs
- **Modules:** Each hardening module lives under `internal/modules/<name>/` with its own package

## Quality Gates (required before any PR merge)

```bash
go vet ./...
golangci-lint run
go test ./... -race
```

## Do Not Change Without Discussion

- `internal/engine/snapshot.go` — atomic write / rollback primitives
- `configs/profiles/` — schema changes require changelog entry
- `.github/workflows/` — CI changes require team review
- `go.sum` — never hand-edit; regenerate with `go mod tidy`

## Compliance Mapping

See `docs/` for module-to-framework mapping (CIS, STIG, NIST SP 800-53, PCI-DSS, ISO 27001, HIPAA).
