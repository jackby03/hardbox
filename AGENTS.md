# AGENTS.md

## Project Context

`hardbox` is an open-source, TUI-driven Linux server hardening toolkit written in Go.
It is designed for infrastructure and security teams to run guided, auditable, and repeatable hardening workflows across multiple Linux distributions.

Core product goals:
- Secure Linux hosts using modular checks and profiles.
- Keep operations safe with dry-run, rollback, and atomic file writes.
- Support compliance-oriented workflows (CIS, STIG, NIST, PCI-DSS, ISO 27001, HIPAA).
- Work both interactively (TUI) and in headless/CI environments.

Technical constraints and standards:
- Go 1.22+.
- No network calls in runtime hardening logic.
- No CGO (`CGO_ENABLED=0` builds).
- File writes must use the atomic write pattern (`internal/engine/snapshot.go` pattern).
- Logging must use `zerolog`.

Key repository structure:
- `cmd/hardbox/main.go`: CLI entrypoint.
- `internal/engine`: orchestration, registry, snapshots/rollback.
- `internal/modules/<name>`: hardening modules.
- `internal/tui`: Bubble Tea based user interface.
- `configs/profiles`: built-in hardening profiles.
- `docs`: architecture, modules, compliance mapping.

---

## Local Skills in `.agents/skills`

### `github-flow`
Purpose:
- Standardize branch lifecycle, naming, commits, PR workflow, release flow, and merge strategy.

Use when:
- Creating branches, writing commit messages, opening/reviewing/merging PRs, rebasing, or preparing releases.

### `go-best-practices`
Purpose:
- Enforce idiomatic Go architecture, package design, error handling, testing, concurrency, and secure file I/O.

Use when:
- Implementing or reviewing Go code, adding modules/packages, and validating quality gates.

---

## Branching and Naming Standard

Branch format:
- `<type>/<short-description>` in lowercase kebab-case.
- Max ~5 words in the description.
- No underscores, no camelCase, no issue numbers in the branch name.

Allowed prefixes:
- `feat/`, `fix/`, `chore/`, `refactor/`, `test/`, `docs/`, `release/`.

Examples:
- `feat/firewall-module`
- `fix/ssh-audit-panic`
- `docs/modules-reference`

Lifecycle:
1. Start from updated `main`.
2. Create branch.
3. Commit iteratively.
4. Push and open PR to `main`.
5. Rebase on `origin/main` when needed (do not merge `main` into feature branches).
6. Merge PR and delete branch.

Protected branch policy:
- Never push directly to `main`.
- `main` changes only through PR.

---

## Commit and PR Standard

Commit/PR title format (Conventional Commits):
- `<type>(<scope>): <description>`
- Scope is recommended (`ssh`, `engine`, `tui`, `config`, `ci`, etc.).
- Lowercase type/scope.

Examples:
- `feat(ssh): add PermitRootLogin check`
- `fix(engine): prevent nil deref on empty module list`

PR workflow:
1. Open PR against `main` (draft if still WIP).
2. Ensure CI passes before requesting review.
3. Minimum 1 approval before merge.
4. Respond to review comments and re-request review when blocking items are addressed.

Required checks before merge:
- `build-and-test` (`go vet`, `go build`, `go test -race`)
- `lint` (`golangci-lint`)
- `hardbox-audit` dry-run job

Merge strategy:
- Default: **Squash and Merge** for linear `main` history.
- Exception: `release/vX.Y.Z` uses **Merge Commit**.

---

## Contributor Quality Gates

Before opening or merging a PR, ensure:
- `go vet ./...`
- `golangci-lint run`
- `go test ./... -race`
- Relevant docs updated when adding/modifying checks (`docs/MODULES.md` and related docs).
