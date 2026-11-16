# AGENTS.md

## ACS Compliance

This project follows the [Agentic Collaboration Standard v1.0](https://github.com/jackby03/agentic-collaboration-standard).
ACS-compatible agents should read `.agents/main.yaml` as the entry point for context, skills, commands, and permissions.

---

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

Development and testing environment:

hardbox distinguishes three planes. Do not collapse them — most past confusion about
"Windows support" came from treating them as one.

| Plane | Rule |
|---|---|
| **Runtime target** | Linux only. hardbox never audits or applies hardening on a non-Linux host. Never weaken this. |
| **Build host** | Any OS. `go build ./...` works on Windows, macOS and Linux and must keep working. |
| **Test host** | Any OS for pure logic. Tests that depend on POSIX semantics (mode bits, `geteuid`, `/proc`, `systemctl`) must declare it via the guards below and skip elsewhere. |

Testing rules:

- Declare platform dependencies with the helpers in
  `internal/modules/util/testutil/platform.go`: `RequireUnixPerms`, `RequireUnprivileged`,
  `RequireLinux`, or the `UnixPermsSupported()` predicate. Never hand-roll
  `if runtime.GOOS == ...` in a test — an inverted condition there already shipped once.
- `make test` is the fast cross-platform suite (`go test ./... -count=1`). It must pass everywhere.
- `make test-race` and `make validate` require cgo and a 64-bit toolchain. They are the CI gate.
- On a Windows host, **do not** trust `make test-race` results: `/mnt/c` is mounted over 9p
  without the `metadata` option, so `chmod 0000` is masked, files stay readable and permission
  tests report false results. Run the gates on a WSL-native copy instead:
  `wsl -d Debian -- bash scripts/dev/wsl-validate.sh` (provision once with
  `scripts/dev/wsl-setup.sh`).
- `make build` links with `CGO_ENABLED=0`; `test-race` needs `CGO_ENABLED=1`. Keep the two separate.
- Integration and smoke tests are performed in the Vagrant lab.

CI runs on `ubuntu-latest` plus RPM-based containers. See
[docs/DEVSECOPS.md](docs/DEVSECOPS.md) for the authoritative job list and which checks are
required on `main` — do not duplicate that list here, it drifts.

Key repository structure:
- `cmd/hardbox/main.go`: CLI entrypoint.
- `internal/engine`: orchestration, registry, snapshots/rollback.
- `internal/modules/<name>`: hardening modules.
- `internal/tui`: Bubble Tea based user interface (deprecated — will be removed in a future release).
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
- `feat/`, `fix/`, `chore/`, `refactor/`, `test/`, `docs/`, `release/`, `perf/`.

Examples:
- `feat/firewall-module`
- `fix/ssh-audit-panic`
- `docs/modules-reference`
- `perf/engine-registry-cache`

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

Allowed PR title types:
- `feat`, `fix`, `chore`, `refactor`, `test`, `docs`, `release`, `perf`, `ci`.
- Note: `ci` is valid as a PR title type (e.g. workflow-only changes) but does not have a
  corresponding branch prefix — use `chore/` for the branch name in that case.

Examples:
- `feat(ssh): add PermitRootLogin check`
- `fix(engine): prevent nil deref on empty module list`
- `perf(engine): cache registered modules slice at startup`
- `ci(workflows): pin golangci-lint to v1.57`
- `release(v0.1): cut first pre-release`

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
- `go test ./... -race` on Linux (see the testing rules above for Windows hosts)
- Relevant docs updated when adding/modifying checks (`docs/MODULES.md` and related docs).

---

## AI Agent Instructions

- **Purpose:** Short, actionable guidance for AI coding agents working in this repository.
- **Start here:** Read [.agents/main.yaml](.agents/main.yaml) for agent permissions, then this file.
- **Build & test:** Run `go build ./...` on any platform; run `go test ./... -race` under WSL/Linux or a Linux VM. See [Makefile](Makefile) for CI targets and `scripts/dev/` for the WSL helpers.
- **Key files to inspect:** [cmd/hardbox/main.go](cmd/hardbox/main.go), [internal/engine](internal/engine), [internal/modules](internal/modules), [configs/profiles](configs/profiles), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- **Conventions:** Follow the `go-best-practices` and `github-flow` skills under `.agents/skills/`.
- **Safety rules:** Do not push directly to `main`. Make small, focused changes and open a PR targeting `main`.
- **Authoring guidance:** Link to existing docs rather than copying their contents — prefer the "link, don't embed" principle.

