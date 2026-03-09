# Go Project Structure Reference

## Standard Layout

```
project-root/
├── cmd/
│   └── <binary-name>/
│       └── main.go          # Entrypoint: parse flags, wire deps, call Run()
├── internal/                 # Private: cannot be imported by external modules
│   ├── config/               # Config loading/validation
│   ├── <domain-a>/           # One directory per domain (ssh, distro, firewall…)
│   └── <domain-b>/
├── pkg/                      # Public reusable libs (use sparingly)
├── configs/                  # Config templates, default profiles (YAML/TOML/JSON)
├── docs/                     # Design docs, ADRs, API specs
├── scripts/                  # Build/release helper scripts (not Go)
├── testdata/                 # Test fixtures — ignored by go build
├── .github/
│   ├── workflows/            # CI pipelines
│   └── skills/               # Copilot skills
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Rules

### cmd/ — Thin Entrypoints
`main.go` must only:
1. Parse CLI flags / environment
2. Load configuration
3. Wire dependencies (call constructors)
4. Call the top-level `Run(ctx)` function
5. Handle the returned error and exit

**No business logic in `main.go`.**

### internal/ — Default for Everything Private
- Use `internal/` unless the package will genuinely be imported by a separate Go module
- `pkg/` is NOT required — most projects only use `internal/`
- Sub-packages inside `internal/` can still import each other freely

### Package per Domain, Not per Layer
```
// Bad — layer-based (creates coupling, circular import risk)
internal/
  models/
  services/
  repositories/

// Good — domain-based (clear ownership, easy to navigate)
internal/
  ssh/
  distro/
  firewall/
  config/
```

### testdata/
- Place test fixture files (config files, OS release files, JSON responses) here
- Never embed large fixtures as string literals in test files
- Subdirectories allowed: `testdata/ubuntu/`, `testdata/rhel/`
- Referenced with relative paths in tests: `"testdata/ubuntu_os_release"`

## Module Layout (go.mod)

```
module github.com/org/project

go 1.22

require (...)
```

- Module path is the canonical import path — keep it stable after publishing
- Use semantic import versioning for v2+: `module github.com/org/project/v2`
- `go.sum` must be committed — it is the lockfile

## File Naming

| File | Convention |
|---|---|
| Implementation | `<noun>.go` (e.g. `engine.go`, `distro.go`) |
| Tests | `<name>_test.go` (same directory) |
| Test exports | `export_test.go` (exposes internals for `_test` packages) |
| Generated code | `<name>_gen.go` or `zz_generated_<name>.go` |
| OS/arch build tags | `<name>_linux.go`, `<name>_darwin.go` |

## Dependency Injection Pattern

Wire dependencies top-down from `main.go`:

```
main.go
  └─ engine.New(cfg)
       ├─ distro.Detect()
       ├─ ssh.New()
       └─ snapshot.New(sessionID)
```

No global singletons. No `init()` side effects. No `sync.Once` for business logic — only for truly one-time initialization.
