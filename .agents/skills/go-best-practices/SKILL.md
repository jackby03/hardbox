---
name: go-best-practices
description: "Go software engineering best practices and standard project architecture for hardbox. Use when writing new Go code, adding packages or modules, designing interfaces, implementing error handling, writing tests, structuring a Go project, reviewing Go code for idiomatic style, or working with concurrency, contexts, or file I/O in Go."
compatibility: Designed for Claude Code and any Agent Skills-compatible agent
metadata:
  author: hardbox-io
  version: "0.1"
  argument-hint: "Describe the Go task or area to focus on (e.g. 'new module', 'error handling', 'testing')"
---

# Go Best Practices & Standard Architecture

## When to Use
- Creating or extending a Go package or module
- Reviewing code for idiomatic Go style
- Designing interfaces, types, or APIs
- Writing tests (unit, integration, table-driven)
- Handling errors, concurrency, contexts, or file I/O
- Structuring a new Go project from scratch

---

## 1. Project Layout (Standard Go Structure)

Follow the [Standard Go Project Layout](https://github.com/golang-standards/project-layout):

```
project/
├── cmd/<name>/main.go     # Binary entry points — thin, just wires and launches
├── internal/              # Private packages — not importable by outside modules
│   ├── <domain>/          # Group by domain/feature, not by layer
│   └── config/
├── pkg/                   # Public, reusable packages (only if truly reusable)
├── configs/               # Config file templates
├── docs/                  # Design docs, ADRs
├── testdata/              # Test fixtures (ignored by go build)
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

**Rules:**
- `cmd/` entrypoints must be thin — no business logic, only wiring
- Use `internal/` to enforce encapsulation; default to `internal/` over `pkg/`
- Group packages by **domain** (e.g. `internal/ssh/`, `internal/distro/`), not by layer (`internal/models/`, `internal/services/`)
- `testdata/` directories are ignored by `go build` — use them for fixtures
- One binary per `cmd/<name>/` subdirectory

See: [references/project-structure.md](./references/project-structure.md)

---

## 2. Package Design

- **Small, focused packages** — a package should do one thing well
- **Package name = directory name** — `package distro` lives in `internal/distro/`
- **No circular imports** — design a dependency graph before coding; `internal/` packages should form a DAG
- **Avoid `util`, `common`, `helpers`** — these are signs of unclear ownership; use domain names instead
- **Unexport by default** — only export what external callers need
- **Interfaces belong in the consumer** — define interfaces where they're used, not where they're implemented

```go
// Good: interface in the consumer package
type FileReader interface {
    ReadFile(path string) ([]byte, error)
}

// Bad: interface in the implementation package (forces coupling)
```

---

## 3. Error Handling

- **Always handle errors** — never `_ = err`
- **Wrap with context** using `fmt.Errorf("context: %w", err)` — preserves the chain for `errors.Is` / `errors.As`
- **Sentinel errors** for expected conditions callers must handle: `var ErrNotFound = errors.New("not found")`
- **Custom error types** when callers need structured data: implement the `error` interface
- **Never panic** in library code — only acceptable in `main()` during startup for unrecoverable init failures
- **Return early** on errors — avoid deeply nested happy-path logic

```go
// Good
func readConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("readConfig: %w", err)
    }
    // ...
}

// Bad — swallows context
return nil, err
```

See: [references/error-handling.md](./references/error-handling.md)

---

## 4. Interfaces & Dependency Injection

- **Accept interfaces, return concrete types** — functions accepting interfaces are easier to test
- **Keep interfaces small** — prefer 1-3 methods (io.Reader, io.Writer are the gold standard)
- **Inject dependencies** via constructor parameters, not global variables or init()
- **No global state** — avoid `var db *sql.DB` at package level

```go
// Good: testable, no global state
func New(reader FileReader, logger zerolog.Logger) *Service {
    return &Service{reader: reader, log: logger}
}
```

---

## 5. Naming Conventions

| Element | Convention | Example |
|---|---|---|
| Package | lowercase, no underscores | `distro`, `sshconfig` |
| Exported type | PascalCase noun | `Finding`, `ModuleConfig` |
| Unexported | camelCase | `parseKeyValue` |
| Interface | noun or `-er` suffix | `Module`, `FileReader` |
| Constructor | `New` or `NewX` | `New(cfg)`, `NewEngine(cfg)` |
| Error var | `Err` prefix | `ErrNotFound` |
| Test helper | `must` prefix | `mustDetect(t, ...)` |
| Receiver name | 1-2 letter abbrev, consistent | `func (e *Engine)` |

- Avoid stuttering: `distro.DistroInfo` → `distro.Info`
- Acronyms: all-caps or all-lower: `ID`, `URL`, `userID`, `parseURL`

---

## 6. Testing

- **Table-driven tests** for multiple cases — use `[]struct{ name, input, want }` + `t.Run`
- **`_test.go` files live alongside the code** they test — same directory, always
- **External test package** (`package foo_test`) for black-box tests; internal (`package foo`) only when testing unexported symbols
- **`export_test.go`** to expose internals for external test packages (never export via main API)
- **`testdata/` for fixtures** — file-based inputs go here, not inline strings
- **Test helpers** call `t.Helper()` so failures point to the call site, not the helper
- **No sleeps in tests** — use channels, sync primitives, or `httptest`
- **`-race` flag in CI** — always run `go test -race`

```go
func TestParseConfig(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid", "key=value", "value", false},
        {"empty", "", "", true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := parseConfig(tt.input)
            if (err != nil) != tt.wantErr {
                t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
            }
            if got != tt.want {
                t.Errorf("got %q, want %q", got, tt.want)
            }
        })
    }
}
```

See: [references/testing.md](./references/testing.md)

---

## 7. Concurrency

- **Pass `context.Context` as the first argument** to every function that does I/O or can block
- **Goroutines must have a clear owner** — know who starts them and who ensures they stop
- **Use `errgroup`** (`golang.org/x/sync/errgroup`) for fan-out with error collection
- **Protect shared state** with `sync.Mutex` or channels — never raw access from multiple goroutines
- **Prefer channels for ownership transfer**, mutexes for shared state
- **Close channels from the sender**, never the receiver
- **`select` with `ctx.Done()`** for all blocking operations:

```go
select {
case result := <-ch:
    return result, nil
case <-ctx.Done():
    return nil, ctx.Err()
}
```

---

## 8. File I/O & System Calls

- **Atomic writes** — write to a temp file, then `os.Rename` to the target (prevents partial writes)
- **Explicit file modes** — always pass the intended `os.FileMode` (`0600`, `0644`, `0700`)
- **Validate and sanitize paths** — never concatenate user input into file paths directly
- **`defer f.Close()`** immediately after `os.Open` succeeds — never before the error check
- **`bufio.Scanner`** for line-by-line reading; `os.ReadFile` for small whole-file reads

```go
// Atomic write pattern
func atomicWrite(path string, data []byte, mode os.FileMode) error {
    dir := filepath.Dir(path)
    tmp, err := os.CreateTemp(dir, ".tmp-")
    if err != nil {
        return err
    }
    tmpName := tmp.Name()
    if _, err := tmp.Write(data); err != nil {
        tmp.Close()
        os.Remove(tmpName)
        return err
    }
    if err := tmp.Close(); err != nil {
        os.Remove(tmpName)
        return err
    }
    if err := os.Chmod(tmpName, mode); err != nil {
        os.Remove(tmpName)
        return err
    }
    return os.Rename(tmpName, path)
}
```

---

## 9. Security (OWASP-aligned)

- **Never shell out** (`exec.Command`) with user-controlled input — prefer native Go APIs
- **Sanitize file paths** — use `filepath.Clean` and reject paths escaping a base dir (path traversal)
- **Minimal permissions** — open files with the least permissive mode needed
- **No credentials in code or logs** — use environment variables or secret managers
- **Validate all external input** at system boundaries (CLI args, config files, environment)
- **`crypto/rand`** for randomness — never `math/rand` for security-sensitive values
- **Run as least-privilege** — drop privileges after startup when possible

---

## 10. Code Quality Checklist

Before committing Go code, verify:

- [ ] `go vet ./...` passes with no warnings
- [ ] `golangci-lint run` passes (or known suppressions are justified)
- [ ] `go test ./... -race` passes
- [ ] All exported symbols have doc comments
- [ ] No `TODO` left without a linked issue
- [ ] Error paths are tested, not just happy paths
- [ ] No magic numbers — use named constants
- [ ] No global mutable state introduced
- [ ] File writes use atomic pattern
- [ ] Context is propagated, not ignored

---

## References

- [Project Structure](./references/project-structure.md)
- [Error Handling](./references/error-handling.md)
- [Testing Patterns](./references/testing.md)
- [Effective Go](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Standard Go Project Layout](https://github.com/golang-standards/project-layout)
