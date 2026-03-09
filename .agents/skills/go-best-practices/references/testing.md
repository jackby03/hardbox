# Go Testing Patterns Reference

## File & Package Conventions

| File | Package | Purpose |
|---|---|---|
| `foo_test.go` | `package foo_test` | Black-box tests — normal default |
| `foo_internal_test.go` | `package foo` | White-box tests — only for unexported symbols |
| `export_test.go` | `package foo` | Exposes internals to `foo_test` package |

**Rule:** Default to `package foo_test`. Only use `package foo` when you truly need to reach unexported symbols.

## export_test.go Pattern

Expose internals without polluting the public API:

```go
// export_test.go — compiled only during `go test`
package foo

var TestInternalFunc = internalFunc
var TestDetectFromPaths = detectFromPaths
```

External test files can then call `foo.TestInternalFunc(...)`.

## Table-Driven Tests

The standard Go testing pattern for multiple cases:

```go
func TestParseKeyValue(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        wantKey string
        wantVal string
        wantErr bool
    }{
        {
            name:    "simple pair",
            input:   `KEY=value`,
            wantKey: "KEY",
            wantVal: "value",
        },
        {
            name:    "quoted value",
            input:   `KEY="hello world"`,
            wantKey: "KEY",
            wantVal: "hello world",
        },
        {
            name:    "empty value",
            input:   `KEY=`,
            wantKey: "KEY",
            wantVal: "",
        },
        {
            name:    "no equals sign",
            input:   `INVALID`,
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            k, v, err := parseKeyValue(tt.input)
            if (err != nil) != tt.wantErr {
                t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
            }
            if !tt.wantErr {
                if k != tt.wantKey {
                    t.Errorf("key: got %q, want %q", k, tt.wantKey)
                }
                if v != tt.wantVal {
                    t.Errorf("val: got %q, want %q", v, tt.wantVal)
                }
            }
        })
    }
}
```

## Test Helpers

Always call `t.Helper()` so failures report the correct line:

```go
func mustParseConfig(t *testing.T, path string) *Config {
    t.Helper()
    cfg, err := parseConfig(path)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    return cfg
}
```

## Testdata Fixtures

For file-based tests, keep fixtures in `testdata/`:

```go
func TestDetectUbuntu(t *testing.T) {
    info, err := detectFromPaths("testdata/ubuntu_os_release", "", "")
    // ...
}
```

- `testdata/` is ignored by `go build` — safe to put any content there
- Use descriptive names: `testdata/ubuntu_22_os_release`, not `testdata/test1`
- Subdirectory OK: `testdata/rhel/`, `testdata/debian/`

## Subtests & Parallelism

Mark independent subtests as parallel to speed up the suite:

```go
for _, tt := range tests {
    tt := tt // capture range variable (required pre-Go 1.22)
    t.Run(tt.name, func(t *testing.T) {
        t.Parallel()
        // ...
    })
}
```

## Testing with Context

Always pass a context with a timeout to prevent hanging tests:

```go
func TestAudit(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // ...
    findings, err := module.Audit(ctx, cfg)
}
```

## Mocking & Fakes

Prefer **fakes** (simple in-memory implementations) over mock frameworks:

```go
// Fake fulfills the interface with predictable behavior
type fakeReader struct {
    data map[string][]byte
    err  error
}

func (f *fakeReader) ReadFile(path string) ([]byte, error) {
    if f.err != nil {
        return nil, f.err
    }
    return f.data[path], nil
}
```

Avoid complex mock frameworks (e.g. `gomock`, `testify/mock`) unless the interface is large — they couple tests to implementation details.

## CI Configuration

```yaml
# Recommended test flags for CI
go test ./... -count=1 -timeout=5m

# With race detector (Linux/macOS CI)
go test ./... -race -count=1 -timeout=5m
```

- `-count=1` disables test result caching — always run fresh in CI
- `-timeout=5m` catches infinite loops / deadlocks
- `-race` catches data races — enable on Linux/macOS CI runners

## What to Test

| Priority | What |
|---|---|
| Always | Happy paths, error paths, edge cases (empty, nil, zero values) |
| Always | Functions with file I/O — use `testdata/` not real `/etc/` |
| When risky | Concurrency — use `-race` |
| Skip | Trivial getters/setters with no logic |
| Skip | External I/O without an injectable interface |

## Coverage

Run coverage to identify gaps — but don't chase 100%:

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

Target: high coverage on **logic-heavy** packages (`internal/distro`, `internal/engine`). Don't stress about `cmd/` main glue code.
