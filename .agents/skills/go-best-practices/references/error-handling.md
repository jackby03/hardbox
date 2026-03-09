# Go Error Handling Reference

## Core Rules

1. **Always check errors** — `_ = err` is forbidden except in well-documented defer cleanups
2. **Wrap with `%w`** to preserve the error chain
3. **Add context at each layer** — the caller adds what it knows; the callee doesn't repeat it
4. **Return early** — don't nest happy-path logic inside `if err == nil`

## Wrapping Errors

```go
// Add context at every boundary crossing
func (e *Engine) Audit(ctx context.Context) error {
    findings, err := e.runAudit(ctx)
    if err != nil {
        return fmt.Errorf("audit: %w", err)   // ← %w preserves chain
    }
    return nil
}
```

Caller can then inspect the chain:
```go
if errors.Is(err, os.ErrNotExist) { ... }
if errors.As(err, &myErr) { ... }
```

## Sentinel Errors

Use for conditions callers are **expected** to handle:

```go
var (
    ErrNotFound    = errors.New("not found")
    ErrPermission  = errors.New("permission denied")
)

if errors.Is(err, ErrNotFound) {
    // handle gracefully
}
```

**Don't** make every error a sentinel — only errors that callers need to distinguish.

## Custom Error Types

Use when callers need **structured data** from the error:

```go
type CheckError struct {
    CheckID string
    Detail  string
}

func (e *CheckError) Error() string {
    return fmt.Sprintf("check %s failed: %s", e.CheckID, e.Detail)
}

// Caller:
var ce *CheckError
if errors.As(err, &ce) {
    log.Error().Str("check", ce.CheckID).Msg(ce.Detail)
}
```

## When to Panic

**Only in `main()` for unrecoverable startup failures:**

```go
func main() {
    cfg, err := config.Load()
    if err != nil {
        log.Fatal().Err(err).Msg("failed to load config")
        // or: panic(err) — acceptable only here
    }
}
```

**Never panic in library/internal code.** Consumers have no way to recover from it gracefully.

## Error Conventions by Layer

| Layer | Convention |
|---|---|
| `cmd/` (main) | Log + `os.Exit(1)` or `log.Fatal()` |
| `internal/engine` | Wrap with domain context, return up |
| `internal/<module>` | Wrap with check ID / file path |
| Low-level helpers | Return raw `error`, let callers add context |

## Multi-error Handling (Go 1.20+)

When aggregating errors from concurrent operations:

```go
var errs []error
for _, m := range modules {
    if err := m.Run(); err != nil {
        errs = append(errs, fmt.Errorf("module %s: %w", m.Name(), err))
    }
}
return errors.Join(errs...)
```

## Defer Cleanup Pattern

```go
f, err := os.Open(path)
if err != nil {
    return fmt.Errorf("open %s: %w", path, err)
}
defer f.Close()  // ← after nil check, never before
```

For write operations where close errors matter:

```go
if err := f.Close(); err != nil {
    return fmt.Errorf("close %s: %w", path, err)
}
```

## Logging vs Returning Errors

**Never do both** — log the error AND return it:

```go
// Bad: error gets logged twice (once here, once by the caller)
log.Error().Err(err).Msg("failed")
return err

// Good: return up, let the entry point log
return fmt.Errorf("readConfig: %w", err)

// Good: log and absorb (when the caller doesn't care)
log.Warn().Err(err).Msg("optional op failed, continuing")
```
