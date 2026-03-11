---
name: check-quality-gates
description: Run all hardbox quality gates and report results. Use before opening a PR or when asked to verify the codebase is clean.
---

## Task

Run the three required quality gates for hardbox and produce a pass/fail report.

## Steps

Run each command from the repository root and capture the output:

```bash
# 1. Static analysis
go vet ./...

# 2. Linter
golangci-lint run

# 3. Tests with race detector
go test ./... -race
```

## Output format

Report results as a markdown table:

| Gate | Status | Notes |
|---|---|---|
| `go vet` | ✅ Pass / ❌ Fail | Errors if any |
| `golangci-lint` | ✅ Pass / ❌ Fail | Lint violations if any |
| `go test -race` | ✅ Pass / ❌ Fail | Failed tests / race conditions |

- If all gates pass: state "All quality gates pass — safe to open PR."
- If any gate fails: list each failure with file, line, and description, and suggest a fix.
- Do not modify any files — just report findings.
