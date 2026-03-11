---
name: audit-dry-run
description: Run hardbox in dry-run mode against the local system and summarize the findings. Use when the user wants to preview what hardbox would change without applying anything.
input: profile_name
---

## Task

Run a `hardbox audit` in dry-run mode using the specified profile (default: `cis-level1`) and summarize the output.

## Steps

1. Locate the compiled `hardbox` binary (check `./bin/hardbox` or run `go build -o ./bin/hardbox ./cmd/hardbox`).
2. Run:
   ```bash
   sudo ./bin/hardbox audit --profile <profile_name> --dry-run
   ```
   If no profile was specified, default to `cis-level1`.
3. Parse the output and produce a structured summary:
   - Total checks run
   - Passed / Failed / Skipped counts
   - List of failed checks with their IDs and descriptions
   - Any warnings or errors printed by the engine

## Output format

- Use a markdown table for the check summary (ID | Status | Description)
- Highlight critical failures with ⚠️
- Maximum 400 words; be factual and concise
