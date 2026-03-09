# Pull Request Workflow Reference

## PR Lifecycle

```
Branch pushed
    │
    ▼
gh pr create          ← draft if WIP, ready when CI passes
    │
    ▼
CI checks run         ← build-and-test, lint, hardbox-audit
    │
    ▼
Request review        ← at least 1 approval required
    │
    ▼
Address feedback      ← push fixup commits, re-request review
    │
    ▼
Squash & Merge        ← linear history on main
    │
    ▼
Delete branch         ← gh pr merge --delete-branch
```

## gh Commands

```bash
# Create PR
gh pr create \
  --title "feat(ssh): add PermitRootLogin check" \
  --body "$(cat .github/pull_request_template.md)" \
  --label enhancement

# Create draft PR (work in progress)
gh pr create --draft --title "WIP: feat/firewall-module"

# Check CI status
gh pr checks

# View PR diff
gh pr diff

# Request review
gh pr edit --add-reviewer @username

# Merge (squash, delete branch)
gh pr merge --squash --delete-branch

# List open PRs
gh pr list --state open

# Check out a PR locally for review
gh pr checkout 42
```

## PR Size Guidelines

| Size | Lines changed | Guideline |
|---|---|---|
| Small | < 200 | Ideal — fast review |
| Medium | 200–500 | Acceptable — document scope clearly |
| Large | 500–1000 | Split if possible |
| XL | > 1000 | Must split (except initial scaffolding) |

If a PR is large, add a comment explaining why it can't be split.

## Review Etiquette

### As a Reviewer

- Review within 24h of assignment
- Use prefixes to signal urgency:
  - `nit:` — minor style, non-blocking
  - `suggestion:` — improvement idea, non-blocking
  - `blocking:` — must fix before merge
  - `question:` — needs clarification
- Check hardbox-specific rules:
  - Atomic write pattern for file I/O
  - Compliance refs for new hardening checks
  - No network calls added
  - No global mutable state
- Approve explicitly when satisfied — don't leave PRs in limbo

### As the Author

- Respond to every comment (address it or explain why not)
- Use fixup commits during review: `git commit --fixup HEAD~1`
- Don't push unrelated changes during review cycle
- Re-request review after addressing blocking comments

## CI Required Checks

All three jobs must pass before merge:

| Check | What it runs |
|---|---|
| `build-and-test` | `go vet`, `go build`, `go test -race` |
| `lint` | `golangci-lint` |
| `hardbox-audit` | `./hardbox audit --profile cis-level1 --format json` (dry run) |

If `hardbox-audit` fails on CI but passes locally, check that the binary compiles and that the SSH module is registered in `registry.go`.

## Merge Strategy

hardbox uses **Squash and Merge** for all PRs:

- All commits on the branch are squashed into one commit on `main`
- The squash commit message must follow Conventional Commits format
- Set the squash message to the PR title (already formatted correctly)

**Exception:** `release/vX.Y.Z` branches use **Merge Commit** to preserve the release history boundary.

## Labels

| Label | Set by | Meaning |
|---|---|---|
| `enhancement` | Auto (from `feat/` branch) | New feature |
| `bug` | Auto (from `fix/` branch) | Bug fix |
| `documentation` | Auto (from `docs/` branch) | Docs only |
| `chore` | Auto (from `chore/` branch) | Tooling / maintenance |
| `breaking-change` | Manual | Contains breaking API change |
| `needs-review` | Manual | Ready for review |
| `blocked` | Manual | Waiting on external dep or decision |
| `priority:critical` | Manual | Expedited review needed |

## PR Title Validation

PR titles are validated by CI (`.github/workflows/github-flow.yaml`).

Valid format: `<type>(<scope>): <description>`

```
feat(ssh): add PermitRootLogin check        ✓
fix(engine): prevent nil deref               ✓
SSH fix                                      ✗  (no type prefix)
feat: add firewall module                    ✓  (scope optional)
Feat(SSH): Add check                         ✗  (must be lowercase)
```
