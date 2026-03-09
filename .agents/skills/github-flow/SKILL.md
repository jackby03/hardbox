---
name: github-flow
description: "GitHub Flow branching and collaboration workflow for hardbox. Use when creating a feature branch, opening or reviewing a pull request, naming branches, writing commit messages, preparing a release, resolving conflicts, or enforcing PR conventions."
compatibility: Designed for Claude Code and any Agent Skills-compatible agent
metadata:
  author: hardbox-io
  version: "0.1"
  argument-hint: "Describe the task (e.g. 'new feature branch for firewall module', 'PR for ssh fix', 'release v0.2.0')"
---

# GitHub Flow — hardbox Workflow

## When to Use
- Creating or naming a feature/fix/chore branch
- Writing a commit message
- Opening, reviewing, or merging a pull request
- Resolving merge conflicts or rebasing
- Preparing a release tag

---

## 1. Core Principle

**`main` is always deployable.** Every change — no matter how small — flows through a branch and a pull request.

```
main  ──────●──────────────────────────────●────
             \                            /
              ●──●──●──●  (feature branch)
                        \
                         PR → review → merge → delete
```

---

## 2. Branch Naming

Format: `<type>/<short-description>` (lowercase kebab-case)

| Type | Purpose | Example |
|---|---|---|
| `feat/` | New feature or module | `feat/firewall-module` |
| `fix/` | Bug fix | `fix/ssh-audit-panic` |
| `chore/` | Tooling, deps, CI | `chore/update-golangci` |
| `refactor/` | Restructuring, no behavior change | `refactor/engine-errors` |
| `test/` | Tests only | `test/ssh-coverage` |
| `docs/` | Documentation only | `docs/modules-reference` |
| `release/` | Release preparation | `release/v0.2.0` |

Rules:
- Always branch from `main` (pull latest first)
- Lowercase kebab-case only — no camelCase, no underscores, no issue numbers
- Delete branch after merge

```bash
git checkout main && git pull
git checkout -b feat/firewall-module
```

See: [references/branching.md](./references/branching.md)

---

## 3. Commit Messages (Conventional Commits)

```
<type>(<scope>): <short description>

[body — explain WHY, not what. wrap at 72 chars]

[footer: Fixes #123]
```

Types: `feat`, `fix`, `chore`, `refactor`, `test`, `docs`, `perf`, `ci`

Scope: package/module name (`ssh`, `engine`, `tui`, `config`, `ci`)

Examples:
```
feat(ssh): add PermitRootLogin check (ssh-001)
fix(engine): prevent nil deref on empty module list
chore(ci): pin golangci-lint to v1.57
test(ssh): add table-driven tests for ParseSSHConfig
```

---

## 4. Pull Request Workflow

1. Push branch: `git push -u origin feat/firewall-module`
2. Open PR targeting `main`
3. PR title follows Conventional Commits format
4. Fill the PR description (see template below)
5. Pass all CI checks before requesting review
6. At least 1 approval required before merge
7. **Squash and Merge** — keeps `main` history linear
8. Delete branch after merge

### PR Description Template

```markdown
## What
<!-- One-paragraph summary -->

## Why
Fixes #<issue-number>

## How
<!-- Implementation approach -->

## Testing
- [ ] `go test ./... -race` passes
- [ ] Manual: `sudo ./bin/hardbox audit --profile cis-level1`
- [ ] Module registered in `registry.go` (if applicable)
- [ ] `docs/MODULES.md` updated (if applicable)

## Checklist
- [ ] Branch branched from `main`
- [ ] Conventional Commits format
- [ ] `go vet ./...` passes
- [ ] `golangci-lint run` passes
- [ ] Atomic write pattern for any file writes
```

See: [references/pr-workflow.md](./references/pr-workflow.md)

---

## 5. Keeping Branch Up to Date

```bash
git fetch origin
git rebase origin/main
# Resolve conflicts, then:
git add <file>
git rebase --continue
```

Always rebase (not merge) to keep history clean.

---

## 6. Release Flow

```bash
# 1. Branch from main
git checkout main && git pull
git checkout -b release/v0.2.0

# 2. Update CHANGELOG, version refs
# 3. PR: release/v0.2.0 → main
# 4. After merge, tag on main
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
# goreleaser CI publishes linux/amd64 + arm64 binaries automatically
```

---

## References

- [Branching Guide](./references/branching.md)
- [PR Workflow](./references/pr-workflow.md)
- [GitHub Flow Guide](https://docs.github.com/en/get-started/using-github/github-flow)
- [Conventional Commits](https://www.conventionalcommits.org/)
