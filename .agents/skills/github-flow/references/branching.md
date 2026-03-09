# Branching Reference

## Branch Lifecycle

```
1. git checkout main && git pull        # always start from latest main
2. git checkout -b feat/my-feature      # create branch
3. git add / git commit (iterate)       # commit early and often
4. git push -u origin feat/my-feature   # push when ready for PR
5. Open PR → review → merge             # squash merge preferred
6. git branch -d feat/my-feature        # delete local branch
```

## Naming Rules

| Rule | Good | Bad |
|---|---|---|
| lowercase only | `feat/firewall-module` | `feat/FirewallModule` |
| kebab-case | `fix/ssh-audit-panic` | `fix/ssh_audit_panic` |
| type prefix | `chore/update-ci` | `update-ci` |
| no issue numbers | `feat/kernel-hardening` | `feat/123-kernel-hardening` |
| max 5 words | `feat/ssh-root-login` | `feat/add-check-for-ssh-root-login-to-sshd` |

## Types Reference

| Prefix | Triggers CI audit? | Auto-labels PR? |
|---|---|---|
| `feat/` | yes | `enhancement` |
| `fix/` | yes | `bug` |
| `chore/` | no | `chore` |
| `refactor/` | yes | `refactor` |
| `test/` | yes | `testing` |
| `docs/` | no | `documentation` |
| `release/` | yes (full) | `release` |

## Protected Branches

| Branch | Push directly? | Force push? | Delete? |
|---|---|---|---|
| `main` | No — PR required | Never | Never |
| `release/*` | No — PR required | Never | After release only |
| `feat/*`, `fix/*` etc. | Yes (your branch) | OK (your branch) | After merge |

## Stale Branch Policy

- Branches with no commits in 30 days are considered stale
- CI will warn on PRs from branches > 60 commits behind `main`
- Rebase stale branches before requesting review

## Hotfix Flow

For urgent production fixes:

```bash
git checkout main && git pull
git checkout -b fix/critical-ssh-vuln

# Make the fix, commit
git commit -m "fix(ssh): patch CVE-XXXX-XXXX in sshd_config handling"

# Open PR immediately — request expedited review
gh pr create --title "fix(ssh): patch CVE-XXXX-XXXX" --label "priority:critical"

# After merge, tag a patch release
git tag -a v0.1.1 -m "Patch: CVE-XXXX-XXXX"
git push origin v0.1.1
```

Do NOT push directly to `main`, even for hotfixes.

## Conflict Resolution

```bash
# Update your branch
git fetch origin
git rebase origin/main

# If conflicts:
# 1. Open conflicted files, resolve markers
# 2. git add <resolved-file>
# 3. git rebase --continue
# 4. Repeat until rebase completes

# If you want to abort and start over:
git rebase --abort
```

Never use `git merge origin/main` on feature branches — use `rebase` to keep history linear.
