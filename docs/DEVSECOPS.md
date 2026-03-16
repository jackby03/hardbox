# DevSecOps and Delivery Model

This document defines the operational model for hardbox across development, security, release, and documentation automation.

---

## Workflow Catalog

### `quality-gates.yaml`

Purpose: repository quality gates for code, docs, and release config.

Checks exposed in GitHub:
- `Quality Gates / Build and Test`
- `Quality Gates / Lint`
- `Quality Gates / Self-Audit`
- `Quality Gates / Documentation Links`
- `Quality Gates / Profile Documentation`
- `Quality Gates / Release Configuration`

### `contribution-governance.yaml`

Purpose: contribution policy enforcement and governance.

Checks exposed in GitHub:
- `Contribution Governance / Branch Naming`
- `Contribution Governance / PR Title Convention`
- `Contribution Governance / Change Volume`
- `Contribution Governance / Direct Push Protection`
- `Contribution Governance / Branch Freshness`
- `Contribution Governance / PR Label Sync`
- `Contribution Governance / Policy Alignment`

### `release-publish.yaml`

Purpose: build and publish release artifacts from tags.

Checks exposed in GitHub:
- `Release Publish / Publish Release Artifacts`

### `release-smoke.yaml`

Purpose: validate a published release from a user point of view.

Checks exposed in GitHub:
- `Release Smoke / Installation and Runtime`

### `docs-publish.yaml`

Purpose: deploy project documentation to GitHub Pages.

Checks exposed in GitHub:
- `Documentation Publish / Publish GitHub Pages Site`

---

## Branch Protection Policy

Recommended required checks for `main`:
- `Quality Gates / Build and Test`
- `Quality Gates / Lint`
- `Quality Gates / Self-Audit`
- `Contribution Governance / Branch Naming`
- `Contribution Governance / PR Title Convention`
- `Contribution Governance / Policy Alignment`

Recommended informational checks, not required for merge:
- `Quality Gates / Documentation Links`
- `Quality Gates / Profile Documentation`
- `Quality Gates / Release Configuration`
- `Contribution Governance / Change Volume`
- `Contribution Governance / Branch Freshness`

Not merge-blocking by design:
- `Contribution Governance / PR Label Sync`
- `Contribution Governance / Direct Push Protection`
- `Release Publish / Publish Release Artifacts`
- `Release Smoke / Installation and Runtime`
- `Documentation Publish / Publish GitHub Pages Site`

Branch protection settings:
- Require at least 1 approval.
- Dismiss stale approvals when new commits are pushed.
- Block direct pushes to `main`.
- Prefer squash merge.
- Optionally require branches to be up to date before merge.

---

## Release Process

1. Merge approved work into `main`.
2. Create and push a version tag.
3. `release-publish.yaml` produces Linux artifacts and checksums.
4. `release-smoke.yaml` validates release assets, installer flow, and minimal runtime execution.
5. Only announce the release after publish and smoke succeed.

Example:

```bash
git checkout main
git pull --ff-only origin main
git tag v0.1.1-rc1
git push origin v0.1.1-rc1
```

---

## Security Controls

Repository-level controls already enabled or recommended:
- CodeQL
- Dependabot alerts
- Secret scanning
- Private vulnerability reporting
- Checksum verification in installer

Recommended next steps:
- Dependabot version update PRs
- Artifact signing
- Release provenance or attestations

---

## Failure Modes

### Release without artifacts

Cause:
- tag exists but `release-publish.yaml` failed or did not upload artifacts

Action:
- inspect release workflow
- verify GoReleaser config
- do not announce the version until release-smoke passes

### Installer fails on published version

Cause:
- missing tarball or checksums
- bad release asset naming

Action:
- inspect release assets
- rerun or repair release publication
- rerun release smoke

### Governance policy drift

Cause:
- AGENTS.md and workflow rules diverged

Action:
- align branch and PR title types between AGENTS.md and `contribution-governance.yaml`

---

## Ownership Model

Suggested ownership:
- Maintainers own release tagging, branch protection, and final release approval.
- Contributors own passing quality gates and accurate docs for their changes.
- Automation enforces consistency and catches packaging or governance regressions.
