# DevSecOps and Delivery Model

This document defines the operational model for hardbox across development,
security, release, and documentation automation.

---

## Workflow Catalog

### `quality-gates.yaml`

Purpose: repository quality gates for code, docs, release config, and
multi-distro parity.

Checks exposed in GitHub:
- `Quality Gates / Build and Test` ← **required for merge**
- `Quality Gates / Lint` ← **required for merge**
- `Quality Gates / Distro Parity Gate` ← **required for merge**
- `Quality Gates / Distro Parity / Rocky Linux 9`
- `Quality Gates / Distro Parity / RHEL UBI 9`
- `Quality Gates / Self-Audit`
- `Quality Gates / Documentation Links`
- `Quality Gates / Profile Documentation`
- `Quality Gates / Release Configuration`

### `release-publish.yaml`

Purpose: build and publish release artifacts from version tags.

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

## Distro Parity

### Scope

The `distro-parity` job matrix in `quality-gates.yaml` runs on every PR and
push to `main`. It currently covers:

| Distro | Container image | Notes |
|---|---|---|
| Rocky Linux 9 | `rockylinux:9` | Free RHEL-compatible rebuild |
| RHEL UBI 9 | `redhat/ubi9` | Red Hat Universal Base Image — ABI-compatible with RHEL 9 |

Each leg performs:
1. **Build** — `go build ./...` inside the container
2. **Unit tests** — `go test ./... -count=1` (without `-race` to keep image deps minimal)
3. **Smoke audit** — `hardbox audit --profile cis-level1 --format json`
4. **Structure assertion** — `jq` validates the JSON output has `session_id`, `overall_score`, and non-empty `modules`
5. **Findings assertion** — fails if 0 findings are returned (indicates distro detection is broken)

The `Distro Parity Gate` job aggregates all matrix results. Only this check
name needs to be added to branch protection rules.

### Limitations

- **No systemd in containers.** GitHub Actions containers do not run systemd.
  Modules that shell out to `systemctl` (services, ntp) receive empty output
  and record the check as a finding rather than erroring out. This is the
  expected degraded-but-functional behavior; the audit JSON is still valid.
- **UBI 9 ≠ full RHEL 9.** The Universal Base Image does not include every
  RPM available in the full RHEL subscription. Build and runtime behavior are
  identical for hardbox's purposes (Go binaries, standard syscalls).
- **No AlmaLinux / Amazon Linux / Fedora legs yet.** These can be added by
  extending the matrix with their OCI images.

### Adding a new distro

1. Add an entry to the `matrix.include` list in `quality-gates.yaml`:

```yaml
- distro: AlmaLinux 9
  image: almalinux:9
```

2. Ensure the image ships `dnf` and the same `Install system dependencies`
   step runs successfully.
3. No other changes are needed — the remaining steps are distro-agnostic.

---

## Branch Protection Policy

Current required checks for `main` (solo-maintainer project — no PR approval
required):

| Check name | Why required |
|---|---|
| `Build and Test` | Catch compilation and unit-test regressions |
| `Lint` | Enforce code style via golangci-lint |
| `Distro Parity Gate` | Block merges that break RHEL/Rocky compatibility |

Informational checks (run on every PR, not merge-blocking):
- `Quality Gates / Self-Audit`
- `Quality Gates / Documentation Links`
- `Quality Gates / Profile Documentation`
- `Quality Gates / Release Configuration`

Not merge-blocking by design:
- `Release Publish / Publish Release Artifacts`
- `Release Smoke / Installation and Runtime`
- `Documentation Publish / Publish GitHub Pages Site`

Branch protection settings (current):
- No required approvals (solo maintainer).
- `strict: false` — branches do not need to be up to date before merge.
- Direct pushes to `main` are not blocked at the workflow level.

---

## Release Process

1. Merge approved work into `main`.
2. Create and push a version tag.
3. `release-publish.yaml` produces Linux `amd64` and `arm64` artifacts with checksums.
4. `release-smoke.yaml` validates release assets, installer flow, and minimal runtime execution.
5. Only announce the release after publish and smoke succeed.

```bash
git checkout main
git pull --ff-only origin main
git tag v0.2.0
git push origin v0.2.0
```

---

## Security Controls

Repository-level controls enabled:
- CodeQL (actions + Go dynamic analysis)
- Secret scanning
- Private vulnerability reporting
- Checksum verification in `install.sh`

Recommended next steps:
- Dependabot version update PRs
- Artifact signing (SLSA / cosign)
- Release provenance attestations

---

## Failure Modes

### Distro parity failure

Cause:
- A code change relies on a Debian/Ubuntu-specific path, package name, or
  file location that does not exist on RPM-based systems.

Action:
- Check the failing leg's logs for the first non-zero exit.
- Common culprits: `/etc/os-release` parsing, `apt` vs `dnf`, paths under
  `/etc/default/` (Debian) vs `/etc/sysconfig/` (RHEL).
- Fix the distro-detection logic in the affected module and re-push.

### Release without artifacts

Cause:
- Tag exists but `release-publish.yaml` failed or did not upload artifacts.

Action:
- Inspect the release workflow run.
- Verify GoReleaser config (`goreleaser check`).
- Do not announce the version until `release-smoke` passes.

### Installer fails on published version

Cause:
- Missing tarball or checksums, or bad release asset naming.

Action:
- Inspect release assets on the GitHub Releases page.
- Rerun or repair release publication.
- Rerun release smoke.
