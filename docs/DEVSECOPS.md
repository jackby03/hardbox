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

The `distro-parity` job matrix in `quality-gates.yaml` runs on every push to
`main`, and on a pull request only when the PR carries the `full-ci` label (or
when the workflow is dispatched manually). Running the two container legs on
every PR cost roughly a minute and a half of wall clock for changes that cannot
possibly affect distro behaviour; `main` always gets the full matrix, so a
distro regression is still caught before it can reach a release.

To request the full suite on a PR, add the label:

```bash
gh pr edit <number> --add-label full-ci
```

The `Distro Parity Gate` job reports success when the matrix was skipped, so a
PR that did not opt in is never left pending. It covers one representative of
each family the README claims to support:

| Distro | Container image | Family |
|---|---|---|
| Rocky Linux 9 | `rockylinux:9` | RPM |
| RHEL UBI 9 | `redhat/ubi9` | RPM |
| AlmaLinux 9 | `almalinux:9` | RPM |
| Debian 12 | `debian:12` | Debian |
| Amazon Linux 2023 | `amazonlinux:2023` | RPM |
| Fedora 41 | `fedora:41` | RPM |

Ubuntu is covered implicitly: `build-and-test`, `lint` and `Self-Audit` run
`hardbox` on the `ubuntu-latest` runner itself.

Each leg performs:
1. **Build** — `go build ./...` inside the container
2. **Unit tests** — `go test ./... -count=1` (without `-race` to keep image deps minimal)
3. **Smoke audit** — `hardbox audit --profile cis-level1 --format json`
4. **Structure assertion** — `jq` validates the JSON output has `session_id`, `overall_score`, and non-empty `modules`
5. **Findings assertion** — fails if 0 findings are returned (indicates distro detection is broken)
6. **Partial-audit report** — prints the modules listed under `module_errors` (informational)
7. **Plan assertion** — `hardbox apply --dry-run` must build a plan and no module may fail to plan
8. **Package-manager assertion** — the plan must not invoke a package manager from the
   other family. A Debian image may not mention `dnf`, `yum`, `zypper` or `pacman`; an RPM
   image may not mention `apt-get`. This is the check that catches a remediation hardcoding
   a package manager without executing it.

Step 7 exercises `Plan()` on every distro. Step 8 inspects the plan text, which is the only
place the chosen package manager is visible before `Apply()` runs — four modules used to
call `apt-get` or `yum` directly, which passed every other check in this job while being
broken on five of the six images.

Each leg runs against a **bare container**. It deliberately does not create stub
config files such as `/etc/ssh/sshd_config` or `/etc/login.defs`: a previous
revision did, which meant the job validated a system nobody runs and hid the
fact that a single missing file aborted the entire audit. A module whose config
is absent must report its checks as `skipped`, and the report must still be
produced in full.

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
- **One image per family.** Six legs cover the two package-manager families,
  not every point release. A version-specific regression in, say, Ubuntu 22.04
  versus 24.04 will not be caught.

### Adding a new distro

1. Add an entry to the `matrix.include` list in `quality-gates.yaml`:

```yaml
- distro: openSUSE Leap 15
  image: opensuse/leap:15.6
  slug: opensuse-leap-15
```

2. If the image is neither Debian-based nor RPM-based, extend the
   `Install system dependencies` step: it detects `apt-get` and otherwise
   assumes `dnf`.
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
