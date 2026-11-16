# Custom checks

hardbox ships 220 checks across 24 modules, and profiles let you change the
**values** those checks expect. This document is about the other half: adding a
check that does not exist yet, without writing Go.

Custom checks are declarative YAML files in `/etc/hardbox/checks.d/` (override with
`custom_checks_dir` in `config.yaml`). Every `.yaml` or `.yml` file is loaded at
startup.

```bash
sudo mkdir -p /etc/hardbox/checks.d
sudo cp examples/custom-checks/example.yaml /etc/hardbox/checks.d/
sudo hardbox audit --profile cis-level1 --format text
```

Findings appear in the report grouped under the prefix of their check ID — the
`corp` in `corp-001` — with their own score, exactly like a built-in module.

---

## Why declarative

A check file is written by someone who already has root. Even so, a config file
that can execute arbitrary commands turns "can write to `/etc/hardbox/checks.d`"
into "can run code as root", which is a privilege boundary most teams do not want
to widen by accident.

So assertions are a fixed vocabulary — file expectations and sysctl values — and
there is no `command:` field. If a check needs logic that cannot be expressed here,
it belongs in a module, not in YAML.

---

## Schema

```yaml
version: "1"

checks:
  - id: corp-001                 # required: <prefix>-NNN, prefix must not be a built-in
    title: Authorized-use banner # required
    description: Longer explanation (optional)
    remediation: What a human should do (optional, shown in reports)
    severity: medium             # required: low | medium | high | critical
    compliance:                  # optional, but recommended
      - framework: NIST
        control: AC-8
    audit_only: false            # required to be true when there is no remediation
    assert:
      file: { ... }              # exactly one of file / sysctl
    remediate:
      write: { ... }             # required unless audit_only is true
```

### `assert.file`

| Field | Meaning |
|---|---|
| `path` | Absolute path. Required. |
| `exists` | `true` means the file must exist, `false` means it must not. |
| `contains` | The content must include this substring. |
| `not_contains` | The content must not include this substring. |
| `equals` | The content must match exactly, byte for byte. |
| `mode` | Octal mode the file must have, e.g. `"0644"`. |
| `owner` | User name that must own the file, e.g. `root`. |

At least one expectation is required. All of them are checked; the first failure is
reported.

### `assert.sysctl`

| Field | Meaning |
|---|---|
| `key` | Dotted kernel parameter, e.g. `kernel.kptr_restrict`. |
| `equals` | Required value, compared after trimming whitespace. |

### `remediate.write`

| Field | Meaning |
|---|---|
| `path` | Absolute path. Must match `assert.file.path`. |
| `content` | Exact file content to write. |
| `mode` | Octal mode, default `0644`. |

The write goes through hardbox's atomic write helper, and the path is declared for
the snapshot, so `hardbox rollback apply --last` restores the previous content.

The parent directory must already exist. A wrong path fails instead of creating
directories across the host.

---

## What is validated at load time

A malformed check file makes `hardbox` log the error and **skip the whole file** —
it never half-applies a baseline. Rejected cases:

- `version` other than `"1"`, or a file with no checks
- an `id` that is not `<prefix>-NNN`, or whose prefix collides with a built-in
  module (`ssh`, `fs`, `kn`, …) — the report groups findings by prefix, so a
  collision would merge your findings into a built-in module
- a duplicate `id` across files
- a missing `title`, or a `severity` outside the four allowed values
- `assert` that sets both `file` and `sysctl`, or neither
- a `remediate.write.path` that is relative, or that differs from `assert.file.path`
- a non-octal `mode`
- a check that is neither remediable nor marked `audit_only: true`

---

## Current limitations

- **`sysctl` checks are audit-only.** Writing kernel parameters from YAML is not
  automated in this version; mark them `audit_only: true`.
- **`owner` is only checked on Unix.** Elsewhere the finding is `manual` rather
  than wrong.
- **No templating or variables.** Content is written verbatim.
- **Not covered by the documentation gates.** Those scan the modules compiled into
  hardbox, so your checks are documented by your own files, not by
  `docs/COMPLIANCE.md`.

---

## See also

- [`MODULES.md`](MODULES.md) — the built-in checks you can override with profiles
- [`ROADMAP.md`](ROADMAP.md#pillar-3--custom-rules) — where this sits in the plan
- [`examples/custom-checks/example.yaml`](../examples/custom-checks/example.yaml)
