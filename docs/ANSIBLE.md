# hardbox — Ansible Role

The `hardbox` Ansible role installs the hardbox binary on target hosts and
applies a compliance profile. It supports all built-in profiles, custom
profile files, audit-only mode, report fetching, rollback on failure, and
a systemd timer for periodic re-hardening.

---

## Installation

### From Ansible Galaxy

```bash
ansible-galaxy role install jackby03.hardbox
```

### From this repository

```bash
ansible-galaxy role install \
  --roles-path ./roles \
  git+https://github.com/jackby03/hardbox,main#subdirectory=ansible-role/hardbox
```

Or add to `requirements.yml`:

```yaml
roles:
  - name: jackby03.hardbox
    src: https://github.com/jackby03/hardbox
    scm: git
    version: main
```

---

## Role Structure

```
ansible-role/hardbox/
├── defaults/main.yml          # All user-configurable variables with defaults
├── vars/main.yml              # Internal variables (arch map, paths, URLs)
├── tasks/
│   ├── main.yml               # Entrypoint — orchestrates install, apply/audit, timer
│   ├── install.yml            # Download binary, verify checksum, install
│   ├── apply.yml              # hardbox apply with rescue/rollback block
│   ├── audit.yml              # hardbox audit (read-only)
│   └── timer.yml              # systemd timer for periodic re-hardening
├── handlers/main.yml          # Systemd reload, timer restart, install verify
├── templates/
│   ├── hardbox-harden.service.j2
│   └── hardbox-harden.timer.j2
├── meta/main.yml              # Galaxy metadata, platform support, dependencies
├── molecule/default/          # Integration tests (Docker + Molecule)
│   ├── molecule.yml
│   ├── converge.yml
│   └── verify.yml
└── README.md
```

---

## Quick Start

### 1. Inventory

```ini
# inventory/hosts
[web]
web-01.example.com
web-02.example.com

[db]
db-01.example.com
```

### 2. Playbook

```yaml
# harden.yml
- hosts: all
  become: true
  roles:
    - role: jackby03.hardbox
      vars:
        hardbox_profile: cis-level1
        hardbox_fetch_report: true
```

### 3. Run

```bash
# Dry-run first
ansible-playbook harden.yml -i inventory/hosts --extra-vars hardbox_dry_run=true

# Apply hardening
ansible-playbook harden.yml -i inventory/hosts

# Audit only (no changes)
ansible-playbook harden.yml -i inventory/hosts --extra-vars hardbox_apply=false
```

---

## Variable Reference

### Installation

| Variable | Default | Description |
|---|---|---|
| `hardbox_version` | `"latest"` | Release tag (`"v0.3.0"`) or `"latest"` |
| `hardbox_install_dir` | `/usr/local/bin` | Binary destination |
| `hardbox_force_reinstall` | `false` | Re-install even if version matches |

### Profile

| Variable | Default | Description |
|---|---|---|
| `hardbox_profile` | `"production"` | Built-in profile name |
| `hardbox_custom_profile_src` | `""` | Path to a custom YAML profile on the controller |

### Run mode

| Variable | Default | Description |
|---|---|---|
| `hardbox_apply` | `true` | Apply hardening; set `false` for audit-only |
| `hardbox_dry_run` | `false` | Preview changes without applying |
| `hardbox_non_interactive` | `true` | Always pass `--non-interactive` |

### Reporting

| Variable | Default | Description |
|---|---|---|
| `hardbox_report_format` | `"html"` | `html`, `json`, `text`, `markdown` |
| `hardbox_report_dir` | `/var/lib/hardbox/reports` | Report dir on target |
| `hardbox_fetch_report` | `false` | Copy report to controller |
| `hardbox_fetch_report_dest` | `"{{ playbook_dir }}/hardbox-reports"` | Controller destination |

### Audit thresholds

| Variable | Default | Description |
|---|---|---|
| `hardbox_fail_on_critical` | `true` | Fail play on critical findings |
| `hardbox_fail_on_high` | `true` | Fail play on high findings |
| `hardbox_fail_on_medium` | `false` | Fail play on medium findings |

### Rollback

| Variable | Default | Description |
|---|---|---|
| `hardbox_rollback_on_failure` | `true` | Run `hardbox rollback apply --last` on failure |

### Systemd timer

| Variable | Default | Description |
|---|---|---|
| `hardbox_timer_enabled` | `false` | Install systemd re-hardening timer |
| `hardbox_timer_schedule` | `"daily"` | `OnCalendar` value |
| `hardbox_timer_on_boot_sec` | `"5min"` | `OnBootSec` value |

---

## Profiles

Any profile shipped in `configs/profiles/` is valid:

| Profile | Framework |
|---|---|
| `cis-level1` | CIS Benchmarks Level 1 |
| `cis-level2` | CIS Benchmarks Level 2 |
| `pci-dss` | PCI-DSS v4.0 |
| `stig` | DISA STIG |
| `hipaa` | HIPAA Security Rule |
| `iso27001` | ISO/IEC 27001:2022 |
| `cloud-aws` | CIS AWS Foundations v2.0 |
| `cloud-gcp` | CIS GCP Foundations v2.0 |
| `cloud-azure` | CIS Azure Foundations v2.1 |
| `production` | hardbox curated |
| `development` | hardbox curated |

---

## Running Integration Tests

Tests use [Molecule](https://ansible.readthedocs.io/projects/molecule/) with Docker.

```bash
cd ansible-role/hardbox

# Install test dependencies
pip install molecule molecule-plugins[docker] ansible-lint yamllint

# Run the full test matrix (Ubuntu 22.04, Debian 12, Rocky Linux 9)
molecule test

# Run only the converge step (faster iteration)
molecule converge

# Run only the verify step
molecule verify

# Destroy test containers
molecule destroy
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/harden.yml
name: Harden servers

on:
  push:
    branches: [main]
  schedule:
    - cron: "0 2 * * *"   # nightly re-hardening audit

jobs:
  harden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Ansible
        run: pip install ansible

      - name: Install hardbox role
        run: ansible-galaxy role install jackby03.hardbox

      - name: Audit compliance
        run: |
          ansible-playbook harden.yml \
            -i inventory/production \
            --extra-vars "hardbox_apply=false hardbox_fetch_report=true"

      - name: Upload compliance reports
        uses: actions/upload-artifact@v4
        with:
          name: hardbox-reports
          path: hardbox-reports/
```
