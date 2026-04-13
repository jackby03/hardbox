# Ansible Role: hardbox

[![Ansible Galaxy](https://img.shields.io/badge/galaxy-jackby03.hardbox-blue)](https://galaxy.ansible.com/jackby03/hardbox)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](../../LICENSE)

Installs and runs [hardbox](https://github.com/jackby03/hardbox) — a Linux OS hardening tool with built-in compliance profiles.

## Requirements

- Ansible >= 2.14
- Target hosts: Ubuntu 20.04/22.04, Debian 11/12, RHEL/Rocky/AlmaLinux 8/9
- Become (sudo) access on target hosts

## Role Variables

See [`defaults/main.yml`](defaults/main.yml) for the full list with inline documentation.

| Variable | Default | Description |
|---|---|---|
| `hardbox_version` | `"latest"` | Release tag or `"latest"` |
| `hardbox_profile` | `"production"` | Compliance profile to apply |
| `hardbox_apply` | `true` | Apply hardening (`true`) or audit-only (`false`) |
| `hardbox_dry_run` | `false` | Dry-run mode — preview changes without applying |
| `hardbox_report_format` | `"html"` | Report format: `html`, `json`, `text`, `markdown` |
| `hardbox_report_dir` | `/var/lib/hardbox/reports` | Report directory on target host |
| `hardbox_fetch_report` | `false` | Fetch report to Ansible controller |
| `hardbox_fetch_report_dest` | `"{{ playbook_dir }}/hardbox-reports"` | Local report destination |
| `hardbox_rollback_on_failure` | `true` | Roll back on apply failure |
| `hardbox_timer_enabled` | `false` | Install systemd re-hardening timer |
| `hardbox_timer_schedule` | `"daily"` | systemd OnCalendar schedule |
| `hardbox_fail_on_critical` | `true` | Fail play on critical findings |
| `hardbox_fail_on_high` | `true` | Fail play on high findings |

## Example Playbooks

### Minimal — apply CIS Level 1 baseline

```yaml
- hosts: all
  become: true
  roles:
    - role: jackby03.hardbox
      vars:
        hardbox_profile: cis-level1
```

### Audit-only — check compliance without changing anything

```yaml
- hosts: production
  become: true
  roles:
    - role: jackby03.hardbox
      vars:
        hardbox_profile: pci-dss
        hardbox_apply: false
        hardbox_fetch_report: true
        hardbox_report_format: html
```

### Cloud AWS — harden and fetch report

```yaml
- hosts: aws_ec2
  become: true
  roles:
    - role: jackby03.hardbox
      vars:
        hardbox_profile: cloud-aws
        hardbox_report_format: json
        hardbox_fetch_report: true
        hardbox_timer_enabled: true
        hardbox_timer_schedule: "daily"
```

### Pin version and use custom profile

```yaml
- hosts: all
  become: true
  roles:
    - role: jackby03.hardbox
      vars:
        hardbox_version: "v0.3.0"
        hardbox_custom_profile_src: files/my-profile.yaml
        hardbox_fetch_report: true
```

## Galaxy Installation

```bash
ansible-galaxy role install jackby03.hardbox
```

Or add to `requirements.yml`:

```yaml
roles:
  - name: jackby03.hardbox
    version: ">=0.3.0"
```

```bash
ansible-galaxy install -r requirements.yml
```

## License

AGPL v3 — see [LICENSE](../../LICENSE).
