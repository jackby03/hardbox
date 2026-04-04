# hardbox fleet — Remote Multi-Host Hardening

`hardbox fleet` applies hardening profiles or runs compliance audits across a fleet of Linux hosts concurrently over SSH. Per-host results stream as they complete; a unified aggregate report is generated at the end.

## Quick start

```bash
# Apply the production profile to a fleet
hardbox fleet apply \
  --hosts hosts.txt \
  --profile production \
  --concurrency 10

# Audit a fleet and write an HTML report
hardbox fleet audit \
  --hosts hosts.txt \
  --profile cis-level2 \
  --format html \
  --output fleet-audit.html
```

## Hosts file format

One entry per line — blank lines and `#` comments are ignored.

```
# production web tier
deploy@10.0.1.10
deploy@10.0.1.11:2222

# bastion
admin@bastion.example.com:22
```

Format: `user@host` or `user@host:port` (default port: 22).

## Commands

### `hardbox fleet apply`

Applies the selected hardening profile to every host concurrently.

```
hardbox fleet apply [flags]

Flags:
  --hosts <file>          Path to hosts file (required)
  --concurrency N         Max parallel SSH sessions (default: 10)
  --dry-run               Preview changes without applying them
  --fail-on-critical      Exit 1 if any host reports critical findings (default: true)
  -i, --identity <file>   SSH private key file
  --host-key-file <file>  known_hosts file for host key verification

Global flags (inherited):
  -p, --profile <name>    Hardening profile (default: production)
  --log-level <level>     debug|info|warn|error (default: info)
```

### `hardbox fleet audit`

Audits every host and generates a unified aggregate report.

```
hardbox fleet audit [flags]

Flags:
  --hosts <file>          Path to hosts file (required)
  --concurrency N         Max parallel SSH sessions (default: 10)
  --format text|html      Report format (default: text)
  -o, --output <file>     Write aggregate report to file (default: stdout)
  --fail-on-critical      Exit 1 if any host reports critical findings (default: true)
  -i, --identity <file>   SSH private key file
  --host-key-file <file>  known_hosts file for host key verification
```

## SSH authentication

`hardbox fleet` delegates SSH connections to the system `ssh` binary. All standard authentication methods are supported:

| Method | How to use |
|--------|-----------|
| SSH agent | Set `$SSH_AUTH_SOCK` (default) |
| Private key | `-i ~/.ssh/id_ed25519` |
| `~/.ssh/config` | Works automatically |

## Host key verification

Host key checking is **always enabled** (`StrictHostKeyChecking=yes`). Unknown host keys are rejected.

```bash
# Scan host keys into a dedicated known_hosts file
ssh-keyscan -t ed25519 10.0.1.10 10.0.1.11 >> fleet-known-hosts

# Use the dedicated file
hardbox fleet audit \
  --hosts hosts.txt \
  --host-key-file fleet-known-hosts
```

When `--host-key-file` is omitted, the system `~/.ssh/known_hosts` is used.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All hosts succeeded (and no critical findings when `--fail-on-critical`) |
| 1 | One or more hosts failed **or** critical findings were detected |

Failed hosts are reported clearly; the fleet run always completes all hosts.

## Concurrency

`--concurrency N` controls the maximum number of parallel SSH sessions. Tune this to avoid overwhelming the network or target hosts.

```bash
# Conservative — useful for rate-limited environments
hardbox fleet apply --hosts hosts.txt --concurrency 3

# Aggressive — for large fleets on fast networks
hardbox fleet apply --hosts hosts.txt --concurrency 50
```

## HTML report

The HTML report includes:

- **Summary cards** — total / passed / failed counts.
- **Per-host status table** — host, badge (OK / FAIL), duration, expandable output.

```bash
hardbox fleet audit \
  --hosts hosts.txt \
  --profile cis-level2 \
  --format html \
  --output /var/lib/hardbox/reports/fleet-$(date +%Y%m%d).html
```

## Requirements

- `ssh` must be in `$PATH` on the machine running `hardbox fleet`.
- `hardbox` must be installed on each remote host (use the [Ansible role](../ansible-role/) or [cloud-init](../cloud-init/) scripts to pre-install it).
- The SSH user needs `sudo` / root access on the remote hosts.
