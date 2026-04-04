# hardbox watch — Continuous Audit Daemon

`hardbox watch` runs a full audit on a configurable interval, writes a timestamped JSON report to disk after each run, and detects regressions by comparing each audit to the previous one.

## Quick start

```bash
# Run continuously every 6 hours, write reports to /var/lib/hardbox/reports
sudo hardbox watch --profile production --interval 6h \
    --report-dir /var/lib/hardbox/reports

# Run a single baseline audit and exit
sudo hardbox watch --profile cis-level1 --report-dir ./reports --max-runs 1

# Two-run regression check for CI (baseline then verify)
sudo hardbox watch --max-runs 2 --fail-on-regression --report-dir ./reports
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `--interval` | `5m` | Duration between audit runs — any Go duration string: `30m`, `6h`, `24h` |
| `--max-runs` | `0` | Maximum number of runs. `0` = run forever until SIGINT/SIGTERM |
| `--report-dir` / `-d` | _(config `report.output_dir`)_ | Directory for timestamped JSON report files |
| `--fail-on-regression` | `false` | Exit code 1 when any regressions are detected |
| `--quiet` | `false` | Suppress per-run diff output; only log warnings and errors |

Global flags `--profile`, `--config`, and `--log-level` are inherited from the root command.

## What happens on each iteration

1. Run a full audit against the active profile
2. Write a timestamped JSON report to `--report-dir`
3. Diff the result against the previous run (skipped on the first run — baseline)
4. If regressions are found: log a `WARN` event and (if `--fail-on-regression`) exit 1

## Report file naming

Each run produces exactly one file:

```
<report-dir>/hardbox-report-<sessionID>.json
```

Where `sessionID` is `YYYY-MM-DDTHHMMSSZ` in UTC — for example:

```
/var/lib/hardbox/reports/hardbox-report-2026-04-04T142305Z.json
```

Files are sorted lexicographically by time, consistent with the naming convention used by `hardbox audit` and `hardbox fleet audit`. These files are automatically picked up by `hardbox serve` for trend history and fleet overview.

## Regression detection

`watch` compares each run to the immediately preceding successful run:

- A **regression** is a check that was compliant in the previous run and is non-compliant now.
- On the first run (baseline), no comparison is made — the report is written and the daemon waits for the next interval.
- A failed audit run (engine error) is skipped; the previous successful report is retained as the comparison baseline.

## Alerting

To receive notifications on regressions, combine `watch` with webhook alerting (v0.5 #135):

```yaml
# /etc/hardbox/config.yaml
notifications:
  webhook: https://hooks.slack.com/services/...
  on: [regression, critical_finding]
```

## Running as a systemd service

A ready-to-use unit file is provided at `contrib/systemd/hardbox-watch.service`.

```bash
# Install and enable
sudo cp contrib/systemd/hardbox-watch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hardbox-watch

# View status and logs
sudo systemctl status hardbox-watch
sudo journalctl -u hardbox-watch -f
```

The unit file configures:
- `--interval 6h` — audit every 6 hours
- `--quiet` — suppress diff output to journald; regressions are logged as warnings
- `StateDirectory=hardbox` — reports directory at `/var/lib/hardbox/reports`
- `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp` — hardened service execution

## Using watch in CI/CD

`watch` with `--max-runs 2` and `--fail-on-regression` is the recommended pattern for catching security regressions in CI:

```yaml
# GitHub Actions example
- name: Baseline audit
  run: sudo hardbox watch --profile production --max-runs 1 --report-dir ./reports

- name: Apply changes
  run: sudo hardbox apply --profile production --dry-run

- name: Verify — fail on regression
  run: sudo hardbox watch --profile production --max-runs 1 --fail-on-regression \
       --report-dir ./reports
```

The second `watch` run detects any regression introduced by the changes and fails the pipeline with exit code 1.

For a single-comparison workflow, use [`hardbox diff`](SERVE.md) directly:

```bash
hardbox diff reports/hardbox-report-before.json reports/hardbox-report-after.json
```
