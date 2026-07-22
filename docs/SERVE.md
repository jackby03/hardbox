# hardbox serve — Web Dashboard

`hardbox serve` starts a local, read-only HTTP dashboard for browsing audit reports, inspecting findings, and comparing reports side by side.

## Usage

```bash
hardbox serve [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--reports-dir` | `.` | Directory containing JSON audit reports |
| `--port` | `8080` | Port to listen on (ignored when `--addr` is set) |
| `--addr` | `127.0.0.1:8080` | Full listen address — override to change host |
| `--no-open` | `false` | Do not open the browser automatically |
| `--basic-auth` | _(none)_ | Enable HTTP Basic Auth: `user:pass` |

## Quick start

```bash
# Run an audit and save the report
hardbox audit --format json --output /var/log/hardbox/reports/$(date +%s).json

# Start the dashboard
hardbox serve --reports-dir /var/log/hardbox/reports/
# → hardbox dashboard → http://127.0.0.1:8080
```

## Dashboard routes

| Route | Description |
|---|---|
| `/` | Report list or fleet overview (auto-detected) |
| `/report/<session_id>` | Single report — findings table per module |
| `/diff/<before_id>/<after_id>` | Inline diff between two reports |
| `/fleet` | Fleet overview — host table with scores and trends |
| `/host/<hostname>` | Per-host drill-down — score sparkline and history |
| `/api/reports` | JSON API — report metadata list |

## Fleet overview (v0.5)

When JSON reports from multiple hosts are present in `--reports-dir`
(each report must include a non-empty `hostname` field), the dashboard
automatically switches to fleet overview mode.

The fleet page shows:

- **Host table** — hostname, last audit timestamp, compliance score, delta
- **Regression indicator** — hosts with score drops highlighted in red
- **Trend sparklines** — inline SVG bars per host showing score history
- **Per-host drill-down** — click hostname to see all reports and score chart

```bash
# Generate fleet reports on multiple hosts
hardbox fleet audit --hosts hosts.txt --profile production

# Start the dashboard — fleet view auto-detected
hardbox serve --reports-dir /var/log/hardbox/reports/
```

## Compliance trend history (v0.5)

The dashboard renders SVG sparklines from historical JSON reports in the
reports directory. No database required — history is derived from files
on disk produced by `hardbox watch` or consecutive audit runs.

- **Single-host view** — trend card above the report list with stats
- **Host detail** — sparkline with high, low, and delta from first report
- **Fleet rows** — mini sparklines per host in the fleet table
- **Color coding** — green (>=80%), yellow (>=50%), red (<50%)
- **Graceful** — single report shows "need more data"; two+ renders sparkline

## Security

- Binds to `127.0.0.1` by default — not reachable from the network.
- To expose on the local network (e.g. in a shared lab), set `--addr 0.0.0.0:8080` and protect with `--basic-auth`.
- Read-only — no write operations are exposed via HTTP.
- All assets are embedded in the binary via `go:embed` — no external CDN or internet access required.

## Examples

```bash
# Custom port, no browser
hardbox serve --port 9000 --reports-dir ./reports/ --no-open

# Shared access with basic auth
hardbox serve --addr 0.0.0.0:8080 --basic-auth ops:s3cr3t --reports-dir /var/log/hardbox/reports/

# Compare two specific reports from the UI
# Navigate to: http://127.0.0.1:8080/diff/<before_session_id>/<after_session_id>
```
