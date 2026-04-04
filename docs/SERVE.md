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
| `/` | Report list — all JSON reports sorted by date |
| `/report/<session_id>` | Single report — findings table per module |
| `/diff/<before_id>/<after_id>` | Inline diff between two reports |
| `/api/reports` | JSON API — report metadata list |

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
