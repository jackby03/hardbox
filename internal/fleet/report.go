// Copyright (C) 2024 Jack (jackby03)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
package fleet

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"
)

// ReportFormat selects the output format for the aggregate fleet report.
type ReportFormat string

const (
	FormatText ReportFormat = "text"
	FormatHTML ReportFormat = "html"
)

// WriteReport writes an aggregate multi-host report to w.
func WriteReport(w io.Writer, results []HostResult, profile string, format ReportFormat) error {
	switch format {
	case FormatHTML:
		return writeHTML(w, results, profile)
	default:
		return writeText(w, results, profile)
	}
}

// --------------------------------------------------------------------------
// Text report
// --------------------------------------------------------------------------

func writeText(w io.Writer, results []HostResult, profile string) error {
	total := len(results)
	passed, failed := countOutcomes(results)

	fmt.Fprintf(w, "hardbox fleet report — profile: %s — %s\n", profile, time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, strings.Repeat("=", 72)+"\n")
	fmt.Fprintf(w, "Hosts: %d total  |  %d ok  |  %d failed\n\n", total, passed, failed)

	for _, r := range results {
		status := "OK"
		if !r.OK() {
			status = "FAIL"
		}
		fmt.Fprintf(w, "[%s] %s  (%s)\n", status, r.Host, r.Duration.Round(time.Millisecond))
		if !r.OK() {
			fmt.Fprintf(w, "     Error: %v\n", r.Err)
		}
	}

	return nil
}

// --------------------------------------------------------------------------
// HTML report
// --------------------------------------------------------------------------

func writeHTML(w io.Writer, results []HostResult, profile string) error {
	total := len(results)
	passed, failed := countOutcomes(results)
	ts := time.Now().UTC().Format(time.RFC3339)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>hardbox fleet report — %s</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 1200px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; }
  h1 { font-size: 1.5rem; border-bottom: 2px solid #e2e8f0; padding-bottom: .5rem; }
  .meta { color: #64748b; font-size: .875rem; margin-bottom: 1.5rem; }
  .summary { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: .5rem; padding: 1rem 1.5rem; min-width: 120px; text-align: center; }
  .card .num { font-size: 2rem; font-weight: 700; }
  .card .lbl { font-size: .75rem; text-transform: uppercase; color: #64748b; }
  .ok   { color: #16a34a; }
  .fail { color: #dc2626; }
  table { width: 100%%; border-collapse: collapse; }
  th, td { padding: .625rem .875rem; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: .875rem; }
  th { background: #f1f5f9; font-weight: 600; }
  tr:hover td { background: #f8fafc; }
  .badge { display: inline-block; padding: .2rem .6rem; border-radius: 9999px; font-size: .75rem; font-weight: 600; }
  .badge-ok   { background: #dcfce7; color: #166534; }
  .badge-fail { background: #fee2e2; color: #991b1b; }
  details summary { cursor: pointer; color: #3b82f6; font-size: .8rem; margin-top: .4rem; }
  pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: .375rem; overflow-x: auto; font-size: .75rem; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }
</style>
</head>
<body>
<h1>hardbox fleet report</h1>
<p class="meta">Profile: <strong>%s</strong> &nbsp;|&nbsp; Generated: %s</p>

<div class="summary">
  <div class="card"><div class="num">%d</div><div class="lbl">Total</div></div>
  <div class="card"><div class="num ok">%d</div><div class="lbl">Passed</div></div>
  <div class="card"><div class="num fail">%d</div><div class="lbl">Failed</div></div>
</div>

<table>
<thead><tr><th>Host</th><th>Status</th><th>Duration</th><th>Details</th></tr></thead>
<tbody>
`,
		html.EscapeString(profile),
		html.EscapeString(profile),
		html.EscapeString(ts),
		total, passed, failed,
	)

	for _, r := range results {
		badge := `<span class="badge badge-ok">OK</span>`
		detail := ""
		if !r.OK() {
			badge = `<span class="badge badge-fail">FAIL</span>`
			detail = fmt.Sprintf(
				`<details><summary>show error</summary><pre>%s</pre></details>`,
				html.EscapeString(r.Err.Error()),
			)
		} else if r.Output != "" {
			detail = fmt.Sprintf(
				`<details><summary>show output</summary><pre>%s</pre></details>`,
				html.EscapeString(r.Output),
			)
		}

		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(r.Host.String()),
			badge,
			html.EscapeString(r.Duration.Round(time.Millisecond).String()),
			detail,
		)
	}

	fmt.Fprintf(w, `</tbody>
</table>
</body>
</html>
`)
	return nil
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

func countOutcomes(results []HostResult) (passed, failed int) {
	for _, r := range results {
		if r.OK() {
			passed++
		} else {
			failed++
		}
	}
	return
}

