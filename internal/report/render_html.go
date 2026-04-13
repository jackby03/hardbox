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
package report

import (
	"fmt"
	"html"
	"io"
	"strings"
)

// htmlCSS is the embedded stylesheet for the HTML report.
// Kept separate from fmt.Fprintf calls to avoid misinterpreting CSS as format verbs.
const htmlCSS = `<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       background:#0f1117;color:#e2e8f0;line-height:1.6}
  header{background:#1a1d27;border-bottom:1px solid #2d3148;padding:24px 40px}
  header h1{font-size:1.4rem;font-weight:600;color:#a78bfa}
  header .meta{font-size:.85rem;color:#94a3b8;margin-top:6px}
  main{max-width:1200px;margin:32px auto;padding:0 40px}
  .summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
           gap:16px;margin-bottom:32px}
  .card{background:#1a1d27;border:1px solid #2d3148;border-radius:10px;padding:20px}
  .card .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;
               color:#64748b;margin-bottom:6px}
  .card .value{font-size:1.8rem;font-weight:700}
  .score-good{color:#34d399}
  .score-warn{color:#fbbf24}
  .score-bad{color:#f87171}
  .module{background:#1a1d27;border:1px solid #2d3148;border-radius:10px;
          margin-bottom:24px;overflow:hidden}
  .module-header{display:flex;justify-content:space-between;align-items:center;
                 padding:14px 20px;background:#22253a;border-bottom:1px solid #2d3148}
  .module-name{font-weight:600;font-size:1rem}
  .module-score{font-size:.9rem;font-weight:600}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th{text-align:left;padding:10px 16px;font-size:.75rem;text-transform:uppercase;
     letter-spacing:.05em;color:#64748b;border-bottom:1px solid #2d3148}
  td{padding:10px 16px;border-bottom:1px solid #1e2235;vertical-align:top}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#1e2235}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;
         font-weight:600;text-transform:uppercase}
  .badge-compliant{background:#064e3b;color:#34d399}
  .badge-non-compliant{background:#7f1d1d;color:#f87171}
  .badge-manual{background:#78350f;color:#fbbf24}
  .badge-skipped{background:#1e293b;color:#94a3b8}
  .sev-critical{color:#f87171;font-weight:600}
  .sev-high{color:#fb923c;font-weight:600}
  .sev-medium{color:#fbbf24}
  .sev-low{color:#94a3b8}
  .sev-info{color:#64748b}
  .detail{color:#94a3b8;font-size:.8rem;margin-top:2px}
  code{background:#0f1117;padding:1px 5px;border-radius:3px;font-size:.85em;
       font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace}
  footer{text-align:center;padding:24px;color:#475569;font-size:.8rem}
</style>`

// renderHTML writes a self-contained HTML audit report to w.
// The output is a single HTML file with embedded CSS — no external dependencies.
func renderHTML(r *Report, w io.Writer) error {
	compliant, total := countFindings(r)
	scoreClass := scoreCSS(r.OverallScore)

	// ── document head ─────────────────────────────────────────────────────────
	if _, err := fmt.Fprintf(w,
		"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"+
			"<meta charset=\"UTF-8\">\n"+
			"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"+
			"<title>hardbox Audit Report \u2014 %s</title>\n",
		html.EscapeString(r.Profile),
	); err != nil {
		return err
	}
	if _, err := io.WriteString(w, htmlCSS+"\n</head>\n<body>\n"); err != nil {
		return err
	}

	// ── header ────────────────────────────────────────────────────────────────
	if _, err := fmt.Fprintf(w,
		"<header>\n  <h1>hardbox Audit Report</h1>\n"+
			"  <div class=\"meta\">\n"+
			"    Session: <code>%s</code> &nbsp;&middot;&nbsp;\n"+
			"    Profile: <code>%s</code> &nbsp;&middot;&nbsp;\n"+
			"    Generated: %s\n"+
			"  </div>\n</header>\n<main>\n",
		html.EscapeString(r.SessionID),
		html.EscapeString(r.Profile),
		r.Timestamp.Format("2006-01-02 15:04:05 UTC"),
	); err != nil {
		return err
	}

	// ── summary cards ─────────────────────────────────────────────────────────
	if _, err := fmt.Fprintf(w,
		"<div class=\"summary\">\n"+
			"  <div class=\"card\"><div class=\"label\">Overall Score</div>"+
			"<div class=\"value %s\">%d%%</div></div>\n"+
			"  <div class=\"card\"><div class=\"label\">Modules</div>"+
			"<div class=\"value\">%d</div></div>\n"+
			"  <div class=\"card\"><div class=\"label\">Compliant</div>"+
			"<div class=\"value score-good\">%d</div></div>\n"+
			"  <div class=\"card\"><div class=\"label\">Total Findings</div>"+
			"<div class=\"value\">%d</div></div>\n"+
			"</div>\n",
		scoreClass, r.OverallScore, len(r.Modules), compliant, total,
	); err != nil {
		return err
	}

	// ── per-module tables ─────────────────────────────────────────────────────
	for _, mod := range r.Modules {
		modScoreClass := scoreCSS(mod.Score)
		if _, err := fmt.Fprintf(w,
			"<div class=\"module\">\n"+
				"  <div class=\"module-header\">\n"+
				"    <span class=\"module-name\">%s</span>\n"+
				"    <span class=\"module-score %s\">Score: %d%%</span>\n"+
				"  </div>\n"+
				"  <table>\n    <thead>\n      <tr>\n"+
				"        <th>Check ID</th><th>Status</th><th>Severity</th>"+
				"<th>Title / Detail</th><th>Current &rarr; Target</th>\n"+
				"      </tr>\n    </thead>\n    <tbody>\n",
			html.EscapeString(mod.Name),
			modScoreClass,
			mod.Score,
		); err != nil {
			return err
		}

		for _, f := range mod.Findings {
			detail := ""
			if f.Detail != "" {
				detail = fmt.Sprintf(
					"<div class=\"detail\">%s</div>",
					html.EscapeString(f.Detail),
				)
			}

			currentTarget := ""
			if f.Current != "" || f.Target != "" {
				currentTarget = fmt.Sprintf(
					"<code>%s</code> &rarr; <code>%s</code>",
					html.EscapeString(f.Current),
					html.EscapeString(f.Target),
				)
			}

			if _, err := fmt.Fprintf(w,
				"      <tr>\n"+
					"        <td><code>%s</code></td>\n"+
					"        <td><span class=\"%s\">%s</span></td>\n"+
					"        <td><span class=\"%s\">%s</span></td>\n"+
					"        <td>%s%s</td>\n"+
					"        <td>%s</td>\n"+
					"      </tr>\n",
				html.EscapeString(f.CheckID),
				htmlStatusBadgeClass(f.Status),
				html.EscapeString(f.Status),
				htmlSeverityClass(f.Severity),
				html.EscapeString(f.Severity),
				html.EscapeString(f.Title),
				detail,
				currentTarget,
			); err != nil {
				return err
			}
		}

		if _, err := io.WriteString(w, "    </tbody>\n  </table>\n</div>\n"); err != nil {
			return err
		}
	}

	// ── footer ────────────────────────────────────────────────────────────────
	_, err := fmt.Fprintf(w,
		"</main>\n<footer>%d compliant / %d total findings &mdash; generated by <strong>hardbox</strong></footer>\n</body>\n</html>\n",
		compliant, total,
	)
	return err
}

func scoreCSS(score int) string {
	switch {
	case score >= 80:
		return "score-good"
	case score >= 50:
		return "score-warn"
	default:
		return "score-bad"
	}
}

func htmlStatusBadgeClass(status string) string {
	switch strings.ToLower(status) {
	case "compliant":
		return "badge badge-compliant"
	case "non-compliant":
		return "badge badge-non-compliant"
	case "manual":
		return "badge badge-manual"
	case "skipped":
		return "badge badge-skipped"
	default:
		return "badge badge-skipped"
	}
}

func htmlSeverityClass(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	default:
		return "sev-info"
	}
}

