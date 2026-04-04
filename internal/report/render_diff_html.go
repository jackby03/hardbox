package report

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"
)

func renderDiffHTML(d *DiffReport, w io.Writer) error {
	sign := "+"
	if d.ScoreDelta < 0 {
		sign = ""
	}
	deltaClass := "neutral"
	if d.ScoreDelta > 0 {
		deltaClass = "positive"
	} else if d.ScoreDelta < 0 {
		deltaClass = "negative"
	}

	p := func(s string, args ...any) error {
		_, err := fmt.Fprintf(w, s, args...)
		return err
	}

	if err := p(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>hardbox audit diff</title>
<style>
  :root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;
    --red:#f87171;--green:#4ade80;--yellow:#facc15;--blue:#60a5fa;--badge-bg:#0f172a}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;padding:2rem}
  h1{font-size:1.5rem;font-weight:700;margin-bottom:.25rem}
  .subtitle{color:var(--muted);margin-bottom:2rem;font-size:.875rem}
  .meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:2rem}
  .meta-card{background:var(--card);border:1px solid var(--border);border-radius:.5rem;padding:1rem}
  .meta-card h3{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:.5rem}
  .score{font-size:2rem;font-weight:700}
  .delta{font-size:1.25rem;font-weight:700;margin-bottom:1.5rem}
  .delta.positive{color:var(--green)}.delta.negative{color:var(--red)}.delta.neutral{color:var(--muted)}
  .summary-bar{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}
  .badge{display:inline-flex;align-items:center;gap:.4rem;padding:.35rem .75rem;border-radius:9999px;font-size:.8rem;font-weight:600;background:var(--card);border:1px solid var(--border)}
  .badge.red{border-color:var(--red);color:var(--red)}
  .badge.green{border-color:var(--green);color:var(--green)}
  .badge.yellow{border-color:var(--yellow);color:var(--yellow)}
  .badge.blue{border-color:var(--blue);color:var(--blue)}
  .section{margin-bottom:2rem}
  .section-title{font-size:1rem;font-weight:600;margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem}
  table{width:100%%;border-collapse:collapse;background:var(--card);border-radius:.5rem;overflow:hidden;border:1px solid var(--border)}
  th{background:#0f172a;padding:.6rem 1rem;text-align:left;font-size:.75rem;text-transform:uppercase;color:var(--muted);letter-spacing:.05em}
  td{padding:.6rem 1rem;border-top:1px solid var(--border);vertical-align:top}
  .sev-critical{color:#f87171}.sev-high{color:#fb923c}.sev-medium{color:var(--yellow)}.sev-low{color:var(--blue)}.sev-info{color:var(--muted)}
  .status{display:inline-block;padding:.15rem .5rem;border-radius:.25rem;font-size:.75rem;font-weight:600}
  .status-compliant{background:#14532d;color:#4ade80}
  .status-non-compliant{background:#450a0a;color:#f87171}
  .status-skipped,.status-manual{background:#1e293b;color:#94a3b8}
  .footer{margin-top:3rem;color:var(--muted);font-size:.75rem;text-align:center}
</style>
</head>
<body>
<h1>hardbox audit diff</h1>
<p class="subtitle">Generated %s</p>
`, html.EscapeString(time.Now().UTC().Format(time.RFC1123))); err != nil {
		return err
	}

	// Meta cards
	if err := p(`<div class="meta-grid">
  <div class="meta-card">
    <h3>Before</h3>
    <div class="score">%d</div>
    <div style="color:var(--muted);font-size:.8rem;margin-top:.5rem">%s · %s</div>
  </div>
  <div class="meta-card">
    <h3>After</h3>
    <div class="score">%d</div>
    <div style="color:var(--muted);font-size:.8rem;margin-top:.5rem">%s · %s</div>
  </div>
</div>
`, d.Before.Score, html.EscapeString(d.Before.Profile), html.EscapeString(d.Before.Timestamp.Format("2006-01-02 15:04 UTC")),
		d.After.Score, html.EscapeString(d.After.Profile), html.EscapeString(d.After.Timestamp.Format("2006-01-02 15:04 UTC"))); err != nil {
		return err
	}

	// Delta + summary badges
	if err := p(`<div class="delta %s">Score: %s%d</div>
<div class="summary-bar">
  <span class="badge red">🔴 %d regression(s)</span>
  <span class="badge green">🟢 %d improvement(s)</span>
  <span class="badge yellow">🟡 %d unchanged failure(s)</span>
  <span class="badge blue">🔵 %d new check(s)</span>
</div>
`, deltaClass, sign, d.ScoreDelta,
		len(d.Regressions), len(d.Improvements), len(d.Unchanged), len(d.NewChecks)); err != nil {
		return err
	}

	// Sections
	sections := []struct {
		emoji    string
		title    string
		findings []DiffFinding
		cls      string
	}{
		{"🔴", "Regressions — checks that now fail", d.Regressions, "red"},
		{"🟢", "Improvements — checks that now pass", d.Improvements, "green"},
		{"🟡", "Unchanged Failures", d.Unchanged, "yellow"},
		{"🔵", "New Failing Checks", d.NewChecks, "blue"},
	}

	for _, sec := range sections {
		if len(sec.findings) == 0 {
			continue
		}
		if err := p(`<div class="section">
<div class="section-title"><span>%s</span><span>%s (%d)</span></div>
<table>
<thead><tr><th>Check ID</th><th>Severity</th><th>Before</th><th>After</th><th>Title</th></tr></thead>
<tbody>
`, sec.emoji, html.EscapeString(sec.title), len(sec.findings)); err != nil {
			return err
		}
		for _, f := range sec.findings {
			if err := p(`<tr>
  <td><code>%s</code></td>
  <td><span class="sev-%s">%s</span></td>
  <td><span class="status status-%s">%s</span></td>
  <td><span class="status status-%s">%s</span></td>
  <td>%s</td>
</tr>
`, html.EscapeString(f.CheckID),
				html.EscapeString(f.Severity), html.EscapeString(f.Severity),
				html.EscapeString(strings.ReplaceAll(f.StatusBefore, "-", "")), html.EscapeString(f.StatusBefore),
				html.EscapeString(strings.ReplaceAll(f.StatusAfter, "-", "")), html.EscapeString(f.StatusAfter),
				html.EscapeString(f.Title)); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "</tbody></table></div>\n"); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(w, `<div class="footer">hardbox — %s</div>
</body></html>`, html.EscapeString(time.Now().UTC().Format("2006")))
	return err
}
