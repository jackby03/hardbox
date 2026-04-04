package report

import (
	"fmt"
	"io"
	"strings"
)

// WriteDiff renders a DiffReport to w in the requested format.
// Supported formats: "text" (default), "json", "html".
func WriteDiff(d *DiffReport, format string, w io.Writer) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return renderJSON(d, w)
	case "html":
		return renderDiffHTML(d, w)
	case "text", "":
		return renderDiffText(d, w)
	default:
		if _, err := fmt.Fprintf(w, "# Warning: unknown format %q — falling back to text\n\n", format); err != nil {
			return err
		}
		return renderDiffText(d, w)
	}
}

func renderDiffText(d *DiffReport, w io.Writer) error {
	p := func(format string, args ...any) error {
		_, err := fmt.Fprintf(w, format, args...)
		return err
	}

	// Header
	if err := p("hardbox audit diff\n%s\n\n", strings.Repeat("=", 60)); err != nil {
		return err
	}

	// Before / After summary
	if err := p("Before  session=%-36s profile=%-15s score=%3d\n",
		d.Before.SessionID, d.Before.Profile, d.Before.Score); err != nil {
		return err
	}
	if err := p("After   session=%-36s profile=%-15s score=%3d\n",
		d.After.SessionID, d.After.Profile, d.After.Score); err != nil {
		return err
	}

	// Score delta
	delta := d.ScoreDelta
	sign := "+"
	if delta < 0 {
		sign = ""
	}
	if err := p("\nScore delta: %s%d\n", sign, delta); err != nil {
		return err
	}

	// One-line summary
	if err := p("Summary: %d regression(s)  %d improvement(s)  %d unchanged failure(s)  %d new check(s)\n",
		len(d.Regressions), len(d.Improvements), len(d.Unchanged), len(d.NewChecks)); err != nil {
		return err
	}

	if len(d.Regressions) > 0 {
		if err := p("\n%s REGRESSIONS (%d) — checks that now fail\n%s\n",
			"🔴", len(d.Regressions), strings.Repeat("-", 60)); err != nil {
			return err
		}
		if err := writeDiffFindingTable(w, d.Regressions); err != nil {
			return err
		}
	}

	if len(d.Improvements) > 0 {
		if err := p("\n%s IMPROVEMENTS (%d) — checks that now pass\n%s\n",
			"🟢", len(d.Improvements), strings.Repeat("-", 60)); err != nil {
			return err
		}
		if err := writeDiffFindingTable(w, d.Improvements); err != nil {
			return err
		}
	}

	if len(d.Unchanged) > 0 {
		if err := p("\n%s UNCHANGED FAILURES (%d)\n%s\n",
			"🟡", len(d.Unchanged), strings.Repeat("-", 60)); err != nil {
			return err
		}
		if err := writeDiffFindingTable(w, d.Unchanged); err != nil {
			return err
		}
	}

	if len(d.NewChecks) > 0 {
		if err := p("\n🔵 NEW FAILING CHECKS (%d)\n%s\n",
			len(d.NewChecks), strings.Repeat("-", 60)); err != nil {
			return err
		}
		if err := writeDiffFindingTable(w, d.NewChecks); err != nil {
			return err
		}
	}

	return nil
}

func writeDiffFindingTable(w io.Writer, findings []DiffFinding) error {
	if len(findings) == 0 {
		return nil
	}
	_, err := fmt.Fprintf(w, "  %-12s %-10s %-15s %-15s  %s\n",
		"CHECK-ID", "SEVERITY", "BEFORE", "AFTER", "TITLE")
	if err != nil {
		return err
	}
	for _, f := range findings {
		if _, err := fmt.Fprintf(w, "  %-12s %-10s %-15s %-15s  %s\n",
			f.CheckID, f.Severity, f.StatusBefore, f.StatusAfter, f.Title); err != nil {
			return err
		}
	}
	return nil
}
