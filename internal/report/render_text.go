package report

import (
	"fmt"
	"io"
	"strings"
)

func renderText(r *Report, w io.Writer) error {
	sep := strings.Repeat("─", 72)

	if _, err := fmt.Fprintf(w,
		"\n%s\n  hardbox audit report\n  Session : %s\n  Profile : %s\n  Time    : %s\n%s\n",
		sep, r.SessionID, r.Profile,
		r.Timestamp.Format("2006-01-02 15:04:05 UTC"),
		sep,
	); err != nil {
		return err
	}

	for _, mod := range r.Modules {
		if _, err := fmt.Fprintf(w, "\nModule: %-20s  Score: %3d%%\n", mod.Name, mod.Score); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  %-12s %-10s %-8s %s\n",
			"CHECK ID", "STATUS", "SEVERITY", "TITLE"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  %s\n", strings.Repeat("·", 68)); err != nil {
			return err
		}

		for _, f := range mod.Findings {
			statusIcon := statusSymbol(f.Status)
			if _, err := fmt.Fprintf(w, "  %-12s %s %-8s %-8s %s\n",
				f.CheckID, statusIcon, f.Status, f.Severity, f.Title); err != nil {
				return err
			}
			if f.Detail != "" {
				if _, err := fmt.Fprintf(w, "    ↳ %s\n", f.Detail); err != nil {
					return err
				}
			}
		}
	}

	compliant, total := countFindings(r)
	if _, err := fmt.Fprintf(w,
		"\n%s\n  Overall score: %d%%   Findings: %d compliant / %d total\n%s\n\n",
		sep, r.OverallScore, compliant, total, sep,
	); err != nil {
		return err
	}

	return nil
}

func statusSymbol(status string) string {
	switch status {
	case "compliant":
		return "✓"
	case "non-compliant":
		return "✗"
	case "manual":
		return "?"
	case "skipped":
		return "-"
	default:
		return "!"
	}
}

func countFindings(r *Report) (compliant, total int) {
	for _, mod := range r.Modules {
		for _, f := range mod.Findings {
			total++
			if f.Status == "compliant" {
				compliant++
			}
		}
	}
	return
}
