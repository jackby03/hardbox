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
	"io"
	"sort"
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
		if _, err := fmt.Fprintf(w, "\nModule: %-20s  Score: %s\n", mod.Name, scoreLabel(mod.Score)); err != nil {
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
		"\n%s\n  Overall score: %s   Findings: %d compliant / %d total\n%s\n",
		sep, scoreLabel(r.OverallScore), compliant, total, sep,
	); err != nil {
		return err
	}

	if len(r.ModuleErrors) > 0 {
		// A partial audit must be impossible to miss when reading the report.
		names := make([]string, 0, len(r.ModuleErrors))
		for name := range r.ModuleErrors {
			names = append(names, name)
		}
		sort.Strings(names)

		if _, err := fmt.Fprintf(w,
			"\n  ⚠ PARTIAL AUDIT — %d module(s) could not be inspected:\n", len(names)); err != nil {
			return err
		}
		for _, name := range names {
			if _, err := fmt.Fprintf(w, "    %-12s %s\n", name, r.ModuleErrors[name]); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
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

