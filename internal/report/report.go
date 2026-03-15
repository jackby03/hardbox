// Package report builds and renders hardbox audit reports in multiple formats.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/hardbox-io/hardbox/internal/modules"
)

// Report is the top-level audit report structure.
type Report struct {
	SessionID    string         `json:"session_id"`
	Timestamp    time.Time      `json:"timestamp"`
	Profile      string         `json:"profile"`
	OverallScore int            `json:"overall_score"`
	Modules      []ModuleReport `json:"modules"`
}

// ModuleReport aggregates findings for a single hardening module.
type ModuleReport struct {
	Name     string          `json:"name"`
	Score    int             `json:"score"`
	Findings []FindingRecord `json:"findings"`
}

// FindingRecord is a serialisable representation of a single audit finding.
type FindingRecord struct {
	CheckID  string `json:"check_id"`
	Title    string `json:"title"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Current  string `json:"current,omitempty"`
	Target   string `json:"target,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Build constructs a Report from a list of findings.
// Findings are grouped by the module prefix in their Check ID
// (e.g. "ssh-001" → module "ssh", "kern-003" → module "kern").
func Build(sessionID, profile string, findings []modules.Finding) *Report {
	grouped := make(map[string][]modules.Finding)
	for _, f := range findings {
		mod := modulePrefix(f.Check.ID)
		grouped[mod] = append(grouped[mod], f)
	}

	// Sort module names for deterministic output.
	modNames := make([]string, 0, len(grouped))
	for name := range grouped {
		modNames = append(modNames, name)
	}
	sort.Strings(modNames)

	var modReports []ModuleReport
	overallCompliant, overallTotal := 0, 0

	for _, name := range modNames {
		mf := grouped[name]
		compliantW, totalW := 0, 0
		records := make([]FindingRecord, 0, len(mf))

		for _, f := range mf {
			w := severityWeight(f.Check.Severity)
			totalW += w
			if f.IsCompliant() {
				compliantW += w
			}
			records = append(records, FindingRecord{
				CheckID:  f.Check.ID,
				Title:    f.Check.Title,
				Status:   string(f.Status),
				Severity: string(f.Check.Severity),
				Current:  f.Current,
				Target:   f.Target,
				Detail:   f.Detail,
			})
		}

		score := 0
		if totalW > 0 {
			score = (compliantW * 100) / totalW
		}

		overallCompliant += compliantW
		overallTotal += totalW

		modReports = append(modReports, ModuleReport{
			Name:     name,
			Score:    score,
			Findings: records,
		})
	}

	overall := 0
	if overallTotal > 0 {
		overall = (overallCompliant * 100) / overallTotal
	}

	return &Report{
		SessionID:    sessionID,
		Timestamp:    time.Now().UTC(),
		Profile:      profile,
		OverallScore: overall,
		Modules:      modReports,
	}
}

// Write renders the report in the requested format to w.
// Supported formats: "json", "text" (default), "markdown" / "md", "html".
func Write(r *Report, format string, w io.Writer) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return renderJSON(r, w)
	case "markdown", "md":
		return renderMarkdown(r, w)
	case "html":
		return renderHTML(r, w)
	case "text", "":
		return renderText(r, w)
	default:
		// Unrecognised format — fall back to text so the binary stays usable.
		if _, err := fmt.Fprintf(w, "# Warning: unknown format %q — falling back to text\n\n", format); err != nil {
			return err
		}
		return renderText(r, w)
	}
}

// modulePrefix extracts the module name from a check ID.
// "ssh-001" → "ssh",  "kern-003" → "kern",  "pkg-manager-001" → "pkg-manager".
// It splits on the LAST hyphen so the three-digit suffix is always removed.
func modulePrefix(checkID string) string {
	if idx := strings.LastIndex(checkID, "-"); idx > 0 {
		return checkID[:idx]
	}
	return checkID
}

// severityWeight maps a severity to its numeric scoring weight.
// Weights follow the hardbox spec: critical=10, high=6, medium=3, low=1, info=0.
func severityWeight(s modules.Severity) int {
	switch s {
	case modules.SeverityCritical:
		return 10
	case modules.SeverityHigh:
		return 6
	case modules.SeverityMedium:
		return 3
	case modules.SeverityLow:
		return 1
	default: // info and unknown
		return 0
	}
}
