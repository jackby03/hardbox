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
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// DiffReport is the result of comparing two audit Report files.
type DiffReport struct {
	Before       DiffMeta      `json:"before"`
	After        DiffMeta      `json:"after"`
	ScoreDelta   int           `json:"score_delta"`
	Regressions  []DiffFinding `json:"regressions"`  // compliant → non-compliant
	Improvements []DiffFinding `json:"improvements"` // non-compliant → compliant
	Unchanged    []DiffFinding `json:"unchanged"`    // still non-compliant
	NewChecks    []DiffFinding `json:"new_checks"`   // only in after report
}

// DiffMeta summarises the metadata of one side of the diff.
type DiffMeta struct {
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`
	Profile   string    `json:"profile"`
	Score     int       `json:"score"`
}

// DiffFinding represents a single check that changed (or stayed the same).
type DiffFinding struct {
	CheckID      string `json:"check_id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	StatusBefore string `json:"status_before"`
	StatusAfter  string `json:"status_after"`
	Detail       string `json:"detail,omitempty"`
}

// compliantStatuses are the statuses that count as "passing" for diff purposes.
var compliantStatuses = map[string]bool{
	"compliant": true,
	"manual":    true,
	"skipped":   true,
}

func isCompliantStatus(s string) bool { return compliantStatuses[s] }

// Diff compares before and after reports and returns a DiffReport.
func Diff(before, after *Report) *DiffReport {
	// Flatten all findings from each report into a map keyed by check ID.
	beforeMap := flattenFindings(before)
	afterMap := flattenFindings(after)

	dr := &DiffReport{
		Before: DiffMeta{
			SessionID: before.SessionID,
			Timestamp: before.Timestamp,
			Profile:   before.Profile,
			Score:     before.OverallScore,
		},
		After: DiffMeta{
			SessionID: after.SessionID,
			Timestamp: after.Timestamp,
			Profile:   after.Profile,
			Score:     after.OverallScore,
		},
		ScoreDelta: after.OverallScore - before.OverallScore,
	}

	// Walk all checks present in after report.
	for id, af := range afterMap {
		bf, existedBefore := beforeMap[id]

		df := DiffFinding{
			CheckID:     af.CheckID,
			Title:       af.Title,
			Severity:    af.Severity,
			StatusAfter: af.Status,
			Detail:      af.Detail,
		}

		if !existedBefore {
			df.StatusBefore = "—"
			if !isCompliantStatus(af.Status) {
				dr.NewChecks = append(dr.NewChecks, df)
			}
			continue
		}

		df.StatusBefore = bf.Status
		wasCompliant := isCompliantStatus(bf.Status)
		isCompliant := isCompliantStatus(af.Status)

		switch {
		case wasCompliant && !isCompliant:
			dr.Regressions = append(dr.Regressions, df)
		case !wasCompliant && isCompliant:
			dr.Improvements = append(dr.Improvements, df)
		case !wasCompliant && !isCompliant:
			dr.Unchanged = append(dr.Unchanged, df)
		}
	}

	sortDiffFindings(dr.Regressions)
	sortDiffFindings(dr.Improvements)
	sortDiffFindings(dr.Unchanged)
	sortDiffFindings(dr.NewChecks)

	return dr
}

// DiffFiles reads two JSON report files and returns a DiffReport.
func DiffFiles(beforePath, afterPath string) (*DiffReport, error) {
	before, err := readReportFile(beforePath)
	if err != nil {
		return nil, fmt.Errorf("reading before report %q: %w", beforePath, err)
	}
	after, err := readReportFile(afterPath)
	if err != nil {
		return nil, fmt.Errorf("reading after report %q: %w", afterPath, err)
	}
	return Diff(before, after), nil
}

// HasRegressions returns true when the diff contains any regressions.
// Used to set a non-zero exit code in CI.
func (d *DiffReport) HasRegressions() bool { return len(d.Regressions) > 0 }

// readReportFile deserialises a JSON audit report from disk.
func readReportFile(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	return &r, nil
}

// flattenFindings returns all FindingRecords from a report keyed by CheckID.
// If a check appears in multiple modules (shouldn't happen), the last one wins.
func flattenFindings(r *Report) map[string]FindingRecord {
	m := make(map[string]FindingRecord)
	for _, mod := range r.Modules {
		for _, f := range mod.Findings {
			m[f.CheckID] = f
		}
	}
	return m
}

// sortDiffFindings sorts by severity (critical first) then check ID.
func sortDiffFindings(findings []DiffFinding) {
	severityOrder := map[string]int{
		"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
	}
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0; j-- {
			a, b := findings[j-1], findings[j]
			aOrd := severityOrder[a.Severity]
			bOrd := severityOrder[b.Severity]
			if aOrd > bOrd || (aOrd == bOrd && a.CheckID > b.CheckID) {
				findings[j-1], findings[j] = findings[j], findings[j-1]
			}
		}
	}
}

