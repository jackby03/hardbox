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
package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardbox-io/hardbox/internal/report"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeReport(score int, findings ...report.FindingRecord) *report.Report {
	return &report.Report{
		SessionID:    "test-session",
		Timestamp:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Profile:      "cis-level1",
		OverallScore: score,
		Modules: []report.ModuleReport{
			{Name: "ssh", Score: score, Findings: findings},
		},
	}
}

func fr(id, status, severity, title string) report.FindingRecord {
	return report.FindingRecord{
		CheckID:  id,
		Title:    title,
		Status:   status,
		Severity: severity,
	}
}

// ── Diff logic ────────────────────────────────────────────────────────────────

func TestDiff_Regression(t *testing.T) {
	before := makeReport(90, fr("ssh-001", "compliant", "high", "Disable root login"))
	after := makeReport(60, fr("ssh-001", "non-compliant", "high", "Disable root login"))

	d := report.Diff(before, after)

	if len(d.Regressions) != 1 {
		t.Fatalf("expected 1 regression, got %d", len(d.Regressions))
	}
	if d.Regressions[0].CheckID != "ssh-001" {
		t.Errorf("expected ssh-001 in regressions")
	}
	if len(d.Improvements) != 0 {
		t.Errorf("expected 0 improvements, got %d", len(d.Improvements))
	}
	if d.HasRegressions() != true {
		t.Error("HasRegressions should be true")
	}
}

func TestDiff_Improvement(t *testing.T) {
	before := makeReport(60, fr("ssh-001", "non-compliant", "high", "Disable root login"))
	after := makeReport(90, fr("ssh-001", "compliant", "high", "Disable root login"))

	d := report.Diff(before, after)

	if len(d.Improvements) != 1 {
		t.Fatalf("expected 1 improvement, got %d", len(d.Improvements))
	}
	if len(d.Regressions) != 0 {
		t.Errorf("expected 0 regressions, got %d", len(d.Regressions))
	}
	if d.HasRegressions() != false {
		t.Error("HasRegressions should be false")
	}
}

func TestDiff_Unchanged(t *testing.T) {
	before := makeReport(50,
		fr("ssh-001", "non-compliant", "high", "Disable root login"),
		fr("ssh-002", "non-compliant", "medium", "Disable password auth"),
	)
	after := makeReport(50,
		fr("ssh-001", "non-compliant", "high", "Disable root login"),
		fr("ssh-002", "non-compliant", "medium", "Disable password auth"),
	)

	d := report.Diff(before, after)

	if len(d.Unchanged) != 2 {
		t.Fatalf("expected 2 unchanged, got %d", len(d.Unchanged))
	}
	if len(d.Regressions) != 0 || len(d.Improvements) != 0 {
		t.Error("expected no regressions or improvements")
	}
}

func TestDiff_NewCheck(t *testing.T) {
	before := makeReport(80, fr("ssh-001", "compliant", "high", "Disable root login"))
	after := makeReport(70,
		fr("ssh-001", "compliant", "high", "Disable root login"),
		fr("ssh-002", "non-compliant", "medium", "New check"),
	)

	d := report.Diff(before, after)

	if len(d.NewChecks) != 1 {
		t.Fatalf("expected 1 new check, got %d", len(d.NewChecks))
	}
	if d.NewChecks[0].CheckID != "ssh-002" {
		t.Errorf("expected ssh-002 in new checks")
	}
}

func TestDiff_SkippedCountsAsCompliant(t *testing.T) {
	// skipped → non-compliant should be a regression
	before := makeReport(80, fr("ssh-001", "skipped", "high", "Disable root login"))
	after := makeReport(60, fr("ssh-001", "non-compliant", "high", "Disable root login"))

	d := report.Diff(before, after)

	if len(d.Regressions) != 1 {
		t.Fatalf("skipped→non-compliant should be regression, got %d regressions", len(d.Regressions))
	}
}

func TestDiff_ScoreDelta(t *testing.T) {
	before := makeReport(70)
	after := makeReport(85)

	d := report.Diff(before, after)
	if d.ScoreDelta != 15 {
		t.Errorf("ScoreDelta: got %d, want 15", d.ScoreDelta)
	}
}

func TestDiff_NoChanges(t *testing.T) {
	before := makeReport(100, fr("ssh-001", "compliant", "high", "Disable root login"))
	after := makeReport(100, fr("ssh-001", "compliant", "high", "Disable root login"))

	d := report.Diff(before, after)

	if d.HasRegressions() {
		t.Error("should have no regressions")
	}
	if len(d.Improvements) != 0 || len(d.Unchanged) != 0 || len(d.NewChecks) != 0 {
		t.Error("all lists should be empty for identical compliant reports")
	}
}

// ── DiffFiles ──────────────────────────────────────────────────────────────────

func TestDiffFiles(t *testing.T) {
	before := makeReport(80, fr("ssh-001", "compliant", "high", "Disable root login"))
	after := makeReport(60, fr("ssh-001", "non-compliant", "high", "Disable root login"))

	dir := t.TempDir()
	writeTempReportJSON(t, dir, "before.json", before)
	writeTempReportJSON(t, dir, "after.json", after)

	d, err := report.DiffFiles(
		filepath.Join(dir, "before.json"),
		filepath.Join(dir, "after.json"),
	)
	if err != nil {
		t.Fatalf("DiffFiles error: %v", err)
	}
	if len(d.Regressions) != 1 {
		t.Errorf("expected 1 regression, got %d", len(d.Regressions))
	}
}

func TestDiffFiles_MissingFile(t *testing.T) {
	_, err := report.DiffFiles("/nonexistent/before.json", "/nonexistent/after.json")
	if err == nil {
		t.Error("expected error for missing files")
	}
}

// ── WriteDiff — text ──────────────────────────────────────────────────────────

func TestWriteDiff_Text(t *testing.T) {
	before := makeReport(70,
		fr("ssh-001", "compliant", "high", "Disable root login"),
		fr("ssh-002", "non-compliant", "medium", "Disable password auth"),
	)
	after := makeReport(85,
		fr("ssh-001", "non-compliant", "high", "Disable root login"),
		fr("ssh-002", "compliant", "medium", "Disable password auth"),
	)

	d := report.Diff(before, after)
	var buf bytes.Buffer
	if err := report.WriteDiff(d, "text", &buf); err != nil {
		t.Fatalf("WriteDiff text error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"REGRESSIONS", "IMPROVEMENTS", "ssh-001", "ssh-002"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q", want)
		}
	}
}

// ── WriteDiff — HTML ──────────────────────────────────────────────────────────

func TestWriteDiff_HTML(t *testing.T) {
	before := makeReport(70, fr("ssh-001", "compliant", "high", "Disable root login"))
	after := makeReport(50, fr("ssh-001", "non-compliant", "high", "Disable root login"))

	d := report.Diff(before, after)
	var buf bytes.Buffer
	if err := report.WriteDiff(d, "html", &buf); err != nil {
		t.Fatalf("WriteDiff html error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("HTML output missing DOCTYPE")
	}
	if !strings.Contains(out, "ssh-001") {
		t.Error("HTML output missing check ID")
	}
}

// ── WriteDiff — JSON ──────────────────────────────────────────────────────────

func TestWriteDiff_JSON(t *testing.T) {
	before := makeReport(80, fr("ssh-001", "compliant", "high", "Disable root login"))
	after := makeReport(60, fr("ssh-001", "non-compliant", "high", "Disable root login"))

	d := report.Diff(before, after)
	var buf bytes.Buffer
	if err := report.WriteDiff(d, "json", &buf); err != nil {
		t.Fatalf("WriteDiff json error: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if _, ok := result["regressions"]; !ok {
		t.Error("JSON output missing 'regressions' key")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func writeTempReportJSON(t *testing.T, dir, name string, r *report.Report) {
	t.Helper()
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatalf("write report file: %v", err)
	}
}

