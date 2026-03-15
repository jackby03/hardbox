package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/report"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

var testFindings = []modules.Finding{
	{
		Check: modules.Check{
			ID:       "ssh-001",
			Title:    "PermitRootLogin disabled",
			Severity: modules.SeverityCritical,
		},
		Status:  modules.StatusCompliant,
		Current: "no",
		Target:  "no",
		Detail:  `current: "no", expected: "no"`,
	},
	{
		Check: modules.Check{
			ID:       "ssh-002",
			Title:    "PasswordAuthentication disabled",
			Severity: modules.SeverityHigh,
		},
		Status:  modules.StatusNonCompliant,
		Current: "yes",
		Target:  "no",
		Detail:  `current: "yes", expected: "no"`,
	},
	{
		Check: modules.Check{
			ID:       "ssh-003",
			Title:    "X11Forwarding disabled",
			Severity: modules.SeverityMedium,
		},
		Status:  modules.StatusCompliant,
		Current: "no",
		Target:  "no",
	},
}

// ── Build ─────────────────────────────────────────────────────────────────────

func TestBuild_Grouping(t *testing.T) {
	r := report.Build("sess-001", "cis-level1", testFindings)

	if len(r.Modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(r.Modules))
	}
	if r.Modules[0].Name != "ssh" {
		t.Errorf("expected module name 'ssh', got %q", r.Modules[0].Name)
	}
	if len(r.Modules[0].Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(r.Modules[0].Findings))
	}
}

func TestBuild_Metadata(t *testing.T) {
	r := report.Build("sess-XYZ", "production", testFindings)

	if r.SessionID != "sess-XYZ" {
		t.Errorf("SessionID: got %q, want 'sess-XYZ'", r.SessionID)
	}
	if r.Profile != "production" {
		t.Errorf("Profile: got %q, want 'production'", r.Profile)
	}
	if r.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestBuild_Score(t *testing.T) {
	// ssh-001 compliant critical=10, ssh-002 non-compliant high=6, ssh-003 compliant medium=3
	// compliantW=13, totalW=19 → score = (13*100)/19 = 68
	r := report.Build("s", "p", testFindings)

	wantModScore := (13 * 100) / 19
	if r.Modules[0].Score != wantModScore {
		t.Errorf("module score: got %d, want %d", r.Modules[0].Score, wantModScore)
	}
	if r.OverallScore != wantModScore {
		t.Errorf("overall score: got %d, want %d", r.OverallScore, wantModScore)
	}
}

func TestBuild_EmptyFindings(t *testing.T) {
	r := report.Build("s", "p", nil)

	if len(r.Modules) != 0 {
		t.Errorf("expected 0 modules, got %d", len(r.Modules))
	}
	if r.OverallScore != 0 {
		t.Errorf("expected score 0, got %d", r.OverallScore)
	}
}

func TestBuild_MultiModule(t *testing.T) {
	findings := append(testFindings, modules.Finding{
		Check:  modules.Check{ID: "kern-001", Title: "kernel hardening", Severity: modules.SeverityHigh},
		Status: modules.StatusCompliant,
	})
	r := report.Build("s", "p", findings)

	if len(r.Modules) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(r.Modules))
	}
	// Modules should be sorted alphabetically: kern, ssh
	if r.Modules[0].Name != "kern" {
		t.Errorf("first module: got %q, want 'kern'", r.Modules[0].Name)
	}
	if r.Modules[1].Name != "ssh" {
		t.Errorf("second module: got %q, want 'ssh'", r.Modules[1].Name)
	}
}

// ── JSON renderer ─────────────────────────────────────────────────────────────

func TestWrite_JSON_ValidStructure(t *testing.T) {
	r := report.Build("sess-001", "cis-level1", testFindings)
	var buf bytes.Buffer

	if err := report.Write(r, "json", &buf); err != nil {
		t.Fatalf("Write JSON: %v", err)
	}

	var decoded struct {
		SessionID    string `json:"session_id"`
		Profile      string `json:"profile"`
		OverallScore int    `json:"overall_score"`
		Modules      []struct {
			Name     string `json:"name"`
			Score    int    `json:"score"`
			Findings []struct {
				CheckID  string `json:"check_id"`
				Status   string `json:"status"`
				Severity string `json:"severity"`
			} `json:"findings"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON output: %v\n---\n%s", err, buf.String())
	}

	if decoded.SessionID != "sess-001" {
		t.Errorf("json session_id: got %q", decoded.SessionID)
	}
	if decoded.Profile != "cis-level1" {
		t.Errorf("json profile: got %q", decoded.Profile)
	}
	if len(decoded.Modules) != 1 {
		t.Fatalf("json modules: want 1, got %d", len(decoded.Modules))
	}
	if decoded.Modules[0].Name != "ssh" {
		t.Errorf("json module name: got %q", decoded.Modules[0].Name)
	}
	if len(decoded.Modules[0].Findings) != 3 {
		t.Errorf("json findings count: want 3, got %d", len(decoded.Modules[0].Findings))
	}
}

func TestWrite_JSON_Timestamp(t *testing.T) {
	r := report.Build("s", "p", testFindings)
	var buf bytes.Buffer
	_ = report.Write(r, "json", &buf)

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	ts, ok := raw["timestamp"].(string)
	if !ok || ts == "" {
		t.Errorf("timestamp field missing or empty in JSON output")
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("timestamp %q is not valid RFC3339: %v", ts, err)
	}
}

// ── Text renderer ─────────────────────────────────────────────────────────────

func TestWrite_Text_ContainsKeyFields(t *testing.T) {
	r := report.Build("sess-text", "cis-level1", testFindings)
	var buf bytes.Buffer

	if err := report.Write(r, "text", &buf); err != nil {
		t.Fatalf("Write text: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"sess-text", "cis-level1", "ssh", "ssh-001", "ssh-002", "compliant", "non-compliant"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q", want)
		}
	}
}

func TestWrite_Text_OverallScore(t *testing.T) {
	r := report.Build("s", "p", testFindings)
	var buf bytes.Buffer
	_ = report.Write(r, "text", &buf)

	if !strings.Contains(buf.String(), "Overall score") {
		t.Error("text output missing 'Overall score'")
	}
}

// ── Markdown renderer ─────────────────────────────────────────────────────────

func TestWrite_Markdown_Structure(t *testing.T) {
	r := report.Build("sess-md", "production", testFindings)
	var buf bytes.Buffer

	if err := report.Write(r, "markdown", &buf); err != nil {
		t.Fatalf("Write markdown: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"# hardbox Audit Report", "## Module", "| Check ID |", "sess-md", "production", "ssh-001"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q", want)
		}
	}
}

func TestWrite_Markdown_AliasIsAccepted(t *testing.T) {
	r := report.Build("s", "p", testFindings)
	var buf bytes.Buffer
	if err := report.Write(r, "md", &buf); err != nil {
		t.Fatalf("'md' alias should be accepted: %v", err)
	}
	if !strings.Contains(buf.String(), "# hardbox Audit Report") {
		t.Error("'md' alias did not produce markdown output")
	}
}

// ── Unknown format ────────────────────────────────────────────────────────────

func TestWrite_UnknownFormat_FallsBackToText(t *testing.T) {
	r := report.Build("s", "p", testFindings)
	var buf bytes.Buffer
	// Should not error, and should produce text-like output
	if err := report.Write(r, "xmlreport", &buf); err != nil {
		t.Fatalf("unknown format should not return error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ssh-001") {
		t.Error("fallback text output should contain check IDs")
	}
	if !strings.Contains(out, "Warning: unknown format") {
		t.Error("fallback text output should contain warning about unknown format")
	}
}
