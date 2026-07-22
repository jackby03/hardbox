package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/report"
)

func makeFinding(id, title string, severity modules.Severity, status, current, target string) modules.Finding {
	return modules.Finding{
		Check: modules.Check{
			ID:       id,
			Title:    title,
			Severity: severity,
		},
		Status:  modules.Status(status),
		Current: current,
		Target:  target,
	}
}

func TestWrite_SARIF_ValidSchema(t *testing.T) {
	findings := []modules.Finding{
		makeFinding("ssh-001", "Disable root login", modules.SeverityCritical, "non-compliant", "yes", "no"),
		makeFinding("ssh-002", "Disable password auth", modules.SeverityHigh, "compliant", "no", "no"),
	}
	r := report.Build("sess-001", "cis-level1", findings)
	var buf strings.Builder
	if err := report.Write(r, "sarif", &buf); err != nil {
		t.Fatalf("Write SARIF failed: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(buf.String()), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if v, _ := doc["version"].(string); v != "2.1.0" {
		t.Errorf("version: got %v, want 2.1.0", v)
	}
	if _, ok := doc["$schema"]; !ok {
		t.Error("missing $schema")
	}
}

func TestWrite_SARIF_OnlyNonCompliant(t *testing.T) {
	findings := []modules.Finding{
		makeFinding("ssh-001", "Disable root login", modules.SeverityCritical, "non-compliant", "", "no"),
		makeFinding("ssh-002", "Disable password auth", modules.SeverityCritical, "compliant", "no", "no"),
		makeFinding("ssh-003", "Firewall enabled", modules.SeverityCritical, "skipped", "", ""),
	}
	r := report.Build("sess-001", "production", findings)
	var buf strings.Builder
	if err := report.Write(r, "sarif", &buf); err != nil {
		t.Fatalf("Write SARIF failed: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal([]byte(buf.String()), &doc)
	runs := doc["runs"].([]interface{})
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	if len(results) != 1 {
		t.Errorf("expected 1 result (only non-compliant), got %d", len(results))
	}
}

func TestWrite_SARIF_EmptyFindings(t *testing.T) {
	r := report.Build("sess-001", "production", nil)
	var buf strings.Builder
	if err := report.Write(r, "sarif", &buf); err != nil {
		t.Fatalf("Write SARIF with empty findings failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("empty report should still produce valid SARIF")
	}
}

func TestWrite_DiffSARIF_ProducesResults(t *testing.T) {
	r1 := makeReport(70,
		report.FindingRecord{CheckID: "ssh-001", Title: "Root login", Status: "non-compliant", Severity: "critical"},
		report.FindingRecord{CheckID: "ssh-002", Title: "Password auth", Status: "compliant", Severity: "high"},
	)
	r2 := makeReport(85,
		report.FindingRecord{CheckID: "ssh-001", Title: "Root login", Status: "compliant", Severity: "critical"},
		report.FindingRecord{CheckID: "ssh-002", Title: "Password auth", Status: "non-compliant", Severity: "high"},
	)

	d := report.Diff(r1, r2)
	var buf strings.Builder
	if err := report.WriteDiff(d, "sarif", &buf); err != nil {
		t.Fatalf("WriteDiff SARIF failed: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(buf.String()), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	runs := doc["runs"].([]interface{})
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	if len(results) != 2 {
		t.Errorf("expected 2 results (1 regression + 1 improvement), got %d", len(results))
	}
}

func TestWrite_SARIF_RulesPresent(t *testing.T) {
	findings := []modules.Finding{
		makeFinding("ssh-001", "Disable root login", modules.SeverityCritical, "non-compliant", "yes", "no"),
		makeFinding("ssh-001", "Dupe check", modules.SeverityCritical, "non-compliant", "", "no"),
	}
	r := report.Build("sess-001", "production", findings)
	var buf strings.Builder
	if err := report.Write(r, "sarif", &buf); err != nil {
		t.Fatalf("Write SARIF failed: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal([]byte(buf.String()), &doc)
	runs := doc["runs"].([]interface{})
	driver := runs[0].(map[string]interface{})["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})

	if len(rules) != 1 {
		t.Errorf("expected 1 rule (deduplicated), got %d", len(rules))
	}
}
