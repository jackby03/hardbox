package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStatusSymbol(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"compliant", "✓"},
		{"non-compliant", "✗"},
		{"manual", "?"},
		{"skipped", "-"},
		{"unknown", "!"},
		{"", "!"},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			if got := statusSymbol(tt.status); got != tt.want {
				t.Errorf("statusSymbol(%q) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

func TestRenderText_Success(t *testing.T) {
	report := &Report{
		SessionID:    "sess-001",
		Timestamp:    time.Date(2023, 10, 26, 15, 30, 0, 0, time.UTC),
		Profile:      "default",
		OverallScore: 85,
		Modules: []ModuleReport{
			{
				Name:  "test-module",
				Score: 85,
				Findings: []FindingRecord{
					{
						CheckID:  "test-001",
						Status:   "compliant",
						Severity: "high",
						Title:    "Test Check 1",
					},
					{
						CheckID:  "test-002",
						Status:   "non-compliant",
						Severity: "critical",
						Title:    "Test Check 2",
						Detail:   "Detailed reason for failure",
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := renderText(report, &buf)
	if err != nil {
		t.Fatalf("renderText failed: %v", err)
	}

	output := buf.String()

	// Check header
	if !strings.Contains(output, "Session : sess-001") {
		t.Errorf("expected SessionID in output, got:\n%s", output)
	}
	if !strings.Contains(output, "Profile : default") {
		t.Errorf("expected Profile in output, got:\n%s", output)
	}
	if !strings.Contains(output, "Time    : 2023-10-26 15:30:00 UTC") {
		t.Errorf("expected formatted Timestamp in output, got:\n%s", output)
	}

	// Check module
	if !strings.Contains(output, "Module: test-module           Score:  85%") {
		t.Errorf("expected module info in output, got:\n%s", output)
	}

	// Check findings
	if !strings.Contains(output, "test-001     ✓ compliant non-compliant Test Check 1") &&
		!strings.Contains(output, "test-001     ✓ compliant high     Test Check 1") {
		t.Errorf("expected finding 1 in output, got:\n%s", output)
	}
	if !strings.Contains(output, "test-002     ✗ non-compliant critical Test Check 2") {
		t.Errorf("expected finding 2 in output, got:\n%s", output)
	}
	if !strings.Contains(output, "↳ Detailed reason for failure") {
		t.Errorf("expected detail for finding 2 in output, got:\n%s", output)
	}

	// Check footer
	if !strings.Contains(output, "Overall score: 85%   Findings: 1 compliant / 2 total") {
		t.Errorf("expected overall score in output, got:\n%s", output)
	}
}

type failWriter struct {
	failAfter int
	calls     int
}

func (w *failWriter) Write(p []byte) (n int, err error) {
	w.calls++
	if w.calls > w.failAfter {
		return 0, errors.New("simulated write error")
	}
	return len(p), nil
}

func TestRenderText_WriteErrors(t *testing.T) {
	report := &Report{
		SessionID:    "sess-001",
		Timestamp:    time.Now(),
		Profile:      "default",
		OverallScore: 50,
		Modules: []ModuleReport{
			{
				Name:  "test-module",
				Score: 50,
				Findings: []FindingRecord{
					{
						CheckID:  "test-001",
						Status:   "compliant",
						Severity: "high",
						Title:    "Test Check 1",
						Detail:   "Detailed reason",
					},
				},
			},
		},
	}

	// Test failing at different write calls
	for i := 0; i < 7; i++ {
		t.Run(string(rune('0'+i)), func(t *testing.T) {
			fw := &failWriter{failAfter: i}
			err := renderText(report, fw)
			if err == nil {
				t.Fatalf("expected error when failing after %d calls, got nil", i)
			}
			if err.Error() != "simulated write error" {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
