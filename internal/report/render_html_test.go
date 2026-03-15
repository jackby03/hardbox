package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/report"
)

func TestWrite_HTML_IsValidDocument(t *testing.T) {
	r := report.Build("sess-html", "cis-level1", testFindings)
	var buf bytes.Buffer

	if err := report.Write(r, "html", &buf); err != nil {
		t.Fatalf("Write html: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"<!DOCTYPE html>",
		"<html",
		"</html>",
		"sess-html",
		"cis-level1",
		"ssh-001",
		"ssh-002",
		"compliant",
		"non-compliant",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML output missing %q", want)
		}
	}
}

func TestWrite_HTML_ScoresPresent(t *testing.T) {
	r := report.Build("s", "p", testFindings)
	var buf bytes.Buffer
	_ = report.Write(r, "html", &buf)

	out := buf.String()
	if !strings.Contains(out, "Overall Score") {
		t.Error("HTML output should contain 'Overall Score'")
	}
	if !strings.Contains(out, "68%") {
		t.Errorf("HTML output should contain computed score '68%%'")
	}
}

func TestWrite_HTML_SeverityClasses(t *testing.T) {
	r := report.Build("s", "p", testFindings)
	var buf bytes.Buffer
	_ = report.Write(r, "html", &buf)

	out := buf.String()
	for _, cls := range []string{"sev-critical", "sev-high", "sev-medium"} {
		if !strings.Contains(out, cls) {
			t.Errorf("HTML output missing severity CSS class %q", cls)
		}
	}
}

func TestWrite_HTML_XSSEscaping(t *testing.T) {
	findings := []modules.Finding{
		{
			Check: modules.Check{
				ID:       "xss-001",
				Title:    `<script>alert("xss")</script>`,
				Severity: modules.SeverityLow,
			},
			Status: modules.StatusCompliant,
			Detail: `<img src=x onerror="evil()">`,
		},
	}
	r := report.Build("s", "p", findings)
	var buf bytes.Buffer
	_ = report.Write(r, "html", &buf)

	out := buf.String()
	// Raw <script> tag must not appear as executable HTML.
	if strings.Contains(out, "<script>") {
		t.Error("HTML output must escape <script> tags")
	}
	// onerror="..." must not appear as a raw attribute — html.EscapeString converts
	// the double-quote to &#34; so the attribute cannot execute.
	if strings.Contains(out, `onerror="`) {
		t.Error("HTML output must not contain raw onerror attribute")
	}
	// Escaped version must be present (proves the content was not dropped).
	if !strings.Contains(out, "onerror=&#34;") {
		t.Error("HTML output should contain HTML-escaped onerror content as safe text")
	}
}
