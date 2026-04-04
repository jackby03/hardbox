package notify_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hardbox-io/hardbox/internal/notify"
)

func TestFormatSlackMessage_Regression(t *testing.T) {
	p := notify.AlertPayload{
		Event:      notify.EventRegression,
		Timestamp:  time.Now().UTC(),
		Profile:    "production",
		SessionID:  "2026-04-04T120000Z",
		ScoreDelta: -8,
		Findings: []notify.AlertFinding{
			{CheckID: "ssh-001", Severity: "critical", Title: "Root login disabled",
				Module: "ssh", StatusBefore: "compliant", StatusAfter: "non-compliant"},
		},
	}

	msg := notify.FormatSlackMessage(p)

	if !strings.Contains(msg, "REGRESSION") {
		t.Error("regression message should mention REGRESSION")
	}
	if !strings.Contains(msg, "production") {
		t.Error("message should include profile name")
	}
	if !strings.Contains(msg, "2026-04-04T120000Z") {
		t.Error("message should include session ID")
	}
	if !strings.Contains(msg, "-8") {
		t.Error("message should include score delta")
	}
	if !strings.Contains(msg, "Root login disabled") {
		t.Error("message should include finding title")
	}
	if !strings.Contains(msg, "compliant") {
		t.Error("regression message should show before status")
	}
}

func TestFormatSlackMessage_CriticalFinding(t *testing.T) {
	p := notify.AlertPayload{
		Event:     notify.EventCriticalFinding,
		Timestamp: time.Now().UTC(),
		Profile:   "cis-level2",
		SessionID: "2026-04-04T130000Z",
		Findings: []notify.AlertFinding{
			{CheckID: "km-001", Severity: "critical", Title: "ASLR not enabled",
				Module: "kernel", StatusAfter: "non-compliant"},
		},
	}

	msg := notify.FormatSlackMessage(p)

	if !strings.Contains(msg, "CRITICAL") {
		t.Error("critical finding message should mention CRITICAL")
	}
	if !strings.Contains(msg, "ASLR not enabled") {
		t.Error("message should include finding title")
	}
}

func TestFormatSlackMessage_HighFinding(t *testing.T) {
	p := notify.AlertPayload{
		Event:     notify.EventHighFinding,
		Timestamp: time.Now().UTC(),
		Profile:   "production",
		SessionID: "s1",
		Findings: []notify.AlertFinding{
			{CheckID: "ssh-003", Severity: "high", Title: "MaxAuthTries",
				Module: "ssh", StatusAfter: "non-compliant"},
		},
	}

	msg := notify.FormatSlackMessage(p)
	if !strings.Contains(msg, "HIGH") {
		t.Error("high finding message should mention HIGH")
	}
}

func TestFormatSlackMessage_NoScoreDeltaWhenZero(t *testing.T) {
	p := notify.AlertPayload{
		Event:      notify.EventCriticalFinding,
		Profile:    "p",
		SessionID:  "s",
		ScoreDelta: 0,
		Findings:   []notify.AlertFinding{{CheckID: "x-001", Severity: "critical", Title: "T"}},
	}
	msg := notify.FormatSlackMessage(p)
	if strings.Contains(msg, "Score delta") {
		t.Error("score delta should not appear when it is 0")
	}
}
