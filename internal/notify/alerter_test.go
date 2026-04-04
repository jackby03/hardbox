package notify_test

import (
	"context"
	"testing"
	"time"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/notify"
	"github.com/hardbox-io/hardbox/internal/report"
)

// ── matchesFilter ──────────────────────────────────��──────────────────────

func TestMatchesFilter_EmptyAllowed(t *testing.T) {
	if !notify.MatchesFilter(nil, "anything") {
		t.Error("nil allowed list should match any value")
	}
	if !notify.MatchesFilter([]string{}, "anything") {
		t.Error("empty allowed list should match any value")
	}
}

func TestMatchesFilter_Match(t *testing.T) {
	if !notify.MatchesFilter([]string{"ssh", "firewall"}, "ssh") {
		t.Error("expected match for 'ssh'")
	}
}

func TestMatchesFilter_NoMatch(t *testing.T) {
	if notify.MatchesFilter([]string{"ssh", "firewall"}, "kernel") {
		t.Error("expected no match for 'kernel'")
	}
}

func TestMatchesFilter_CaseInsensitive(t *testing.T) {
	if !notify.MatchesFilter([]string{"SSH"}, "ssh") {
		t.Error("matchesFilter should be case-insensitive")
	}
}

// ── NoopAlerter ───────────────────────────────────────────────────────────

func TestNoopAlerter_DoesNotPanic(t *testing.T) {
	a := notify.NoopAlerter{}
	a.NotifyRegression(context.Background(), &report.DiffReport{})
	a.NotifyNewFindings(context.Background(), &report.Report{})
}

// ── notify.New ────────────────────────────────────────────────────────────

func TestNew_EmptyConfig_ReturnsNoop(t *testing.T) {
	a := notify.New(config.NotificationsConfig{})
	if _, ok := a.(notify.NoopAlerter); !ok {
		t.Error("expected NoopAlerter when no destinations configured")
	}
}

func TestNew_WebhookMissingURL_ReturnsNoop(t *testing.T) {
	cfg := config.NotificationsConfig{
		Webhooks: []config.WebhookConfig{{URL: ""}},
	}
	a := notify.New(cfg)
	if _, ok := a.(notify.NoopAlerter); !ok {
		t.Error("expected NoopAlerter when webhook URL is empty")
	}
}

func TestNew_SlackMissingURL_ReturnsNoop(t *testing.T) {
	cfg := config.NotificationsConfig{
		Slack: []config.SlackConfig{{URL: ""}},
	}
	a := notify.New(cfg)
	if _, ok := a.(notify.NoopAlerter); !ok {
		t.Error("expected NoopAlerter when Slack URL is empty")
	}
}

// ── NotifyNewFindings ─────────────────────────────────────────────────────

func TestNotifyNewFindings_OnlyNonCompliantCriticalHigh(t *testing.T) {
	r := &report.Report{
		Profile:   "production",
		SessionID: "2026-04-04T120000Z",
		Modules: []report.ModuleReport{
			{
				Name: "ssh",
				Findings: []report.FindingRecord{
					// Should fire: critical + non-compliant
					{CheckID: "ssh-001", Severity: "critical", Status: "non-compliant", Title: "Root login"},
					// Should NOT fire: critical but compliant
					{CheckID: "ssh-002", Severity: "critical", Status: "compliant", Title: "Password auth"},
					// Should fire: high + non-compliant
					{CheckID: "ssh-003", Severity: "high", Status: "non-compliant", Title: "MaxAuthTries"},
					// Should NOT fire: medium
					{CheckID: "ssh-004", Severity: "medium", Status: "non-compliant", Title: "LogLevel"},
				},
			},
		},
	}

	fired := make(chan notify.AlertPayload, 10)
	a := notify.NewMultiAlerterForTest(func(p notify.AlertPayload) error {
		fired <- p
		return nil
	})

	a.NotifyNewFindings(context.Background(), r)
	time.Sleep(50 * time.Millisecond)
	close(fired)

	var payloads []notify.AlertPayload
	for p := range fired {
		payloads = append(payloads, p)
	}

	if len(payloads) != 2 {
		t.Errorf("expected 2 payloads, got %d", len(payloads))
	}
	for _, p := range payloads {
		if p.Event != notify.EventCriticalFinding && p.Event != notify.EventHighFinding {
			t.Errorf("unexpected event: %s", p.Event)
		}
		if len(p.Findings) != 1 {
			t.Errorf("expected 1 finding per payload, got %d", len(p.Findings))
		}
	}
}

func TestNotifyNewFindings_SkippedManualIgnored(t *testing.T) {
	r := &report.Report{
		Profile:   "production",
		SessionID: "s1",
		Modules: []report.ModuleReport{
			{
				Name: "kernel",
				Findings: []report.FindingRecord{
					{CheckID: "km-001", Severity: "critical", Status: "skipped", Title: "ASLR"},
					{CheckID: "km-002", Severity: "critical", Status: "manual", Title: "Ptrace"},
				},
			},
		},
	}

	fired := make(chan notify.AlertPayload, 10)
	a := notify.NewMultiAlerterForTest(func(p notify.AlertPayload) error {
		fired <- p
		return nil
	})
	a.NotifyNewFindings(context.Background(), r)
	time.Sleep(50 * time.Millisecond)
	close(fired)

	if count := len(fired); count != 0 {
		t.Errorf("expected 0 payloads for skipped/manual, got %d", count)
	}
}

// ── NotifyRegression ──────────────────────────────────────────────────────

func TestNotifyRegression_OncePerRegression(t *testing.T) {
	d := &report.DiffReport{
		Before:     report.DiffMeta{SessionID: "before", Profile: "production", Score: 80},
		After:      report.DiffMeta{SessionID: "after", Profile: "production", Score: 70},
		ScoreDelta: -10,
		Regressions: []report.DiffFinding{
			{CheckID: "ssh-001", Severity: "critical", Title: "Root login",
				StatusBefore: "compliant", StatusAfter: "non-compliant"},
			{CheckID: "fw-001", Severity: "high", Title: "Firewall enabled",
				StatusBefore: "compliant", StatusAfter: "non-compliant"},
		},
	}

	fired := make(chan notify.AlertPayload, 10)
	a := notify.NewMultiAlerterForTest(func(p notify.AlertPayload) error {
		fired <- p
		return nil
	})

	a.NotifyRegression(context.Background(), d)
	time.Sleep(50 * time.Millisecond)
	close(fired)

	var payloads []notify.AlertPayload
	for p := range fired {
		payloads = append(payloads, p)
	}

	if len(payloads) != 2 {
		t.Errorf("expected 2 payloads (one per regression), got %d", len(payloads))
	}
	for _, p := range payloads {
		if p.Event != notify.EventRegression {
			t.Errorf("expected EventRegression, got %s", p.Event)
		}
		if p.ScoreDelta != -10 {
			t.Errorf("expected ScoreDelta -10, got %d", p.ScoreDelta)
		}
		if len(p.Findings) != 1 {
			t.Errorf("expected 1 finding per payload, got %d", len(p.Findings))
		}
		if p.Findings[0].StatusBefore == "" {
			t.Error("StatusBefore should be set for regression findings")
		}
	}
}

func TestNotifyRegression_NoRegressions_NoFire(t *testing.T) {
	d := &report.DiffReport{
		Before: report.DiffMeta{SessionID: "a", Profile: "p", Score: 80},
		After:  report.DiffMeta{SessionID: "b", Profile: "p", Score: 85},
	}

	fired := make(chan notify.AlertPayload, 10)
	a := notify.NewMultiAlerterForTest(func(p notify.AlertPayload) error {
		fired <- p
		return nil
	})
	a.NotifyRegression(context.Background(), d)
	time.Sleep(50 * time.Millisecond)
	close(fired)

	if count := len(fired); count != 0 {
		t.Errorf("expected 0 payloads when no regressions, got %d", count)
	}
}
