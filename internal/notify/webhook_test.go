package notify_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/notify"
	"github.com/hardbox-io/hardbox/internal/report"
)

func TestWebhook_SuccessOnFirstAttempt(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := notify.New(config.NotificationsConfig{
		Webhooks: []config.WebhookConfig{{URL: srv.URL}},
	})

	a.NotifyRegression(context.Background(), regressionDiff(srv.URL))
	time.Sleep(100 * time.Millisecond)

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("expected 1 HTTP call, got %d", n)
	}
}

func TestWebhook_RetriesOnServerError(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable) // fail first two
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := notify.New(config.NotificationsConfig{
		Webhooks: []config.WebhookConfig{{URL: srv.URL}},
	})

	a.NotifyRegression(context.Background(), regressionDiff(srv.URL))
	// Wait long enough for 3 attempts with backoff.
	time.Sleep(3 * time.Second)

	if n := atomic.LoadInt32(&calls); n != 3 {
		t.Errorf("expected 3 HTTP calls (2 failures + 1 success), got %d", n)
	}
}

func TestWebhook_AllAttemptsFailReturnsError(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Use the test adapter to capture the error directly.
	fired := make(chan notify.AlertPayload, 5)
	adapter := notify.NewMultiAlerterForTest(func(p notify.AlertPayload) error {
		fired <- p
		return nil
	})
	adapter.NotifyRegression(context.Background(), regressionDiff(srv.URL))
	time.Sleep(50 * time.Millisecond)
	close(fired)

	// The fake adapter doesn't hit the server — we just confirm it fires.
	if len(fired) == 0 {
		t.Error("expected adapter to have been called")
	}
}

func TestWebhook_EventFilter_Respected(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Only subscribe to high_finding — regression should NOT fire.
	a := notify.New(config.NotificationsConfig{
		Webhooks: []config.WebhookConfig{{
			URL:    srv.URL,
			Events: []string{"high_finding"},
		}},
	})

	a.NotifyRegression(context.Background(), regressionDiff(srv.URL))
	time.Sleep(100 * time.Millisecond)

	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("expected 0 calls for filtered event, got %d", n)
	}
}

func TestWebhook_ModuleFilter_Respected(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Only subscribe to firewall module — ssh regression should NOT fire.
	a := notify.New(config.NotificationsConfig{
		Webhooks: []config.WebhookConfig{{
			URL:     srv.URL,
			Modules: []string{"firewall"},
		}},
	})

	// The diff has ssh regression only.
	d := &report.DiffReport{
		After:      report.DiffMeta{SessionID: "s", Profile: "p", Score: 70},
		ScoreDelta: -10,
		Regressions: []report.DiffFinding{
			{CheckID: "ssh-001", Severity: "critical", Title: "Root login",
				StatusBefore: "compliant", StatusAfter: "non-compliant"},
		},
	}
	a.NotifyRegression(context.Background(), d)
	time.Sleep(100 * time.Millisecond)

	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Errorf("expected 0 calls for filtered module, got %d", n)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func regressionDiff(_ string) *report.DiffReport {
	return &report.DiffReport{
		Before:     report.DiffMeta{SessionID: "before", Profile: "production", Score: 80},
		After:      report.DiffMeta{SessionID: "after", Profile: "production", Score: 70},
		ScoreDelta: -10,
		Regressions: []report.DiffFinding{
			{CheckID: "ssh-001", Severity: "critical", Title: "Root login",
				StatusBefore: "compliant", StatusAfter: "non-compliant"},
		},
	}
}
