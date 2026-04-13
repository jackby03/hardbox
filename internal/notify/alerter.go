// Package notify dispatches webhook alerts from the hardbox watch daemon.
package notify

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/report"
)

// EventType distinguishes the three alert categories.
type EventType string

const (
	EventRegression      EventType = "regression"
	EventCriticalFinding EventType = "critical_finding"
	EventHighFinding     EventType = "high_finding"
)

// AlertPayload is the JSON body sent by the generic HTTP adapter.
// The Slack adapter receives the same struct and reformats it as text.
type AlertPayload struct {
	Event      EventType      `json:"event"`
	Timestamp  time.Time      `json:"timestamp"`
	Profile    string         `json:"profile"`
	SessionID  string         `json:"session_id"`
	ScoreDelta int            `json:"score_delta,omitempty"`
	Findings   []AlertFinding `json:"findings"`
}

// AlertFinding is a trimmed representation of one triggering check.
type AlertFinding struct {
	CheckID      string `json:"check_id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Module       string `json:"module"`
	StatusBefore string `json:"status_before,omitempty"`
	StatusAfter  string `json:"status_after,omitempty"`
}

// Alerter dispatches alerts to all configured destinations.
type Alerter interface {
	// NotifyRegression fires "regression" events for all regressions in the diff.
	NotifyRegression(ctx context.Context, d *report.DiffReport)
	// NotifyNewFindings fires "critical_finding" or "high_finding" events for
	// non-compliant critical/high findings in the report.
	NotifyNewFindings(ctx context.Context, r *report.Report)
	// Wait blocks until all dispatched alerts have completed or the context expires.
	Wait()
}

// NoopAlerter is a zero-cost implementation used when no notifications are configured.
type NoopAlerter struct{}

func (NoopAlerter) NotifyRegression(_ context.Context, _ *report.DiffReport) {}
func (NoopAlerter) NotifyNewFindings(_ context.Context, _ *report.Report)    {}
func (NoopAlerter) Wait()                                                    {}

// adapter is the internal interface each concrete destination implements.
type adapter interface {
	send(ctx context.Context, payload AlertPayload) error
	matches(event EventType, module string) bool
}

// MultiAlerter fans out to all configured adapters.
type MultiAlerter struct {
	adapters []adapter
	wg       sync.WaitGroup
}

// New builds an Alerter from the notifications config.
// Returns NoopAlerter when no destinations are configured.
func New(cfg config.NotificationsConfig) Alerter {
	var adapters []adapter

	for _, wh := range cfg.Webhooks {
		if wh.URL == "" {
			log.Warn().Msg("notify: webhook entry missing url — skipping")
			continue
		}
		adapters = append(adapters, newHTTPAdapter(wh))
	}

	for _, sl := range cfg.Slack {
		if sl.URL == "" {
			log.Warn().Msg("notify: slack entry missing url — skipping")
			continue
		}
		adapters = append(adapters, newSlackAdapter(sl))
	}

	if len(adapters) == 0 {
		return NoopAlerter{}
	}
	return &MultiAlerter{adapters: adapters}
}

func (m *MultiAlerter) NotifyRegression(ctx context.Context, d *report.DiffReport) {
	for _, reg := range d.Regressions {
		module := report.ModulePrefix(reg.CheckID)
		payload := AlertPayload{
			Event:      EventRegression,
			Timestamp:  time.Now().UTC(),
			Profile:    d.After.Profile,
			SessionID:  d.After.SessionID,
			ScoreDelta: d.ScoreDelta,
			Findings: []AlertFinding{{
				CheckID:      reg.CheckID,
				Title:        reg.Title,
				Severity:     reg.Severity,
				Module:       module,
				StatusBefore: reg.StatusBefore,
				StatusAfter:  reg.StatusAfter,
			}},
		}
		m.dispatch(ctx, EventRegression, module, payload)
	}
}

func (m *MultiAlerter) NotifyNewFindings(ctx context.Context, r *report.Report) {
	for _, mod := range r.Modules {
		for _, f := range mod.Findings {
			if f.Status == "compliant" || f.Status == "skipped" || f.Status == "manual" {
				continue
			}
			var event EventType
			switch f.Severity {
			case "critical":
				event = EventCriticalFinding
			case "high":
				event = EventHighFinding
			default:
				continue
			}
			payload := AlertPayload{
				Event:     event,
				Timestamp: time.Now().UTC(),
				Profile:   r.Profile,
				SessionID: r.SessionID,
				Findings: []AlertFinding{{
					CheckID:     f.CheckID,
					Title:       f.Title,
					Severity:    f.Severity,
					Module:      mod.Name,
					StatusAfter: f.Status,
				}},
			}
			m.dispatch(ctx, event, mod.Name, payload)
		}
	}
}

// Wait blocks until all dispatched alerts have completed.
func (m *MultiAlerter) Wait() {
	m.wg.Wait()
}

func (m *MultiAlerter) dispatch(ctx context.Context, event EventType, module string, payload AlertPayload) {
	for _, a := range m.adapters {
		if !a.matches(event, module) {
			continue
		}
		m.wg.Add(1)
		go func(a adapter) {
			defer m.wg.Done()
			if err := a.send(ctx, payload); err != nil {
				log.Warn().
					Err(err).
					Str("event", string(event)).
					Str("module", module).
					Msg("notify: adapter failed")
			}
		}(a)
	}
}

// matchesFilter returns true when allowed is empty (match all)
// or when value is present in allowed (case-insensitive).
func matchesFilter(allowed []string, value string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if strings.EqualFold(a, value) {
			return true
		}
	}
	return false
}
