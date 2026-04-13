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
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hardbox-io/hardbox/internal/config"
)

// slackAdapter sends alerts as formatted text messages via Slack Incoming Webhooks.
type slackAdapter struct {
	cfg    config.SlackConfig
	client *http.Client
}

// slackPayload is the JSON body accepted by the Slack Incoming Webhook API.
type slackPayload struct {
	Text    string `json:"text"`
	Channel string `json:"channel,omitempty"`
}

func newSlackAdapter(cfg config.SlackConfig) *slackAdapter {
	return &slackAdapter{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *slackAdapter) matches(event EventType, module string) bool {
	return matchesFilter(a.cfg.Events, string(event)) && matchesFilter(a.cfg.Modules, module)
}

func (a *slackAdapter) send(ctx context.Context, payload AlertPayload) error {
	body, err := json.Marshal(slackPayload{
		Text:    formatSlackMessage(payload),
		Channel: a.cfg.Channel,
	})
	if err != nil {
		return fmt.Errorf("marshal slack payload: %w", err)
	}
	return retryPost(ctx, a.client, a.cfg.URL, nil, body)
}

// formatSlackMessage produces a human-readable Slack message for the given payload.
func formatSlackMessage(p AlertPayload) string {
	var sb strings.Builder

	switch p.Event {
	case EventRegression:
		fmt.Fprintf(&sb, "*[hardbox] REGRESSION detected*\n")
	case EventCriticalFinding:
		fmt.Fprintf(&sb, "*[hardbox] CRITICAL finding detected*\n")
	case EventHighFinding:
		fmt.Fprintf(&sb, "*[hardbox] HIGH finding detected*\n")
	default:
		fmt.Fprintf(&sb, "*[hardbox] Alert*\n")
	}

	fmt.Fprintf(&sb, "Profile: `%s` | Session: `%s`", p.Profile, p.SessionID)

	if p.ScoreDelta != 0 {
		sign := "+"
		if p.ScoreDelta < 0 {
			sign = ""
		}
		fmt.Fprintf(&sb, " | Score delta: *%s%d*", sign, p.ScoreDelta)
	}

	if len(p.Findings) > 0 {
		sb.WriteString("\n")
		for _, f := range p.Findings {
			if f.StatusBefore != "" {
				fmt.Fprintf(&sb, "• `%s` (%s) %s — _%s_ → _%s_\n",
					f.CheckID, f.Severity, f.Title, f.StatusBefore, f.StatusAfter)
			} else {
				fmt.Fprintf(&sb, "• `%s` (%s) %s — _%s_\n",
					f.CheckID, f.Severity, f.Title, f.StatusAfter)
			}
		}
	}

	return strings.TrimRight(sb.String(), "\n")
}

