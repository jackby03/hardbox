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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hardbox-io/hardbox/internal/config"
)

const (
	retryAttempts    = 3
	retryBaseBackoff = 500 * time.Millisecond
	retryMaxBackoff  = 8 * time.Second
)

// httpAdapter sends alerts as JSON POST requests to a generic HTTP endpoint.
type httpAdapter struct {
	cfg    config.WebhookConfig
	client *http.Client
}

func newHTTPAdapter(cfg config.WebhookConfig) *httpAdapter {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &httpAdapter{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout},
	}
}

func (a *httpAdapter) matches(event EventType, module string) bool {
	return matchesFilter(a.cfg.Events, string(event)) && matchesFilter(a.cfg.Modules, module)
}

func (a *httpAdapter) send(ctx context.Context, payload AlertPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	return retryPost(ctx, a.client, a.cfg.URL, a.cfg.Headers, body)
}

// retryPost attempts up to retryAttempts times with exponential backoff.
// Backoff sequence: 500ms → 1s → 2s (capped at retryMaxBackoff).
// Context cancellation aborts immediately.
func retryPost(ctx context.Context, client *http.Client, url string,
	headers map[string]string, body []byte) error {

	var lastErr error
	backoff := retryBaseBackoff

	for attempt := 1; attempt <= retryAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
			bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("building request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "hardbox-notify/1")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, doErr := client.Do(req)
		if doErr == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		} else {
			lastErr = doErr
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}

		if attempt < retryAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			if backoff*2 < retryMaxBackoff {
				backoff *= 2
			} else {
				backoff = retryMaxBackoff
			}
		}
	}

	return fmt.Errorf("after %d attempts: %w", retryAttempts, lastErr)
}

