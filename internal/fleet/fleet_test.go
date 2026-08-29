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

package fleet_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/fleet"
)

func TestHasCritical(t *testing.T) {
	tests := []struct {
		name    string
		results []fleet.HostResult
		want    bool
	}{
		{
			name:    "empty results",
			results: []fleet.HostResult{},
			want:    false,
		},
		{
			name: "no critical string present",
			results: []fleet.HostResult{
				{Output: `{"status": "ok"}`},
			},
			want: false,
		},
		{
			name: "critical is zero without space",
			results: []fleet.HostResult{
				{Output: `{"critical":0}`},
			},
			want: false,
		},
		{
			name: "critical is zero with space",
			results: []fleet.HostResult{
				{Output: `{"critical": 0}`},
			},
			want: false,
		},
		{
			name: "critical is greater than zero",
			results: []fleet.HostResult{
				{Output: `{"critical": 1}`},
			},
			want: true,
		},
		{
			name: "critical is greater than zero with space",
			results: []fleet.HostResult{
				{Output: `{"critical":   5}`},
			},
			want: true,
		},
		{
			name: "result with error is skipped",
			results: []fleet.HostResult{
				{Output: `{"critical": 1}`, Err: errors.New("failed")},
			},
			want: false,
		},
		{
			name: "mixed results where one is critical",
			results: []fleet.HostResult{
				{Output: `{"critical": 0}`},
				{Output: `{"critical": 1}`, Err: errors.New("failed")},
				{Output: `{"critical": 2}`},
			},
			want: true,
		},
		{
			name: "only non-critical findings in multiple results",
			results: []fleet.HostResult{
				{Output: `{"critical": 0}`},
				{Output: `{"critical": 0}`},
				{Output: `{"status": "ok"}`},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fleet.HasCritical(tc.results)
			if got != tc.want {
				t.Errorf("HasCritical() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAuditTempFileCreation(t *testing.T) {
	ctx := t.Context()

	runner := fleet.New(fleet.Config{
		Concurrency: 1,
		Profile:     "cis-level1",
	})

	host := fleet.Host{
		User: "testuser",
		Addr: "127.0.0.1",
		Port: 1, // Closed port to force fast connection error
	}

	results := runner.Audit(ctx, []fleet.Host{host})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Err == nil {
		t.Fatal("expected error for unreachable host, got nil")
	}

	if !strings.Contains(results[0].Err.Error(), "create remote temp report file") {
		t.Errorf("expected error to contain 'create remote temp report file', got %v", results[0].Err)
	}
}
