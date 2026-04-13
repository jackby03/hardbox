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
package modules

import (
	"testing"
)

func TestSeverity_ScoreWeight(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		expected int
	}{
		{
			name:     "Critical severity",
			severity: SeverityCritical,
			expected: 10,
		},
		{
			name:     "High severity",
			severity: SeverityHigh,
			expected: 6,
		},
		{
			name:     "Medium severity",
			severity: SeverityMedium,
			expected: 3,
		},
		{
			name:     "Low severity",
			severity: SeverityLow,
			expected: 1,
		},
		{
			name:     "Info severity",
			severity: SeverityInfo,
			expected: 0,
		},
		{
			name:     "Unknown severity",
			severity: Severity("unknown"),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.ScoreWeight(); got != tt.expected {
				t.Errorf("Severity.ScoreWeight() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFinding_IsCompliant(t *testing.T) {
	tests := []struct {
		name     string
		status   Status
		expected bool
	}{
		{
			name:     "StatusCompliant",
			status:   StatusCompliant,
			expected: true,
		},
		{
			name:     "StatusSkipped",
			status:   StatusSkipped,
			expected: true,
		},
		{
			name:     "StatusManual",
			status:   StatusManual,
			expected: true,
		},
		{
			name:     "StatusNonCompliant",
			status:   StatusNonCompliant,
			expected: false,
		},
		{
			name:     "StatusError",
			status:   StatusError,
			expected: false,
		},
		{
			name:     "Unknown status",
			status:   Status("unknown"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := Finding{Status: tt.status}
			if got := finding.IsCompliant(); got != tt.expected {
				t.Errorf("Finding.IsCompliant() = %v, want %v", got, tt.expected)
			}
		})
	}
}

