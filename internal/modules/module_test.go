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
