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
	"context"
)

// Severity levels for hardening findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Status represents the compliance state of a single check.
type Status string

const (
	StatusCompliant    Status = "compliant"
	StatusNonCompliant Status = "non-compliant"
	StatusManual       Status = "manual"
	StatusSkipped      Status = "skipped"
	StatusError        Status = "error"
)

// ComplianceRef maps a check to an external compliance control.
type ComplianceRef struct {
	Framework string // "CIS", "NIST", "STIG", "PCI-DSS", "HIPAA", "ISO27001"
	Control   string // e.g. "5.2.8", "AC-6", "V-238218"
}

// Check describes a single hardening requirement.
type Check struct {
	ID          string
	Title       string
	Description string
	Remediation string
	Severity    Severity
	Compliance  []ComplianceRef
}

// Finding is the result of auditing a Check against the live system.
type Finding struct {
	Check   Check
	Status  Status
	Current string // observed system value
	Target  string // desired value
	Detail  string // human-readable explanation
}

// Change is a single reversible system modification.
type Change struct {
	Description  string
	DryRunOutput string
	Apply        func() error
	Revert       func() error
}

// ModuleConfig carries per-module settings resolved from the profile + user config.
type ModuleConfig map[string]any

// Module is the interface every hardening module must implement.
type Module interface {
	// Name returns the module identifier (e.g. "ssh", "firewall").
	Name() string

	// Version returns the module's schema version.
	Version() string

	// Audit inspects the live system and returns findings. Read-only; no side effects.
	Audit(ctx context.Context, cfg ModuleConfig) ([]Finding, error)

	// Plan returns an ordered list of Changes required to achieve compliance.
	// Each Change knows how to Apply and Revert itself.
	Plan(ctx context.Context, cfg ModuleConfig) ([]Change, error)
}

// IsCompliant returns true when the finding does not require remediation.
func (f Finding) IsCompliant() bool {
	return f.Status == StatusCompliant || f.Status == StatusSkipped || f.Status == StatusManual
}

// ScoreWeight returns a numeric weight for calculating the security score.
func (s Severity) ScoreWeight() int {
	switch s {
	case SeverityCritical:
		return 10
	case SeverityHigh:
		return 6
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

