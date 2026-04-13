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
package ntp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

const (
	defaultChronyConfPath = "/etc/chrony.conf"
	defaultTimezone       = "UTC"
)

type commandRunner func(ctx context.Context, name string, args ...string) (string, error)

type serviceState struct {
	unit      string
	installed bool
	active    bool
}

// Module implements time synchronization hardening checks.
type Module struct {
	run            commandRunner
	chronyConfPath string
}

func (m *Module) Name() string    { return "ntp" }
func (m *Module) Version() string { return "0.1.0" }

func (m *Module) runner() commandRunner {
	if m.run != nil {
		return m.run
	}
	return runCommand
}

func (m *Module) chronyPath() string {
	if m.chronyConfPath != "" {
		return m.chronyConfPath
	}
	return defaultChronyConfPath
}

// Audit checks time synchronization service state, chrony directives, and timezone.
func (m *Module) Audit(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	services := m.detectServices(ctx)
	activeCount := 0
	installedCount := 0
	chronyInstalled := false
	for _, svc := range services {
		if svc.installed {
			installedCount++
		}
		if svc.active {
			activeCount++
		}
		if svc.unit == "chronyd.service" && svc.installed {
			chronyInstalled = true
		}
	}

	findings := make([]modules.Finding, 0, 5)
	findings = append(findings, modules.Finding{
		Check:   checkNTP001(),
		Status:  complianceStatus(installedCount > 0),
		Current: fmt.Sprintf("%d detected", installedCount),
		Target:  "at least 1 (chronyd/systemd-timesyncd/ntpd)",
		Detail:  fmt.Sprintf("installed services: %s", installedServices(services)),
	})
	findings = append(findings, modules.Finding{
		Check:   checkNTP002(),
		Status:  complianceStatus(activeCount == 1),
		Current: fmt.Sprintf("%d active", activeCount),
		Target:  "exactly 1 active service",
		Detail:  fmt.Sprintf("active services: %s", activeServices(services)),
	})

	makestepTarget := cfgString(cfg, "chrony_makestep", "1.0 3")
	maxdistanceTarget := cfgString(cfg, "chrony_maxdistance", "16.0")

	chronyFindings, err := m.auditChronyConfig(chronyInstalled, makestepTarget, maxdistanceTarget)
	if err != nil {
		return nil, err
	}
	findings = append(findings, chronyFindings...)

	tzTarget := cfgString(cfg, "timezone", defaultTimezone)
	tzCurrent, tzErr := m.runner()(ctx, "timedatectl", "show", "--property=Timezone", "--value")
	tzCurrent = strings.TrimSpace(tzCurrent)
	tzStatus := modules.StatusError
	tzDetail := "failed to read timezone"
	if tzErr == nil {
		tzStatus = complianceStatus(timezoneMatches(tzCurrent, tzTarget))
		tzDetail = fmt.Sprintf("current timezone: %q", tzCurrent)
	}
	findings = append(findings, modules.Finding{
		Check:   checkNTP005(),
		Status:  tzStatus,
		Current: tzCurrent,
		Target:  tzTarget,
		Detail:  tzDetail,
	})

	return findings, nil
}

// Plan returns a reversible change that corrects chrony directives when needed.
func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, cfg)
	if err != nil {
		return nil, err
	}

	needsMakestep := false
	needsMaxdistance := false
	for _, f := range findings {
		if f.Check.ID == "ntp-003" && f.Status == modules.StatusNonCompliant {
			needsMakestep = true
		}
		if f.Check.ID == "ntp-004" && f.Status == modules.StatusNonCompliant {
			needsMaxdistance = true
		}
	}
	if !needsMakestep && !needsMaxdistance {
		return nil, nil
	}

	path := m.chronyPath()
	oldContent, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("ntp: read %s: %w", path, readErr)
	}
	fileExisted := readErr == nil

	makestepTarget := cfgString(cfg, "chrony_makestep", "1.0 3")
	maxdistanceTarget := cfgString(cfg, "chrony_maxdistance", "16.0")

	newContent := string(oldContent)
	if needsMakestep {
		newContent = setChronyDirective(newContent, "makestep", makestepTarget)
	}
	if needsMaxdistance {
		newContent = setChronyDirective(newContent, "maxdistance", maxdistanceTarget)
	}
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}

	return []modules.Change{
		{
			Description:  fmt.Sprintf("ntp: update chrony directives in %s", path),
			DryRunOutput: strings.TrimSpace(newContent),
			Apply: func() error {
				return util.AtomicWrite(path, []byte(newContent), 0o644)
			},
			Revert: func() error {
				if !fileExisted {
					return os.Remove(path)
				}
				return util.AtomicWrite(path, oldContent, 0o644)
			},
		},
	}, nil
}

func (m *Module) detectServices(ctx context.Context) []serviceState {
	units := []string{"chronyd.service", "systemd-timesyncd.service", "ntpd.service"}
	states := make([]serviceState, 0, len(units))

	for _, unit := range units {
		enabledOut, enabledErr := m.runner()(ctx, "systemctl", "is-enabled", unit)
		enabledOut = strings.TrimSpace(enabledOut)
		installed := isInstalledState(enabledOut) || (enabledErr == nil && enabledOut != "")

		activeOut, activeErr := m.runner()(ctx, "systemctl", "is-active", unit)
		activeOut = strings.TrimSpace(activeOut)
		if !installed && isInstalledState(activeOut) {
			installed = true
		}
		if looksMissingUnit(enabledOut) || looksMissingUnit(activeOut) || missingUnitError(enabledErr) || missingUnitError(activeErr) {
			installed = false
		}

		states = append(states, serviceState{
			unit:      unit,
			installed: installed,
			active:    installed && strings.EqualFold(activeOut, "active"),
		})
	}

	return states
}

func (m *Module) auditChronyConfig(installed bool, makestepTarget, maxdistanceTarget string) ([]modules.Finding, error) {
	if !installed {
		return []modules.Finding{
			{
				Check:   checkNTP003(),
				Status:  modules.StatusSkipped,
				Current: "chronyd not installed",
				Target:  makestepTarget,
				Detail:  "chrony directive check skipped",
			},
			{
				Check:   checkNTP004(),
				Status:  modules.StatusSkipped,
				Current: "chronyd not installed",
				Target:  maxdistanceTarget,
				Detail:  "chrony directive check skipped",
			},
		}, nil
	}

	content, err := os.ReadFile(m.chronyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []modules.Finding{
				{
					Check:   checkNTP003(),
					Status:  modules.StatusNonCompliant,
					Current: "missing file",
					Target:  makestepTarget,
					Detail:  fmt.Sprintf("%s does not exist", m.chronyPath()),
				},
				{
					Check:   checkNTP004(),
					Status:  modules.StatusNonCompliant,
					Current: "missing file",
					Target:  maxdistanceTarget,
					Detail:  fmt.Sprintf("%s does not exist", m.chronyPath()),
				},
			}, nil
		}
		return nil, fmt.Errorf("ntp: read %s: %w", m.chronyPath(), err)
	}

	makestepCurrent, hasMakestep := readChronyDirective(string(content), "makestep")
	maxdistanceCurrent, hasMaxdistance := readChronyDirective(string(content), "maxdistance")

	makestepStatus := modules.StatusNonCompliant
	if hasMakestep && strings.TrimSpace(makestepCurrent) == makestepTarget {
		makestepStatus = modules.StatusCompliant
	}
	maxdistanceStatus := modules.StatusNonCompliant
	if hasMaxdistance && strings.TrimSpace(maxdistanceCurrent) == maxdistanceTarget {
		maxdistanceStatus = modules.StatusCompliant
	}

	return []modules.Finding{
		{
			Check:   checkNTP003(),
			Status:  makestepStatus,
			Current: valueOrMissing(makestepCurrent, hasMakestep),
			Target:  makestepTarget,
			Detail:  fmt.Sprintf("makestep configured: %t", hasMakestep),
		},
		{
			Check:   checkNTP004(),
			Status:  maxdistanceStatus,
			Current: valueOrMissing(maxdistanceCurrent, hasMaxdistance),
			Target:  maxdistanceTarget,
			Detail:  fmt.Sprintf("maxdistance configured: %t", hasMaxdistance),
		},
	}, nil
}

func checkNTP001() modules.Check {
	return modules.Check{
		ID:       "ntp-001",
		Title:    "Time synchronization service installed",
		Severity: modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "2.2.1"},
			{Framework: "NIST", Control: "AU-8"},
		},
	}
}

func checkNTP002() modules.Check {
	return modules.Check{
		ID:       "ntp-002",
		Title:    "Only one time synchronization service active",
		Severity: modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "2.2.2"},
			{Framework: "NIST", Control: "CM-7"},
		},
	}
}

func checkNTP003() modules.Check {
	return modules.Check{
		ID:       "ntp-003",
		Title:    "chrony makestep configured",
		Severity: modules.SeverityLow,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "2.3.1"},
			{Framework: "NIST", Control: "AU-8"},
		},
	}
}

func checkNTP004() modules.Check {
	return modules.Check{
		ID:       "ntp-004",
		Title:    "chrony maxdistance configured",
		Severity: modules.SeverityLow,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "2.3.2"},
			{Framework: "NIST", Control: "AU-8"},
		},
	}
}

func checkNTP005() modules.Check {
	return modules.Check{
		ID:       "ntp-005",
		Title:    "Timezone set to UTC",
		Severity: modules.SeverityInfo,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "2.2.3"},
			{Framework: "NIST", Control: "AU-8"},
		},
	}
}

func complianceStatus(ok bool) modules.Status {
	if ok {
		return modules.StatusCompliant
	}
	return modules.StatusNonCompliant
}

func installedServices(states []serviceState) string {
	var out []string
	for _, s := range states {
		if s.installed {
			out = append(out, s.unit)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}

func activeServices(states []serviceState) string {
	var out []string
	for _, s := range states {
		if s.active {
			out = append(out, s.unit)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}

func isInstalledState(out string) bool {
	switch strings.TrimSpace(out) {
	case "enabled", "disabled", "static", "indirect", "generated", "masked":
		return true
	default:
		return false
	}
}

func looksMissingUnit(out string) bool {
	out = strings.ToLower(strings.TrimSpace(out))
	return strings.Contains(out, "not-found") || strings.Contains(out, "not found") || strings.Contains(out, "no such file")
}

func missingUnitError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not-found") || strings.Contains(msg, "not found") || strings.Contains(msg, "no such file")
}

func cfgString(cfg modules.ModuleConfig, key, fallback string) string {
	if cfg == nil {
		return fallback
	}
	v, ok := cfg[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok {
		return fallback
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	return s
}

func timezoneMatches(current, target string) bool {
	current = strings.TrimSpace(current)
	target = strings.TrimSpace(target)
	if strings.EqualFold(current, target) {
		return true
	}
	return strings.EqualFold(current, "Etc/UTC") && strings.EqualFold(target, "UTC")
}

func readChronyDirective(content, directive string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		if strings.EqualFold(fields[0], directive) {
			return strings.Join(fields[1:], " "), true
		}
	}
	return "", false
}

func setChronyDirective(content, directive, value string) string {
	// Trim trailing newlines before splitting so that a file ending with a
	// newline (common for config files) does not produce a spurious empty
	// element that would introduce a blank line when appending a new directive.
	trimmed := strings.TrimRight(content, "\n")
	lines := strings.Split(trimmed, "\n")
	updated := false
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		fields := strings.Fields(trimmedLine)
		if len(fields) == 0 {
			continue
		}
		if strings.EqualFold(fields[0], directive) {
			lines[i] = fmt.Sprintf("%s %s", directive, value)
			updated = true
		}
	}
	if !updated {
		lines = append(lines, fmt.Sprintf("%s %s", directive, value))
	}
	return strings.Join(lines, "\n")
}

func valueOrMissing(v string, exists bool) string {
	if !exists {
		return "missing"
	}
	return v
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil {
		if result == "" {
			return "", fmt.Errorf("run %s %s: %w", name, strings.Join(args, " "), err)
		}
		return result, fmt.Errorf("run %s %s: %w", name, strings.Join(args, " "), errors.New(result))
	}
	return result, nil
}

