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
package mac

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hardbox-io/hardbox/internal/distro"
	"github.com/hardbox-io/hardbox/internal/modules"
)

const defaultSELinuxConfig = "/etc/selinux/config"

// backendType identifies the MAC backend on the host.
type backendType string

const (
	backendUnknown  backendType = "unknown"
	backendAppArmor backendType = "apparmor"
	backendSELinux  backendType = "selinux"
)

type commandRunner func(ctx context.Context, name string, args ...string) (string, error)

// Module implements Mandatory Access Control checks.
type Module struct {
	run commandRunner

	backendOverride string
	selinuxConfig   string
	apparmorEnabled string
}

func (m *Module) Name() string    { return "mac" }
func (m *Module) Version() string { return "0.1.0" }

func (m *Module) runner() commandRunner {
	if m.run != nil {
		return m.run
	}
	return runCommand
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec
	return strings.TrimSpace(string(out)), err
}

// Audit evaluates MAC controls for AppArmor or SELinux.
func (m *Module) Audit(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	backend := m.detectBackend(cfg)
	switch backend {
	case backendAppArmor:
		return m.auditAppArmor(ctx)
	case backendSELinux:
		return m.auditSELinux(ctx)
	default:
		return []modules.Finding{
			newSkipped(checkMAC001(), "unknown", "apparmor/selinux", "unable to detect MAC backend"),
			newSkipped(checkMAC002(), "unknown", "enabled", "unable to detect MAC backend"),
			newSkipped(checkMAC003(), "unknown", "enforcing", "unable to detect MAC backend"),
			newSkipped(checkMAC004(), "unknown", "0", "only applicable to AppArmor"),
			newSkipped(checkMAC005(), "unknown", "targeted or mls", "only applicable to SELinux"),
		}, nil
	}
}

// Plan is audit-only in v0.1.
func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	_, err := m.Audit(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (m *Module) detectBackend(cfg modules.ModuleConfig) backendType {
	override := strings.ToLower(strings.TrimSpace(cfgString(cfg, "backend", m.backendOverride)))
	switch override {
	case "apparmor":
		return backendAppArmor
	case "selinux":
		return backendSELinux
	}

	if info, err := distro.Detect(); err == nil {
		switch info.Family {
		case distro.FamilyDebian:
			return backendAppArmor
		case distro.FamilyRHEL:
			return backendSELinux
		}
	}

	if _, err := os.Stat(m.selinuxConfigPath()); err == nil {
		return backendSELinux
	}
	if _, err := os.Stat(m.apparmorEnabledPath()); err == nil {
		return backendAppArmor
	}
	return backendUnknown
}

func (m *Module) auditAppArmor(ctx context.Context) ([]modules.Finding, error) {
	out, err := m.runner()(ctx, "aa-status")
	if err != nil {
		return []modules.Finding{
			{Check: checkMAC001(), Status: modules.StatusNonCompliant, Current: "aa-status failed", Target: "installed", Detail: strings.TrimSpace(out)},
			newSkipped(checkMAC002(), "unknown", "enabled", "aa-status unavailable"),
			newSkipped(checkMAC003(), "unknown", "enforcing", "aa-status unavailable"),
			newSkipped(checkMAC004(), "unknown", "0", "aa-status unavailable"),
			newSkipped(checkMAC005(), "n/a", "targeted or mls", "SELinux-only check"),
		}, nil
	}

	enabledRaw, enabledErr := os.ReadFile(m.apparmorEnabledPath())
	enabled := enabledErr == nil && strings.EqualFold(strings.TrimSpace(string(enabledRaw)), "Y")
	enforcing := parseAANumber(out, "profiles are in enforce mode") > 0
	unconfined := parseAANumber(out, "processes are unconfined")
	if unconfined < 0 {
		unconfined = parseAANumber(out, "processes are unconfined but have a profile defined")
	}
	if unconfined < 0 {
		unconfined = 0
	}

	return []modules.Finding{
		{Check: checkMAC001(), Status: modules.StatusCompliant, Current: "aa-status available", Target: "installed", Detail: "AppArmor userspace tooling detected"},
		{Check: checkMAC002(), Status: modules.ComplianceStatus(enabled), Current: boolLabel(enabled), Target: "enabled", Detail: "read /sys/module/apparmor/parameters/enabled"},
		{Check: checkMAC003(), Status: modules.ComplianceStatus(enforcing), Current: fmt.Sprintf("%d profiles enforcing", parseAANumber(out, "profiles are in enforce mode")), Target: ">= 1 enforcing profile", Detail: "parsed aa-status output"},
		{Check: checkMAC004(), Status: modules.ComplianceStatus(unconfined == 0), Current: fmt.Sprintf("%d unconfined", unconfined), Target: "0", Detail: "parsed aa-status output"},
		newSkipped(checkMAC005(), "n/a", "targeted or mls", "SELinux-only check"),
	}, nil
}

func (m *Module) auditSELinux(ctx context.Context) ([]modules.Finding, error) {
	out, err := m.runner()(ctx, "sestatus")
	config := readSELinuxConfig(m.selinuxConfigPath())
	if err != nil {
		return []modules.Finding{
			{Check: checkMAC001(), Status: modules.StatusNonCompliant, Current: "sestatus failed", Target: "installed", Detail: strings.TrimSpace(out)},
			newSkipped(checkMAC002(), "unknown", "enabled", "sestatus unavailable"),
			newSkipped(checkMAC003(), "unknown", "enforcing", "sestatus unavailable"),
			newSkipped(checkMAC004(), "n/a", "0", "AppArmor-only check"),
			newSkipped(checkMAC005(), "unknown", "targeted or mls", "sestatus unavailable"),
		}, nil
	}

	status := strings.ToLower(parseStatusValue(out, "SELinux status"))
	currentMode := strings.ToLower(parseStatusValue(out, "Current mode"))
	loadedPolicy := strings.ToLower(parseStatusValue(out, "Loaded policy name"))
	cfgMode := strings.ToLower(config["selinux"])
	cfgType := strings.ToLower(config["selinuxtype"])

	enabled := status == "enabled" && cfgMode != "disabled"
	enforcing := currentMode == "enforcing"
	policy := loadedPolicy
	if policy == "" {
		policy = cfgType
	}
	policyOk := policy == "targeted" || policy == "mls"

	return []modules.Finding{
		{Check: checkMAC001(), Status: modules.StatusCompliant, Current: "sestatus available", Target: "installed", Detail: "SELinux userspace tooling detected"},
		{Check: checkMAC002(), Status: modules.ComplianceStatus(enabled), Current: valueOrUnknown(boolLabel(enabled), status == ""), Target: "enabled", Detail: fmt.Sprintf("SELinux status=%q, config SELINUX=%q", status, cfgMode)},
		{Check: checkMAC003(), Status: modules.ComplianceStatus(enforcing), Current: valueOrUnknown(currentMode, currentMode == ""), Target: "enforcing", Detail: "parsed sestatus output"},
		newSkipped(checkMAC004(), "n/a", "0", "AppArmor-only check"),
		{Check: checkMAC005(), Status: modules.ComplianceStatus(policyOk), Current: valueOrUnknown(policy, policy == ""), Target: "targeted or mls", Detail: fmt.Sprintf("SELINUXTYPE=%q", cfgType)},
	}, nil
}

func (m *Module) selinuxConfigPath() string {
	if m.selinuxConfig != "" {
		return m.selinuxConfig
	}
	return defaultSELinuxConfig
}

func (m *Module) apparmorEnabledPath() string {
	if m.apparmorEnabled != "" {
		return m.apparmorEnabled
	}
	return "/sys/module/apparmor/parameters/enabled"
}

func checkMAC001() modules.Check {
	return modules.Check{ID: "mac-001", Title: "AppArmor / SELinux is installed", Severity: modules.SeverityCritical, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "1.6.1"}, {Framework: "STIG", Control: "V-238332"}}}
}

func checkMAC002() modules.Check {
	return modules.Check{ID: "mac-002", Title: "AppArmor / SELinux is enabled at boot", Severity: modules.SeverityCritical, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "1.6.2"}, {Framework: "STIG", Control: "V-238333"}}}
}

func checkMAC003() modules.Check {
	return modules.Check{ID: "mac-003", Title: "All profiles/policies are in enforcing mode", Severity: modules.SeverityHigh, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "1.6.3"}, {Framework: "STIG", Control: "V-238334"}}}
}

func checkMAC004() modules.Check {
	return modules.Check{ID: "mac-004", Title: "No unconfined processes (AppArmor)", Severity: modules.SeverityHigh, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "1.6.4"}}}
}

func checkMAC005() modules.Check {
	return modules.Check{ID: "mac-005", Title: "SELinux policy type is targeted or mls", Severity: modules.SeverityHigh, Compliance: []modules.ComplianceRef{{Framework: "STIG", Control: "V-238335"}}}
}

func parseAANumber(output, phrase string) int {
	s := bufio.NewScanner(strings.NewReader(output))
	needle := strings.ToLower(phrase)
	for s.Scan() {
		line := strings.ToLower(strings.TrimSpace(s.Text()))
		if !strings.Contains(line, needle) {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			return -1
		}
		var n int
		if _, err := fmt.Sscanf(parts[0], "%d", &n); err == nil {
			return n
		}
	}
	return -1
}

func parseStatusValue(output, key string) string {
	s := bufio.NewScanner(strings.NewReader(output))
	for s.Scan() {
		line := s.Text()
		if !strings.Contains(strings.ToLower(line), strings.ToLower(key)) {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func readSELinuxConfig(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
	}
	return out
}

func boolLabel(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

func valueOrUnknown(v string, unknown bool) string {
	if unknown || strings.TrimSpace(v) == "" {
		return "unknown"
	}
	return v
}

func cfgString(cfg modules.ModuleConfig, key, fallback string) string {
	if cfg != nil {
		if val, ok := cfg[key]; ok {
			if s, ok := val.(string); ok {
				return s
			}
		}
	}
	return fallback
}

func newSkipped(chk modules.Check, current, target, detail string) modules.Finding {
	return modules.Finding{Check: chk, Status: modules.StatusSkipped, Current: current, Target: target, Detail: detail}
}
