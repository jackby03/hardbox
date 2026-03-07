package ssh

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
)

const (
	sshdConfig = "/etc/ssh/sshd_config"
)

// Module implements SSH daemon hardening.
type Module struct{}

func (m *Module) Name() string    { return "ssh" }
func (m *Module) Version() string { return "1.0" }

// Audit reads /etc/ssh/sshd_config and checks each setting against the profile.
func (m *Module) Audit(_ context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	content, err := os.ReadFile(sshdConfig)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", sshdConfig, err)
	}

	parsed := parseSshdConfig(content)
	var findings []modules.Finding

	checks := defaultChecks(cfg)
	for _, chk := range checks {
		current := parsed[strings.ToLower(chk.key)]
		status := modules.StatusCompliant
		detail := fmt.Sprintf("current: %q, expected: %q", current, chk.expected)

		if !chk.validate(current) {
			status = modules.StatusNonCompliant
		}

		findings = append(findings, modules.Finding{
			Check:   chk.check,
			Status:  status,
			Current: current,
			Target:  chk.expected,
			Detail:  detail,
		})
	}
	return findings, nil
}

// Plan returns atomic Changes for every non-compliant SSH setting.
func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, cfg)
	if err != nil {
		return nil, err
	}

	var changes []modules.Change
	for _, f := range findings {
		if f.IsCompliant() {
			continue
		}
		f := f // capture
		changes = append(changes, modules.Change{
			Description:  fmt.Sprintf("SSH: set %s = %s", f.Check.ID, f.Target),
			DryRunOutput: fmt.Sprintf("  %s: %q → %q", f.Check.Title, f.Current, f.Target),
			Apply: func() error {
				return setSshdOption(f.Check.ID, f.Target)
			},
			Revert: func() error {
				return setSshdOption(f.Check.ID, f.Current)
			},
		})
	}
	return changes, nil
}

// ── internal helpers ────────────────────────────────────────────────────────

type sshdCheck struct {
	check    modules.Check
	key      string
	expected string
	validate func(current string) bool
}

func eq(expected string) func(string) bool {
	return func(current string) bool {
		return strings.EqualFold(strings.TrimSpace(current), expected)
	}
}

func lteInt(max int) func(string) bool {
	return func(current string) bool {
		v, err := strconv.Atoi(strings.TrimSpace(current))
		if err != nil {
			return false
		}
		return v <= max
	}
}

func defaultChecks(cfg modules.ModuleConfig) []sshdCheck {
	return []sshdCheck{
		{
			check: modules.Check{
				ID: "ssh-001", Title: "Disable root login",
				Severity: modules.SeverityCritical,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.8"},
					{Framework: "NIST", Control: "AC-6"},
					{Framework: "STIG", Control: "V-238218"},
				},
			},
			key: "permitrootlogin", expected: "no",
			validate: eq("no"),
		},
		{
			check: modules.Check{
				ID: "ssh-002", Title: "Disable password authentication",
				Severity: modules.SeverityCritical,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.12"},
					{Framework: "NIST", Control: "IA-5"},
				},
			},
			key: "passwordauthentication", expected: "no",
			validate: eq("no"),
		},
		{
			check: modules.Check{
				ID: "ssh-003", Title: "Set MaxAuthTries ≤ 4",
				Severity: modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.7"},
					{Framework: "NIST", Control: "AC-7"},
				},
			},
			key: "maxauthtries", expected: "3",
			validate: lteInt(4),
		},
		{
			check: modules.Check{
				ID: "ssh-005", Title: "Disable X11 forwarding",
				Severity: modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.6"},
				},
			},
			key: "x11forwarding", expected: "no",
			validate: eq("no"),
		},
		{
			check: modules.Check{
				ID: "ssh-015", Title: "Disable empty passwords",
				Severity: modules.SeverityCritical,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.11"},
					{Framework: "NIST", Control: "IA-5"},
				},
			},
			key: "permitemptypasswords", expected: "no",
			validate: eq("no"),
		},
	}
}

// parseSshdConfig returns a lowercase key → value map from sshd_config content.
func parseSshdConfig(data []byte) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		result[strings.ToLower(parts[0])] = parts[1]
	}
	return result
}

// setSshdOption updates or adds a key = value line in sshd_config.
// It writes atomically and does not leave partial files.
func setSshdOption(key, value string) error {
	data, err := os.ReadFile(sshdConfig)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(key)+" ") ||
			strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(key)+"\t") {
			lines[i] = fmt.Sprintf("%s %s", key, value)
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("%s %s", key, value))
	}

	return atomicWriteText(sshdConfig, strings.Join(lines, "\n"), 0600)
}

func atomicWriteText(path, content string, mode os.FileMode) error {
	dir := strings.TrimSuffix(path, "/"+strings.TrimPrefix(path, path[:strings.LastIndex(path, "/")+1]))
	tmp, err := os.CreateTemp(dir, ".hardbox-sshd-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
