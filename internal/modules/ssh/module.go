package ssh

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

const (
	sshdConfig = "/etc/ssh/sshd_config"
)

// Module implements SSH daemon hardening.
type Module struct {
	configPath string // defaults to sshdConfig if empty
}

func (m *Module) Name() string    { return "ssh" }
func (m *Module) Version() string { return "1.0" }

// Audit reads /etc/ssh/sshd_config and checks each setting against the profile.
func (m *Module) Audit(_ context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	path := m.configPath
	if path == "" {
		path = sshdConfig
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	parsed := parseSshdConfig(content)
	var findings []modules.Finding

	checks := defaultChecks(cfg)
	for _, chk := range checks {
		current := parsed[strings.ToLower(chk.key)]
		var pass bool
		if chk.validateFull != nil {
			pass = chk.validateFull(parsed)
		} else {
			pass = chk.validate(current)
		}

		status := modules.StatusCompliant
		if !pass {
			status = modules.StatusNonCompliant
		}

		detail := fmt.Sprintf("current: %q, expected: %q", current, chk.expected)
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
	check        modules.Check
	key          string
	expected     string
	validate     func(current string) bool
	validateFull func(parsed map[string]string) bool // for multi-key or complex checks
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

// containsNone returns true if the comma-separated current value contains none of the banned items.
// Each token is compared by exact match. Banned entries that end with "-" are treated as prefix
// matches (e.g. "gss-group1-sha1-" matches "gss-group1-sha1-tohost").
func containsNone(banned []string) func(string) bool {
	return func(current string) bool {
		if strings.TrimSpace(current) == "" {
			return false
		}
		tokens := strings.Split(current, ",")
		for _, rawToken := range tokens {
			token := strings.ToLower(strings.TrimSpace(rawToken))
			if token == "" {
				continue
			}
			for _, b := range banned {
				bannedLower := strings.ToLower(strings.TrimSpace(b))
				if bannedLower == "" {
					continue
				}
				// Entries ending with "-" are prefix patterns (e.g. "gss-group1-sha1-").
				if strings.HasSuffix(bannedLower, "-") {
					if strings.HasPrefix(token, bannedLower) {
						return false
					}
				} else {
					if token == bannedLower {
						return false
					}
				}
			}
		}
		return true
	}
}

var (
	weakCiphers = []string{
		"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
		"arcfour", "arcfour128", "arcfour256", "blowfish-cbc",
		"cast128-cbc", "rijndael-cbc@lysator.liu.se",
	}
	weakMACs = []string{
		"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
		"hmac-ripemd160", "umac-64@openssh.com",
	}
	weakKex = []string{
		"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
		"gss-gex-sha1-", "gss-group1-sha1-", "gss-group14-sha1-",
	}
)

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
				ID: "ssh-004", Title: "Set LoginGraceTime ≤ 60",
				Severity: modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.16"},
					{Framework: "NIST", Control: "AC-2"},
				},
			},
			key: "logingracetime", expected: "30",
			validate: func(v string) bool {
				val, err := strconv.Atoi(strings.TrimSpace(v))
				if err != nil {
					return false
				}
				return val > 0 && val <= 60
			},
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
				ID: "ssh-006", Title: "Disable TCP forwarding",
				Severity: modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.21"},
				},
			},
			key: "allowtcpforwarding", expected: "no",
			validate: eq("no"),
		},
		{
			check: modules.Check{
				ID: "ssh-007", Title: "Set ClientAliveInterval and ClientAliveCountMax",
				Severity: modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.16"},
					{Framework: "NIST", Control: "SC-10"},
					{Framework: "STIG", Control: "V-238233"},
				},
			},
			key: "clientaliveinterval", expected: "300/3",
			validateFull: func(parsed map[string]string) bool {
				interval, err1 := strconv.Atoi(strings.TrimSpace(parsed["clientaliveinterval"]))
				count, err2 := strconv.Atoi(strings.TrimSpace(parsed["clientalivecountmax"]))
				if err1 != nil || err2 != nil {
					return false
				}
				return interval > 0 && interval <= 300 && count > 0 && count <= 3
			},
		},
		{
			check: modules.Check{
				ID: "ssh-008", Title: "Restrict AllowUsers or AllowGroups",
				Severity: modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.22"},
					{Framework: "NIST", Control: "AC-17"},
				},
			},
			key: "allowusers", expected: "<configured>",
			validateFull: func(parsed map[string]string) bool {
				return parsed["allowusers"] != "" || parsed["allowgroups"] != ""
			},
		},
		{
			check: modules.Check{
				ID: "ssh-009", Title: "Enforce strong ciphers only",
				Severity: modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.14"},
					{Framework: "NIST", Control: "SC-8"},
					{Framework: "STIG", Control: "V-238234"},
				},
			},
			key:      "ciphers",
			expected: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
			validate: containsNone(weakCiphers),
		},
		{
			check: modules.Check{
				ID: "ssh-010", Title: "Enforce strong MACs only",
				Severity: modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.15"},
					{Framework: "NIST", Control: "SC-8"},
					{Framework: "STIG", Control: "V-238235"},
				},
			},
			key:      "macs",
			expected: "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256",
			validate: containsNone(weakMACs),
		},
		{
			check: modules.Check{
				ID: "ssh-011", Title: "Enforce strong KexAlgorithms",
				Severity: modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.15"},
					{Framework: "NIST", Control: "SC-8"},
				},
			},
			key:      "kexalgorithms",
			expected: "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512",
			validate: containsNone(weakKex),
		},
		{
			check: modules.Check{
				ID: "ssh-012", Title: "Set LogLevel VERBOSE",
				Severity: modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.5"},
					{Framework: "NIST", Control: "AU-12"},
					{Framework: "STIG", Control: "V-238225"},
				},
			},
			key: "loglevel", expected: "VERBOSE",
			validate: eq("verbose"),
		},
		{
			check: modules.Check{
				ID: "ssh-013", Title: "Disable IgnoreRhosts",
				Severity: modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.9"},
				},
			},
			key: "ignorerhosts", expected: "yes",
			validate: eq("yes"),
		},
		{
			check: modules.Check{
				ID: "ssh-014", Title: "Set StrictModes yes",
				Severity: modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{},
			},
			key: "strictmodes", expected: "yes",
			validate: eq("yes"),
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
		{
			check: modules.Check{
				ID: "ssh-016", Title: "Set MaxSessions ≤ 10",
				Severity: modules.SeverityLow,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "5.2.20"},
				},
			},
			key: "maxsessions", expected: "4",
			validate: lteInt(10),
		},
		{
			check: modules.Check{
				ID: "ssh-017", Title: "Non-default SSH port",
				Severity: modules.SeverityInfo,
				Compliance: []modules.ComplianceRef{},
			},
			key: "port", expected: "!22",
			validateFull: func(parsed map[string]string) bool {
				port := strings.TrimSpace(parsed["port"])
				return port != "" && port != "22"
			},
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

	return util.AtomicWrite(sshdConfig, []byte(strings.Join(lines, "\n")), 0600)
}
