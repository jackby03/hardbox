package auditd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

const (
	defaultRulesDir  = "/etc/audit/rules.d"
	defaultConfPath  = "/etc/audit/auditd.conf"
	hardboxRulesFile = "99-hardbox.rules"

	minLogFileSize        = 8  // MB
	wantLogFileAction     = "keep_logs"
	wantSpaceLeftAction   = "email"
)

type commandRunner func(ctx context.Context, name string, args ...string) (string, error)

// Module implements Linux Audit Framework hardening checks.
type Module struct {
	run      commandRunner
	rulesDir string
	confPath string
}

func (m *Module) Name() string    { return "auditd" }
func (m *Module) Version() string { return "0.1.0" }

func (m *Module) runner() commandRunner {
	if m.run != nil {
		return m.run
	}
	return runCommand
}

func (m *Module) getRulesDir() string {
	if m.rulesDir != "" {
		return m.rulesDir
	}
	return defaultRulesDir
}

func (m *Module) getConfPath() string {
	if m.confPath != "" {
		return m.confPath
	}
	return defaultConfPath
}

// Audit inspects the live system and returns audit framework findings.
func (m *Module) Audit(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	rules, err := m.loadRules()
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("auditd: load rules: %w", err)
	}

	conf, confErr := m.loadConf()

	var findings []modules.Finding

	// aud-001 … aud-009: rule-based checks
	ruleChecks := []struct {
		check   modules.Check
		present bool
	}{
		{checkAUD001(), hasPattern(rules, "-S execve", "-k exec")},
		{checkAUD002(), hasPattern(rules, "-S open", "-k access")},
		{checkAUD003(), hasPattern(rules, "/etc/passwd", "-k identity") && hasPattern(rules, "/etc/shadow", "-k identity")},
		{checkAUD004(), hasPattern(rules, "/etc/sudoers", "-k sudo")},
		{checkAUD005(), hasPattern(rules, "/var/log/faillog", "-k logins") || hasPattern(rules, "/var/run/faillock", "-k logins")},
		{checkAUD006(), hasPattern(rules, "-S init_module", "-k modules") || hasPattern(rules, "/sbin/modprobe", "-k modules")},
		{checkAUD007(), hasPattern(rules, "-S chmod", "-k perm_mod") || hasPattern(rules, "-S chown", "-k perm_mod")},
		{checkAUD008(), hasPattern(rules, "/etc/hosts", "-k network") || hasPattern(rules, "-S sethostname", "-k network")},
		{checkAUD009(), hasPattern(rules, "-e 2")},
	}
	for _, rc := range ruleChecks {
		status := modules.StatusNonCompliant
		current := "rule absent"
		if rc.present {
			status = modules.StatusCompliant
			current = "rule present"
		}
		findings = append(findings, modules.Finding{
			Check:   rc.check,
			Status:  status,
			Current: current,
			Target:  "rule present",
		})
	}

	// aud-010 … aud-012: auditd.conf checks
	if confErr != nil {
		for _, ch := range []modules.Check{checkAUD010(), checkAUD011(), checkAUD012()} {
			findings = append(findings, modules.Finding{
				Check:   ch,
				Status:  modules.StatusError,
				Current: "cannot read " + m.getConfPath(),
				Target:  "file readable",
				Detail:  confErr.Error(),
			})
		}
	} else {
		findings = append(findings, m.auditLogSize(conf)...)
		findings = append(findings, m.auditLogFullAction(conf)...)
		findings = append(findings, m.auditSpaceLeft(conf)...)
	}

	// aud-013: service enabled and active
	findings = append(findings, m.auditServiceStatus(ctx))

	return findings, nil
}

// Plan returns changes that write the hardbox audit rules file (and conf corrections).
func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, cfg)
	if err != nil {
		return nil, err
	}

	needsRules := false
	for _, f := range findings {
		id := f.Check.ID
		if id >= "aud-001" && id <= "aud-009" && f.Status == modules.StatusNonCompliant {
			needsRules = true
			break
		}
	}

	var changes []modules.Change

	if needsRules {
		rulesPath := filepath.Join(m.getRulesDir(), hardboxRulesFile)
		oldContent, readErr := os.ReadFile(rulesPath)
		fileExisted := readErr == nil
		newContent := hardboxRulesContent()

		changes = append(changes, modules.Change{
			Description:  fmt.Sprintf("auditd: write hardening rules to %s", rulesPath),
			DryRunOutput: newContent,
			Apply: func() error {
				if err := os.MkdirAll(m.getRulesDir(), 0o750); err != nil {
					return fmt.Errorf("auditd: create rules dir: %w", err)
				}
				return util.AtomicWrite(rulesPath, []byte(newContent), 0o640)
			},
			Revert: func() error {
				if !fileExisted {
					return os.Remove(rulesPath)
				}
				return util.AtomicWrite(rulesPath, oldContent, 0o640)
			},
		})
	}

	return changes, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// loadRules concatenates the content of all *.rules files in getRulesDir().
func (m *Module) loadRules() (string, error) {
	dir := m.getRulesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rules") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		sb.Write(data)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// loadConf reads key=value pairs from auditd.conf.
func (m *Module) loadConf() (map[string]string, error) {
	data, err := os.ReadFile(m.getConfPath())
	if err != nil {
		return nil, err
	}
	conf := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			conf[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return conf, nil
}

// hasPattern returns true if all tokens appear on the same line of rules.
func hasPattern(rules string, tokens ...string) bool {
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		match := true
		for _, tok := range tokens {
			if !strings.Contains(line, tok) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func (m *Module) auditLogSize(conf map[string]string) []modules.Finding {
	val := conf["max_log_file"]
	size, err := strconv.Atoi(val)
	status := modules.StatusNonCompliant
	if err == nil && size >= minLogFileSize {
		status = modules.StatusCompliant
	}
	current := val
	if val == "" {
		current = "not set"
	}
	return []modules.Finding{{
		Check:   checkAUD010(),
		Status:  status,
		Current: current,
		Target:  fmt.Sprintf(">= %d", minLogFileSize),
	}}
}

func (m *Module) auditLogFullAction(conf map[string]string) []modules.Finding {
	val := strings.ToLower(conf["max_log_file_action"])
	ok := val == "keep_logs" || val == "rotate"
	status := modules.StatusNonCompliant
	if ok {
		status = modules.StatusCompliant
	}
	current := val
	if val == "" {
		current = "not set"
	}
	return []modules.Finding{{
		Check:   checkAUD011(),
		Status:  status,
		Current: current,
		Target:  "keep_logs or rotate",
	}}
}

func (m *Module) auditSpaceLeft(conf map[string]string) []modules.Finding {
	val := strings.ToLower(conf["space_left_action"])
	ok := val == "email" || val == "syslog" || val == "exec"
	status := modules.StatusNonCompliant
	if ok {
		status = modules.StatusCompliant
	}
	current := val
	if val == "" {
		current = "not set"
	}
	return []modules.Finding{{
		Check:   checkAUD012(),
		Status:  status,
		Current: current,
		Target:  "email, syslog, or exec",
	}}
}

func (m *Module) auditServiceStatus(ctx context.Context) modules.Finding {
	run := m.runner()
	enabledOut, _ := run(ctx, "systemctl", "is-enabled", "auditd.service")
	activeOut, _ := run(ctx, "systemctl", "is-active", "auditd.service")
	enabled := strings.TrimSpace(enabledOut) == "enabled"
	active := strings.TrimSpace(activeOut) == "active"
	status := modules.StatusNonCompliant
	if enabled && active {
		status = modules.StatusCompliant
	}
	current := fmt.Sprintf("enabled=%v active=%v", enabled, active)
	return modules.Finding{
		Check:   checkAUD013(),
		Status:  status,
		Current: current,
		Target:  "enabled=true active=true",
	}
}

// hardboxRulesContent returns the canonical set of audit rules managed by hardbox.
func hardboxRulesContent() string {
	return `# Generated by hardbox — do not edit manually

# aud-001: execve syscall auditing by non-root
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k exec
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k exec

# aud-002: unauthorized file access attempts
-a always,exit -F arch=b64 -S open,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b64 -S open,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access

# aud-003: identity file modifications
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity

# aud-004: sudo usage logging
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo

# aud-005: login/logout/ssh events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# aud-006: kernel module loading
-a always,exit -F arch=b64 -S init_module,finit_module -k modules
-a always,exit -F arch=b64 -S delete_module -k modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# aud-007: privileged commands — chown/chmod/setuid operations
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr -F auid>=1000 -F auid!=-1 -k perm_mod

# aud-008: network config changes
-w /etc/hosts -p wa -k network
-w /etc/sysconfig/network -p wa -k network
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network

# aud-009: log immutability (must be last)
-e 2
`
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
