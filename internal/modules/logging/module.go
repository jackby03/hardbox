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
package logging

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

const (
	defaultRsyslogConf    = "/etc/rsyslog.conf"
	defaultRsyslogConfDir = "/etc/rsyslog.d"
	defaultJournaldConf   = "/etc/systemd/journald.conf"
	defaultLogrotateConf  = "/etc/logrotate.conf"
	defaultLogrotateDir   = "/etc/logrotate.d"
	defaultVarLog         = "/var/log"
)

type commandRunner func(ctx context.Context, name string, args ...string) (string, error)

// Module implements system logging hardening checks (rsyslog + journald).
type Module struct {
	run           commandRunner
	rsyslogConf   string
	rsyslogDir    string
	journaldConf  string
	logrotateConf string
	logrotateDir  string
	varLog        string
}

func (m *Module) Name() string    { return "logging" }
func (m *Module) Version() string { return "0.1.0" }

func (m *Module) runner() commandRunner {
	if m.run != nil {
		return m.run
	}
	return runCommand
}

func (m *Module) rsyslogConfPath() string {
	if m.rsyslogConf != "" {
		return m.rsyslogConf
	}
	return defaultRsyslogConf
}

func (m *Module) rsyslogDirPath() string {
	if m.rsyslogDir != "" {
		return m.rsyslogDir
	}
	return defaultRsyslogConfDir
}

func (m *Module) journaldConfPath() string {
	if m.journaldConf != "" {
		return m.journaldConf
	}
	return defaultJournaldConf
}

func (m *Module) logrotateConfPath() string {
	if m.logrotateConf != "" {
		return m.logrotateConf
	}
	return defaultLogrotateConf
}

func (m *Module) logrotateDirPath() string {
	if m.logrotateDir != "" {
		return m.logrotateDir
	}
	return defaultLogrotateDir
}

func (m *Module) varLogPath() string {
	if m.varLog != "" {
		return m.varLog
	}
	return defaultVarLog
}

// Audit inspects logging service state and configuration.
func (m *Module) Audit(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	var findings []modules.Finding

	// log-001: rsyslog or syslog-ng installed and active
	findings = append(findings, m.auditSyslogService(ctx))

	// log-002: rsyslog sends logs to remote server
	findings = append(findings, m.auditRemoteTarget(ctx))

	// log-003: rsyslog file permissions restricted (0640 or tighter)
	findings = append(findings, m.auditRsyslogPermissions(ctx))

	// log-004: journald persistent storage enabled
	findings = append(findings, m.auditJournaldPersistence())

	// log-005: journald forwarding to syslog
	findings = append(findings, m.auditJournaldForwardSyslog())

	// log-006: logrotate configured
	findings = append(findings, m.auditLogrotate())

	// log-007: log files not world-readable under /var/log
	worldReadable := m.worldReadableLogFiles()
	status := modules.StatusCompliant
	current := "none found"
	if len(worldReadable) > 0 {
		status = modules.StatusNonCompliant
		current = strings.Join(worldReadable, ", ")
	}
	findings = append(findings, modules.Finding{
		Check:   checkLOG007(),
		Status:  status,
		Current: current,
		Target:  "no world-readable log files",
	})

	return findings, nil
}

// Plan returns changes that correct journald.conf when persistent storage is missing.
func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, cfg)
	if err != nil {
		return nil, err
	}

	var changes []modules.Change
	wantStorage := false
	wantForward := false

	for _, f := range findings {
		if f.Status != modules.StatusNonCompliant {
			continue
		}
		switch f.Check.ID {
		case "log-004":
			wantStorage = true
		case "log-005":
			wantForward = true
		}
	}

	if wantStorage || wantForward {
		ch, err := m.planJournaldUpdate(wantStorage, wantForward)
		if err != nil {
			return nil, err
		}
		if ch != nil {
			changes = append(changes, *ch)
		}
	}

	return changes, nil
}

// ── audit helpers ─────────────────────────────────────────────────────────────

func (m *Module) auditSyslogService(ctx context.Context) modules.Finding {
	run := m.runner()
	for _, unit := range []string{"rsyslog.service", "syslog-ng.service"} {
		enabledOut, _ := run(ctx, "systemctl", "is-enabled", unit)
		activeOut, _ := run(ctx, "systemctl", "is-active", unit)
		if strings.TrimSpace(enabledOut) == "enabled" && strings.TrimSpace(activeOut) == "active" {
			return modules.Finding{
				Check:   checkLOG001(),
				Status:  modules.StatusCompliant,
				Current: unit + " enabled and active",
				Target:  "rsyslog.service or syslog-ng.service active",
			}
		}
	}
	return modules.Finding{
		Check:   checkLOG001(),
		Status:  modules.StatusNonCompliant,
		Current: "no syslog service active",
		Target:  "rsyslog.service or syslog-ng.service active",
	}
}

func (m *Module) auditRemoteTarget(_ context.Context) modules.Finding {
	content, err := m.loadRsyslogConfig()
	if err != nil {
		return modules.Finding{
			Check:   checkLOG002(),
			Status:  modules.StatusError,
			Current: "cannot read rsyslog config: " + err.Error(),
			Target:  "remote target configured (@@host or action type omfwd)",
		}
	}
	hasRemote := rsyslogHasRemoteForwarding(content)
	status := modules.StatusNonCompliant
	current := "no remote target found"
	if hasRemote {
		status = modules.StatusCompliant
		current = "remote target configured"
	}
	return modules.Finding{
		Check:   checkLOG002(),
		Status:  status,
		Current: current,
		Target:  "remote target configured (@@host or omfwd)",
	}
}

func (m *Module) auditRsyslogPermissions(_ context.Context) modules.Finding {
	path := m.rsyslogConfPath()
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return modules.Finding{
				Check:   checkLOG003(),
				Status:  modules.StatusSkipped,
				Current: path + " not found",
				Target:  "mode <= 0640",
			}
		}
		return modules.Finding{
			Check:   checkLOG003(),
			Status:  modules.StatusError,
			Current: err.Error(),
			Target:  "mode <= 0640",
		}
	}
	mode := info.Mode().Perm()
	// world-read bit (o+r = 0004) or world-write (0002) is a violation
	ok := mode&0o004 == 0 && mode&0o002 == 0
	status := modules.StatusNonCompliant
	if ok {
		status = modules.StatusCompliant
	}
	return modules.Finding{
		Check:   checkLOG003(),
		Status:  status,
		Current: fmt.Sprintf("%04o", mode),
		Target:  "mode <= 0640 (no world read/write)",
	}
}

func (m *Module) auditJournaldPersistence() modules.Finding {
	val, err := m.readJournaldKey("Storage")
	if err != nil {
		return modules.Finding{
			Check:   checkLOG004(),
			Status:  modules.StatusError,
			Current: "cannot read " + m.journaldConfPath() + ": " + err.Error(),
			Target:  "Storage=persistent",
		}
	}
	status := modules.StatusNonCompliant
	if strings.EqualFold(val, "persistent") {
		status = modules.StatusCompliant
	}
	current := val
	if current == "" {
		current = "not set (default: auto)"
	}
	return modules.Finding{
		Check:   checkLOG004(),
		Status:  status,
		Current: current,
		Target:  "persistent",
	}
}

func (m *Module) auditJournaldForwardSyslog() modules.Finding {
	val, err := m.readJournaldKey("ForwardToSyslog")
	if err != nil {
		return modules.Finding{
			Check:   checkLOG005(),
			Status:  modules.StatusError,
			Current: "cannot read " + m.journaldConfPath() + ": " + err.Error(),
			Target:  "ForwardToSyslog=yes",
		}
	}
	status := modules.StatusNonCompliant
	if strings.EqualFold(val, "yes") {
		status = modules.StatusCompliant
	}
	current := val
	if current == "" {
		current = "not set (default: no)"
	}
	return modules.Finding{
		Check:   checkLOG005(),
		Status:  status,
		Current: current,
		Target:  "yes",
	}
}

func (m *Module) auditLogrotate() modules.Finding {
	_, errConf := os.Stat(m.logrotateConfPath())
	_, errDir := os.Stat(m.logrotateDirPath())
	if errConf == nil || errDir == nil {
		return modules.Finding{
			Check:   checkLOG006(),
			Status:  modules.StatusCompliant,
			Current: "logrotate config present",
			Target:  "logrotate.conf or logrotate.d/ present",
		}
	}
	return modules.Finding{
		Check:   checkLOG006(),
		Status:  modules.StatusNonCompliant,
		Current: "logrotate config missing",
		Target:  "logrotate.conf or logrotate.d/ present",
	}
}

func (m *Module) worldReadableLogFiles() []string {
	var offenders []string
	_ = filepath.WalkDir(m.varLogPath(), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return nil
		}
		if info.Mode().Perm()&0o004 != 0 {
			offenders = append(offenders, path)
		}
		return nil
	})
	return offenders
}

// ── plan helpers ──────────────────────────────────────────────────────────────

func (m *Module) planJournaldUpdate(setStorage, setForward bool) (*modules.Change, error) {
	path := m.journaldConfPath()
	oldContent, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("logging: read %s: %w", path, readErr)
	}
	fileExisted := readErr == nil

	newContent := string(oldContent)
	desc := make([]string, 0, 2)
	if setStorage {
		newContent = setJournaldKey(newContent, "Storage", "persistent")
		desc = append(desc, "Storage=persistent")
	}
	if setForward {
		newContent = setJournaldKey(newContent, "ForwardToSyslog", "yes")
		desc = append(desc, "ForwardToSyslog=yes")
	}

	ch := &modules.Change{
		Description:  "logging: set journald " + strings.Join(desc, ", "),
		DryRunOutput: newContent,
		Apply: func() error {
			return util.AtomicWrite(path, []byte(newContent), 0o644)
		},
		Revert: func() error {
			if !fileExisted {
				return os.Remove(path)
			}
			return util.AtomicWrite(path, oldContent, 0o644)
		},
	}
	return ch, nil
}

// ── config parsing ────────────────────────────────────────────────────────────

// loadRsyslogConfig concatenates rsyslog.conf and all *.conf files in rsyslog.d/.
func (m *Module) loadRsyslogConfig() (string, error) {
	var sb strings.Builder

	mainData, err := os.ReadFile(m.rsyslogConfPath())
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	sb.Write(mainData)

	entries, err := os.ReadDir(m.rsyslogDirPath())
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(m.rsyslogDirPath(), e.Name()))
		sb.Write(data)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// readJournaldKey reads a key=value pair from journald.conf [Journal] section.
func (m *Module) readJournaldKey(key string) (string, error) {
	data, err := os.ReadFile(m.journaldConfPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	prefix := key + "="
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix)), nil
		}
	}
	return "", nil
}

// setJournaldKey sets or replaces a key in journald.conf content.
// If the key exists (possibly commented), it replaces the first occurrence.
// Otherwise appends under [Journal].
func setJournaldKey(content, key, value string) string {
	lines := strings.Split(content, "\n")
	token := key + "="
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, "# \t")
		if strings.HasPrefix(trimmed, token) {
			lines[i] = token + value
			return strings.Join(lines, "\n")
		}
	}
	// append under [Journal] section or at end
	for i, line := range lines {
		if strings.TrimSpace(line) == "[Journal]" {
			newLines := make([]string, 0, len(lines)+1)
			newLines = append(newLines, lines[:i+1]...)
			newLines = append(newLines, token+value)
			newLines = append(newLines, lines[i+1:]...)
			return strings.Join(newLines, "\n")
		}
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + token + value + "\n"
}

// rsyslogHasRemoteForwarding returns true if the config contains an active (non-commented)
// remote forwarding directive.
func rsyslogHasRemoteForwarding(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "@@") ||
			(strings.HasPrefix(trimmed, "@") && !strings.HasPrefix(trimmed, "@(")) ||
			strings.Contains(trimmed, "omfwd") {
			return true
		}
	}
	return false
}

// ── exec ──────────────────────────────────────────────────────────────────────

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

