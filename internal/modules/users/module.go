package users

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
	defaultLoginDefs   = "/etc/login.defs"
	defaultPamDir      = "/etc/pam.d"
	defaultPasswdFile  = "/etc/passwd"
	defaultSudoers     = "/etc/sudoers"
	defaultSudoersDir  = "/etc/sudoers.d"
	defaultUseraddConf = "/etc/default/useradd"
)

// nonInteractiveShells is the set of shells that indicate non-interactive accounts.
var nonInteractiveShells = map[string]bool{
	"/usr/sbin/nologin": true,
	"/sbin/nologin":     true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
	"/bin/sync":         true,
}

type commandRunner func(ctx context.Context, name string, args ...string) (string, error)

type passwdEntry struct {
	username string
	uid      int
	shell    string
}

// Module implements user account and PAM hardening checks.
type Module struct {
	run         commandRunner
	loginDefs   string
	pamDir      string
	passwdFile  string
	sudoers     string
	sudoersDir  string
	useraddConf string
}

func (m *Module) Name() string    { return "users" }
func (m *Module) Version() string { return "0.1.0" }

func (m *Module) runner() commandRunner {
	if m.run != nil {
		return m.run
	}
	return runCommand
}

func (m *Module) loginDefsPath() string {
	if m.loginDefs != "" {
		return m.loginDefs
	}
	return defaultLoginDefs
}

func (m *Module) pamDirPath() string {
	if m.pamDir != "" {
		return m.pamDir
	}
	return defaultPamDir
}

func (m *Module) passwdPath() string {
	if m.passwdFile != "" {
		return m.passwdFile
	}
	return defaultPasswdFile
}

func (m *Module) sudoersPath() string {
	if m.sudoers != "" {
		return m.sudoers
	}
	return defaultSudoers
}

func (m *Module) sudoersDirPath() string {
	if m.sudoersDir != "" {
		return m.sudoersDir
	}
	return defaultSudoersDir
}

func (m *Module) useraddConfPath() string {
	if m.useraddConf != "" {
		return m.useraddConf
	}
	return defaultUseraddConf
}

// Audit runs all 17 user/PAM hardening checks.
func (m *Module) Audit(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	loginDefs := m.readFileOrEmpty(m.loginDefsPath())
	pamContent := m.loadPamContent()
	passwd, passwdErr := parsePasswdFile(m.passwdPath())
	sudoersContent := m.loadSudoersAll()
	useraddContent := m.readFileOrEmpty(m.useraddConfPath())

	var findings []modules.Finding

	// ── login.defs checks ─────────────────────────────────────────────────────

	findings = append(findings, m.auditLoginDefsInt(loginDefs, "PASS_MAX_DAYS", checkUSR001(),
		func(v int) bool { return v > 0 && v <= 90 },
		"≤ 90"))

	findings = append(findings, m.auditLoginDefsInt(loginDefs, "PASS_MIN_DAYS", checkUSR002(),
		func(v int) bool { return v >= 1 },
		"≥ 1"))

	findings = append(findings, m.auditLoginDefsInt(loginDefs, "PASS_WARN_AGE", checkUSR003(),
		func(v int) bool { return v >= 7 },
		"≥ 7"))

	findings = append(findings, m.auditLoginDefsInt(loginDefs, "PASS_MIN_LEN", checkUSR004(),
		func(v int) bool { return v >= 14 },
		"≥ 14"))

	// ── PAM checks ────────────────────────────────────────────────────────────

	findings = append(findings, m.auditPAMComplexity(pamContent))

	findings = append(findings, m.auditPAMHistory(pamContent))

	findings = append(findings, m.auditPAMLockoutDeny(pamContent))

	findings = append(findings, m.auditPAMLockoutUnlockTime(pamContent))

	findings = append(findings, m.auditPAMRootLockout(pamContent))

	// ── passwd checks ─────────────────────────────────────────────────────────

	findings = append(findings, m.auditUID0(passwd, passwdErr))

	findings = append(findings, m.auditSystemShells(passwd, passwdErr))

	// ── sudo checks ───────────────────────────────────────────────────────────

	findings = append(findings, m.auditSudoersInclude(sudoersContent))

	findings = append(findings, m.auditSudoersNopasswd(sudoersContent))

	findings = append(findings, m.auditSudoersAuthenticate(sudoersContent))

	// ── environment checks ────────────────────────────────────────────────────

	findings = append(findings, m.auditUmask(loginDefs))

	findings = append(findings, m.auditPathSafety(loginDefs))

	findings = append(findings, m.auditInactiveExpiry(useraddContent))

	return findings, nil
}

// Plan returns changes that correct /etc/login.defs and /etc/default/useradd.
func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, cfg)
	if err != nil {
		return nil, err
	}

	var changes []modules.Change

	// Determine which login.defs keys need fixing.
	loginDefsKeys := map[string]string{}
	useraddFix := false
	for _, f := range findings {
		if f.Status != modules.StatusNonCompliant {
			continue
		}
		switch f.Check.ID {
		case "usr-001":
			loginDefsKeys["PASS_MAX_DAYS"] = "90"
		case "usr-002":
			loginDefsKeys["PASS_MIN_DAYS"] = "1"
		case "usr-003":
			loginDefsKeys["PASS_WARN_AGE"] = "14"
		case "usr-004":
			loginDefsKeys["PASS_MIN_LEN"] = "14"
		case "usr-015":
			loginDefsKeys["UMASK"] = "027"
		case "usr-017":
			useraddFix = true
		}
	}

	if len(loginDefsKeys) > 0 {
		ch, err := m.planLoginDefs(loginDefsKeys)
		if err != nil {
			return nil, err
		}
		if ch != nil {
			changes = append(changes, *ch)
		}
	}

	if useraddFix {
		ch, err := m.planUseraddInactive()
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

func (m *Module) auditLoginDefsInt(content, key string, check modules.Check, ok func(int) bool, target string) modules.Finding {
	val, found := parseLoginDefsKey(content, key)
	if !found {
		return modules.Finding{
			Check:   check,
			Status:  modules.StatusNonCompliant,
			Current: "not set",
			Target:  target,
		}
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return modules.Finding{
			Check:   check,
			Status:  modules.StatusError,
			Current: val,
			Target:  target,
		}
	}
	status := modules.StatusNonCompliant
	if ok(n) {
		status = modules.StatusCompliant
	}
	return modules.Finding{
		Check:   check,
		Status:  status,
		Current: val,
		Target:  target,
	}
}

func (m *Module) auditPAMComplexity(pamContent string) modules.Finding {
	has := pamHasModule(pamContent, "pam_pwquality.so") ||
		pamHasModule(pamContent, "pam_cracklib.so")
	status := modules.StatusNonCompliant
	current := "pam_pwquality.so / pam_cracklib.so not found"
	if pamContent == "" {
		return modules.Finding{Check: checkUSR005(), Status: modules.StatusSkipped,
			Current: "PAM directory not found", Target: "pam_pwquality.so or pam_cracklib.so present"}
	}
	if has {
		status = modules.StatusCompliant
		current = "complexity module present"
	}
	return modules.Finding{
		Check:   checkUSR005(),
		Status:  status,
		Current: current,
		Target:  "pam_pwquality.so or pam_cracklib.so present",
	}
}

func (m *Module) auditPAMHistory(pamContent string) modules.Finding {
	if pamContent == "" {
		return modules.Finding{Check: checkUSR006(), Status: modules.StatusSkipped,
			Current: "PAM directory not found", Target: "remember ≥ 5"}
	}
	remember, ok := pamOptionInt(pamContent, "pam_pwhistory.so", "remember")
	if !ok {
		remember, ok = pamOptionInt(pamContent, "pam_unix.so", "remember")
	}
	if !ok || remember < 5 {
		current := "not configured"
		if ok {
			current = fmt.Sprintf("remember=%d", remember)
		}
		return modules.Finding{Check: checkUSR006(), Status: modules.StatusNonCompliant,
			Current: current, Target: "remember ≥ 5"}
	}
	return modules.Finding{Check: checkUSR006(), Status: modules.StatusCompliant,
		Current: fmt.Sprintf("remember=%d", remember), Target: "remember ≥ 5"}
}

func (m *Module) auditPAMLockoutDeny(pamContent string) modules.Finding {
	if pamContent == "" {
		return modules.Finding{Check: checkUSR007(), Status: modules.StatusSkipped,
			Current: "PAM directory not found", Target: "deny ≤ 5"}
	}
	deny, ok := pamOptionInt(pamContent, "pam_faillock.so", "deny")
	if !ok {
		deny, ok = pamOptionInt(pamContent, "pam_tally2.so", "deny")
	}
	if !ok {
		return modules.Finding{Check: checkUSR007(), Status: modules.StatusNonCompliant,
			Current: "pam_faillock / pam_tally2 not configured", Target: "deny ≤ 5"}
	}
	status := modules.StatusNonCompliant
	if deny > 0 && deny <= 5 {
		status = modules.StatusCompliant
	}
	return modules.Finding{Check: checkUSR007(), Status: status,
		Current: fmt.Sprintf("deny=%d", deny), Target: "deny ≤ 5"}
}

func (m *Module) auditPAMLockoutUnlockTime(pamContent string) modules.Finding {
	if pamContent == "" {
		return modules.Finding{Check: checkUSR008(), Status: modules.StatusSkipped,
			Current: "PAM directory not found", Target: "unlock_time ≥ 900"}
	}
	unlockTime, ok := pamOptionInt(pamContent, "pam_faillock.so", "unlock_time")
	if !ok {
		return modules.Finding{Check: checkUSR008(), Status: modules.StatusNonCompliant,
			Current: "unlock_time not configured", Target: "unlock_time ≥ 900"}
	}
	status := modules.StatusNonCompliant
	if unlockTime >= 900 {
		status = modules.StatusCompliant
	}
	return modules.Finding{Check: checkUSR008(), Status: status,
		Current: fmt.Sprintf("unlock_time=%d", unlockTime), Target: "unlock_time ≥ 900"}
}

func (m *Module) auditPAMRootLockout(pamContent string) modules.Finding {
	if pamContent == "" {
		return modules.Finding{Check: checkUSR009(), Status: modules.StatusSkipped,
			Current: "PAM directory not found", Target: "even_deny_root present"}
	}
	has := pamHasFlag(pamContent, "pam_faillock.so", "even_deny_root")
	status := modules.StatusNonCompliant
	current := "even_deny_root not set"
	if has {
		status = modules.StatusCompliant
		current = "even_deny_root present"
	}
	return modules.Finding{Check: checkUSR009(), Status: status, Current: current,
		Target: "even_deny_root present"}
}

func (m *Module) auditUID0(passwd []passwdEntry, passwdErr error) modules.Finding {
	if passwdErr != nil {
		return modules.Finding{Check: checkUSR010(), Status: modules.StatusError,
			Current: "cannot read passwd: " + passwdErr.Error(), Target: "only root has UID 0"}
	}
	var extras []string
	for _, e := range passwd {
		if e.uid == 0 && e.username != "root" {
			extras = append(extras, e.username)
		}
	}
	if len(extras) > 0 {
		return modules.Finding{Check: checkUSR010(), Status: modules.StatusNonCompliant,
			Current: "non-root UID 0 accounts: " + strings.Join(extras, ", "),
			Target:  "only root has UID 0"}
	}
	return modules.Finding{Check: checkUSR010(), Status: modules.StatusCompliant,
		Current: "only root has UID 0", Target: "only root has UID 0"}
}

func (m *Module) auditSystemShells(passwd []passwdEntry, passwdErr error) modules.Finding {
	if passwdErr != nil {
		return modules.Finding{Check: checkUSR011(), Status: modules.StatusError,
			Current: "cannot read passwd: " + passwdErr.Error(),
			Target:  "no interactive system shells"}
	}
	var offenders []string
	for _, e := range passwd {
		if e.uid > 0 && e.uid < 1000 && !nonInteractiveShells[e.shell] {
			offenders = append(offenders, fmt.Sprintf("%s (shell=%s)", e.username, e.shell))
		}
	}
	if len(offenders) > 0 {
		return modules.Finding{Check: checkUSR011(), Status: modules.StatusNonCompliant,
			Current: strings.Join(offenders, ", "), Target: "no interactive system shells"}
	}
	return modules.Finding{Check: checkUSR011(), Status: modules.StatusCompliant,
		Current: "no interactive system shells found", Target: "no interactive system shells"}
}

func (m *Module) auditSudoersInclude(content string) modules.Finding {
	if content == "" {
		return modules.Finding{Check: checkUSR012(), Status: modules.StatusSkipped,
			Current: "sudoers not readable", Target: "#includedir /etc/sudoers.d"}
	}
	has := strings.Contains(content, "#includedir") || strings.Contains(content, "@includedir")
	status := modules.StatusNonCompliant
	current := "#includedir not present"
	if has {
		status = modules.StatusCompliant
		current = "#includedir /etc/sudoers.d present"
	}
	return modules.Finding{Check: checkUSR012(), Status: status, Current: current,
		Target: "#includedir /etc/sudoers.d"}
}

func (m *Module) auditSudoersNopasswd(content string) modules.Finding {
	if content == "" {
		return modules.Finding{Check: checkUSR013(), Status: modules.StatusSkipped,
			Current: "sudoers not readable", Target: "no NOPASSWD"}
	}
	found := sudoersActiveLineContains(content, "NOPASSWD")
	status := modules.StatusCompliant
	current := "no NOPASSWD found"
	if found {
		status = modules.StatusNonCompliant
		current = "NOPASSWD present in sudoers"
	}
	return modules.Finding{Check: checkUSR013(), Status: status, Current: current,
		Target: "no NOPASSWD"}
}

func (m *Module) auditSudoersAuthenticate(content string) modules.Finding {
	if content == "" {
		return modules.Finding{Check: checkUSR014(), Status: modules.StatusSkipped,
			Current: "sudoers not readable", Target: "no !authenticate"}
	}
	found := sudoersActiveLineContains(content, "!authenticate")
	status := modules.StatusCompliant
	current := "no !authenticate found"
	if found {
		status = modules.StatusNonCompliant
		current = "!authenticate present in sudoers"
	}
	return modules.Finding{Check: checkUSR014(), Status: status, Current: current,
		Target: "no !authenticate"}
}

func (m *Module) auditUmask(loginDefs string) modules.Finding {
	val, found := parseLoginDefsKey(loginDefs, "UMASK")
	if !found {
		return modules.Finding{Check: checkUSR015(), Status: modules.StatusNonCompliant,
			Current: "not set", Target: "027 or more restrictive"}
	}
	n, err := strconv.ParseInt(val, 8, 64) // parse as octal
	if err != nil {
		return modules.Finding{Check: checkUSR015(), Status: modules.StatusError,
			Current: val, Target: "027 or more restrictive"}
	}
	// Compliant if all bits of 0o027 are set in the umask
	status := modules.StatusNonCompliant
	if n&0o027 == 0o027 {
		status = modules.StatusCompliant
	}
	return modules.Finding{Check: checkUSR015(), Status: status,
		Current: fmt.Sprintf("0%o", n), Target: "027 or more restrictive"}
}

func (m *Module) auditPathSafety(loginDefs string) modules.Finding {
	paths := []string{}
	if v, ok := parseLoginDefsKey(loginDefs, "ENV_PATH"); ok {
		paths = append(paths, v)
	}
	if v, ok := parseLoginDefsKey(loginDefs, "ENV_SUPATH"); ok {
		paths = append(paths, v)
	}
	if len(paths) == 0 {
		return modules.Finding{Check: checkUSR016(), Status: modules.StatusSkipped,
			Current: "ENV_PATH not set in login.defs", Target: "no '.' in PATH"}
	}
	for _, p := range paths {
		// strip "PATH=" prefix
		p = strings.TrimPrefix(p, "PATH=")
		for _, component := range strings.Split(p, ":") {
			if component == "." || component == "" {
				return modules.Finding{Check: checkUSR016(), Status: modules.StatusNonCompliant,
					Current: "PATH contains '.' or empty component", Target: "no '.' in PATH"}
			}
		}
	}
	return modules.Finding{Check: checkUSR016(), Status: modules.StatusCompliant,
		Current: "PATH safe", Target: "no '.' in PATH"}
}

func (m *Module) auditInactiveExpiry(useraddContent string) modules.Finding {
	val, found := parseSimpleKey(useraddContent, "INACTIVE")
	if !found {
		return modules.Finding{Check: checkUSR017(), Status: modules.StatusNonCompliant,
			Current: "not set", Target: "1–30 days"}
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return modules.Finding{Check: checkUSR017(), Status: modules.StatusError,
			Current: val, Target: "1–30 days"}
	}
	status := modules.StatusNonCompliant
	if n > 0 && n <= 30 {
		status = modules.StatusCompliant
	}
	return modules.Finding{Check: checkUSR017(), Status: status,
		Current: fmt.Sprintf("INACTIVE=%d", n), Target: "1–30 days"}
}

// ── plan helpers ──────────────────────────────────────────────────────────────

func (m *Module) planLoginDefs(keys map[string]string) (*modules.Change, error) {
	path := m.loginDefsPath()
	oldContent, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("users: read %s: %w", path, readErr)
	}
	fileExisted := readErr == nil

	newContent := string(oldContent)
	desc := make([]string, 0, len(keys))
	// Apply in deterministic order
	for _, k := range []string{"PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE", "PASS_MIN_LEN", "UMASK"} {
		if v, ok := keys[k]; ok {
			newContent = setLoginDefsKey(newContent, k, v)
			desc = append(desc, k+"="+v)
		}
	}

	ch := &modules.Change{
		Description:  "users: set login.defs " + strings.Join(desc, ", "),
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

func (m *Module) planUseraddInactive() (*modules.Change, error) {
	path := m.useraddConfPath()
	oldContent, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("users: read %s: %w", path, readErr)
	}
	fileExisted := readErr == nil

	newContent := setSimpleKey(string(oldContent), "INACTIVE", "30")

	ch := &modules.Change{
		Description:  "users: set INACTIVE=30 in " + path,
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

// ── file loading helpers ──────────────────────────────────────────────────────

func (m *Module) readFileOrEmpty(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

// loadPamContent concatenates all files in the PAM directory.
func (m *Module) loadPamContent() string {
	entries, err := os.ReadDir(m.pamDirPath())
	if err != nil {
		return ""
	}
	var sb strings.Builder
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(m.pamDirPath(), e.Name()))
		sb.Write(data)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// loadSudoersAll reads /etc/sudoers and all files in /etc/sudoers.d/.
func (m *Module) loadSudoersAll() string {
	var sb strings.Builder

	mainData, _ := os.ReadFile(m.sudoersPath())
	sb.Write(mainData)

	entries, _ := os.ReadDir(m.sudoersDirPath())
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(m.sudoersDirPath(), e.Name()))
		sb.Write(data)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// ── parsing helpers ───────────────────────────────────────────────────────────

// parseLoginDefsKey returns the value of a whitespace-separated key in login.defs content.
func parseLoginDefsKey(content, key string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == key {
			return fields[1], true
		}
	}
	return "", false
}

// setLoginDefsKey sets or replaces an active key in login.defs content.
func setLoginDefsKey(content, key, value string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 1 && fields[0] == key {
			lines[i] = key + "\t" + value
			return strings.Join(lines, "\n")
		}
	}
	// Key not found — append
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + key + "\t" + value + "\n"
}

// parseSimpleKey parses KEY=value lines (shell assignment style, as in /etc/default/useradd).
func parseSimpleKey(content, key string) (string, bool) {
	prefix := key + "="
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix)), true
		}
	}
	return "", false
}

// setSimpleKey sets or replaces a KEY=value line in shell assignment style content.
func setSimpleKey(content, key, value string) string {
	prefix := key + "="
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, prefix) {
			lines[i] = key + "=" + value
			return strings.Join(lines, "\n")
		}
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + key + "=" + value + "\n"
}

// parsePasswdFile parses /etc/passwd into a slice of passwdEntry.
func parsePasswdFile(path string) ([]passwdEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var entries []passwdEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		entries = append(entries, passwdEntry{
			username: fields[0],
			uid:      uid,
			shell:    fields[6],
		})
	}
	return entries, nil
}

// pamHasModule returns true if any non-commented PAM line references the given module.
func pamHasModule(content, pamModule string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, pamModule) {
			return true
		}
	}
	return false
}

// pamOptionInt scans PAM content for lines containing pamModule and extracts option=N.
func pamOptionInt(content, pamModule, option string) (int, bool) {
	prefix := option + "="
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, pamModule) {
			continue
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, prefix) {
				n, err := strconv.Atoi(strings.TrimPrefix(field, prefix))
				if err == nil {
					return n, true
				}
			}
		}
	}
	return 0, false
}

// pamHasFlag returns true if any PAM line containing pamModule also includes flagName as a standalone word.
func pamHasFlag(content, pamModule, flagName string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, pamModule) {
			continue
		}
		for _, field := range strings.Fields(line) {
			if field == flagName {
				return true
			}
		}
	}
	return false
}

// sudoersActiveLineContains returns true if any non-commented sudoers line contains token.
func sudoersActiveLineContains(content, token string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, token) {
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
