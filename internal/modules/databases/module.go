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

// Package databases audits the configuration of MySQL/MariaDB and PostgreSQL
// servers.
//
// Scope note: everything here reads configuration files or issues read-only
// queries. The module never changes a database schema or an account, because
// rollback restores files, not table contents — an automated `DROP USER` or
// `DROP DATABASE` would be irreversible in a way the rest of the tool is not.
// Those checks are reported as manual with the exact statement to run.
package databases

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

const (
	// Drop-in locations, Debian family first then RHEL family.
	defaultMySQLDropInDebian = "/etc/mysql/conf.d/99-hardbox.cnf"
	defaultMySQLDropInRHEL   = "/etc/my.cnf.d/99-hardbox.cnf"

	// Config files consulted for the audit, in the order the server reads them.
	defaultMySQLConfGlobs = "/etc/mysql/my.cnf,/etc/my.cnf,/etc/mysql/conf.d/*.cnf,/etc/my.cnf.d/*.cnf"
	defaultPGHbaGlobs     = "/etc/postgresql/*/main/pg_hba.conf,/var/lib/pgsql/data/pg_hba.conf"
	defaultPGConfGlobs    = "/etc/postgresql/*/main/postgresql.conf,/var/lib/pgsql/data/postgresql.conf"
)

type commandRunner func(ctx context.Context, name string, args ...string) (string, error)

// Module implements database server hardening checks.
type Module struct {
	mysqlConfGlobs string // comma-separated globs of MySQL config files
	pgHbaGlobs     string
	pgConfGlobs    string
	mysqlDropIn    string // path written by remediation; empty means autodetect
	mysqlQuery     func(ctx context.Context, query string) (string, error)
	run            commandRunner
}

func (m *Module) Name() string    { return "databases" }
func (m *Module) Version() string { return "1.0" }

func (m *Module) runner() commandRunner {
	if m.run != nil {
		return m.run
	}
	return func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
}

func (m *Module) mysqlConfs() []string {
	return expandGlobs(m.mysqlConfGlobs, defaultMySQLConfGlobs)
}

func (m *Module) pgHbaFiles() []string {
	return expandGlobs(m.pgHbaGlobs, defaultPGHbaGlobs)
}

func (m *Module) pgConfFiles() []string {
	return expandGlobs(m.pgConfGlobs, defaultPGConfGlobs)
}

// expandGlobs resolves a comma-separated list of globs to existing files.
func expandGlobs(in, fallback string) []string {
	if in == "" {
		in = fallback
	}
	var out []string
	for _, pattern := range strings.Split(in, ",") {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.ContainsAny(pattern, "*?[") {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}
			out = append(out, matches...)
			continue
		}
		if _, err := os.Stat(pattern); err == nil {
			out = append(out, pattern)
		}
	}
	return out
}

func (m *Module) dropInPath() string {
	if m.mysqlDropIn != "" {
		return m.mysqlDropIn
	}
	if info, err := os.Stat(filepath.Dir(defaultMySQLDropInDebian)); err == nil && info.IsDir() {
		return defaultMySQLDropInDebian
	}
	return defaultMySQLDropInRHEL
}

// mysqlConfigured reports whether a MySQL-family server appears to be installed.
func (m *Module) mysqlConfigured() bool {
	return len(m.mysqlConfs()) > 0
}

// pgConfigured reports whether a PostgreSQL server appears to be installed.
func (m *Module) pgConfigured() bool {
	return len(m.pgHbaFiles()) > 0 || len(m.pgConfFiles()) > 0
}

// Audit inspects both database families. A family that is not installed reports
// every one of its checks as skipped rather than failing the module, so the audit
// still produces a complete report on hosts without a database server.
func (m *Module) Audit(ctx context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	findings := make([]modules.Finding, 0, 8)

	mysql := m.mysqlConfigured()
	pg := m.pgConfigured()

	findings = append(findings, m.auditMySQLBindAddress(mysql))
	findings = append(findings, m.auditMySQLLocalInfile(mysql))
	findings = append(findings, m.auditPGTrust(pg))
	findings = append(findings, m.auditPGPasswordEncryption(pg))
	findings = append(findings, m.auditPGListenAddresses(pg))
	findings = append(findings, m.auditMySQLAnonymous(ctx, mysql))
	findings = append(findings, m.auditMySQLRootRemote(ctx, mysql))
	findings = append(findings, m.auditMySQLTestDatabase(ctx, mysql))

	return findings, nil
}

// ── MySQL config checks ─────────────────────────────────────────────────────

// parseMySQLOptions returns the effective [mysqld] options across every config
// file, later files winning, which is how the server itself resolves them.
func parseMySQLOptions(files []string) map[string]string {
	opts := make(map[string]string)
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		section := ""
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.ToLower(strings.Trim(line, "[]"))
				continue
			}
			if section != "mysqld" && section != "server" && section != "mariadb" {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			// MySQL treats dashes and underscores in option names as equivalent.
			key = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "-", "_")
			opts[key] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
		f.Close()
	}
	return opts
}

func (m *Module) auditMySQLBindAddress(installed bool) modules.Finding {
	chk := checkDB001()
	if !installed {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "no MySQL/MariaDB configuration found"}
	}
	opts := parseMySQLOptions(m.mysqlConfs())
	bind, ok := opts["bind_address"]
	if !ok {
		// MySQL's default is to bind loopback only on the Debian family, but on
		// other platforms an absent directive means all interfaces.
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: "bind-address not set",
			Target:  "127.0.0.1",
			Detail:  "no bind_address directive; the server may listen on every interface",
		}
	}
	if isLoopbackAddress(bind) {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: bind, Target: "127.0.0.1"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: bind, Target: "127.0.0.1"}
}

func (m *Module) auditMySQLLocalInfile(installed bool) modules.Finding {
	chk := checkDB002()
	if !installed {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "no MySQL/MariaDB configuration found"}
	}
	opts := parseMySQLOptions(m.mysqlConfs())
	value, ok := opts["local_infile"]
	if !ok {
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: "not set",
			Target:  "0",
			Detail:  "local_infile defaults to ON unless the server disables it",
		}
	}
	if isFalsey(value) {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: value, Target: "0"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: value, Target: "0"}
}

// ── PostgreSQL config checks ────────────────────────────────────────────────

// hbaTrustRules returns the pg_hba.conf rules whose authentication method is
// 'trust', as "file:line" strings.
func hbaTrustRules(files []string) []string {
	var out []string
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			// local <db> <user> <method> [options]
			// host  <db> <user> <address> <method> [options]
			methodIdx := 3
			if len(fields) > 0 && fields[0] != "local" {
				methodIdx = 4
			}
			if len(fields) <= methodIdx {
				continue
			}
			if strings.EqualFold(fields[methodIdx], "trust") {
				out = append(out, fmt.Sprintf("%s:%d", file, lineNo))
			}
		}
		f.Close()
	}
	return out
}

// parsePGConf returns key→value from the last postgresql.conf that sets a key.
func parsePGConf(files []string) map[string]string {
	opts := make(map[string]string)
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			opts[key] = strings.Trim(strings.TrimSpace(value), `'"`)
		}
		f.Close()
	}
	return opts
}

func (m *Module) auditPGTrust(installed bool) modules.Finding {
	chk := checkDB003()
	if !installed {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "no PostgreSQL configuration found"}
	}
	rules := hbaTrustRules(m.pgHbaFiles())
	if len(rules) == 0 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "no trust rules", Target: "scram-sha-256"}
	}
	return modules.Finding{
		Check:   chk,
		Status:  modules.StatusNonCompliant,
		Current: fmt.Sprintf("%d trust rule(s)", len(rules)),
		Target:  "scram-sha-256",
		Detail:  strings.Join(rules, "\n"),
	}
}

func (m *Module) auditPGPasswordEncryption(installed bool) modules.Finding {
	chk := checkDB004()
	if !installed {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "no PostgreSQL configuration found"}
	}
	opts := parsePGConf(m.pgConfFiles())
	value := opts["password_encryption"]
	if strings.EqualFold(value, "scram-sha-256") {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: value, Target: "scram-sha-256"}
	}
	current := value
	if current == "" {
		current = "not set (default md5 on PostgreSQL < 14)"
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: current, Target: "scram-sha-256"}
}

func (m *Module) auditPGListenAddresses(installed bool) modules.Finding {
	chk := checkDB005()
	if !installed {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "no PostgreSQL configuration found"}
	}
	opts := parsePGConf(m.pgConfFiles())
	value := opts["listen_addresses"]
	if value == "" {
		// PostgreSQL's compiled-in default is localhost.
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "default (localhost)", Target: "localhost"}
	}
	if strings.Contains(value, "*") || strings.Contains(value, "0.0.0.0") {
		return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: value, Target: "localhost"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: value, Target: "localhost"}
}

// ── MySQL account checks (read-only queries) ────────────────────────────────

func (m *Module) query(ctx context.Context, query string) (string, error) {
	if m.mysqlQuery != nil {
		return m.mysqlQuery(ctx, query)
	}
	return m.runner()(ctx, "mysql", "--batch", "--skip-column-names", "-e", query)
}

// auditMySQLAnonymous reports whether any anonymous account exists.
func (m *Module) auditMySQLAnonymous(ctx context.Context, installed bool) modules.Finding {
	chk := checkDB006()
	if !installed {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "no MySQL/MariaDB configuration found"}
	}
	out, err := m.query(ctx, "SELECT COUNT(*) FROM mysql.user WHERE user = ''")
	if err != nil {
		return manualFinding(chk, "could not query the server", "SELECT user, host FROM mysql.user WHERE user = '';")
	}
	if count, ok := parseCount(out); ok && count == 0 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "0 anonymous accounts", Target: "0"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: strings.TrimSpace(out), Target: "0"}
}

func (m *Module) auditMySQLRootRemote(ctx context.Context, installed bool) modules.Finding {
	chk := checkDB007()
	if !installed {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "no MySQL/MariaDB configuration found"}
	}
	const q = "SELECT COUNT(*) FROM mysql.user WHERE user = 'root' AND host NOT IN ('localhost','127.0.0.1','::1')"
	out, err := m.query(ctx, q)
	if err != nil {
		return manualFinding(chk, "could not query the server",
			"SELECT user, host FROM mysql.user WHERE user = 'root' AND host NOT IN ('localhost','127.0.0.1','::1');")
	}
	if count, ok := parseCount(out); ok && count == 0 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "root restricted to loopback", Target: "loopback only"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: strings.TrimSpace(out), Target: "loopback only"}
}

func (m *Module) auditMySQLTestDatabase(ctx context.Context, installed bool) modules.Finding {
	chk := checkDB008()
	if !installed {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "no MySQL/MariaDB configuration found"}
	}
	out, err := m.query(ctx, "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = 'test'")
	if err != nil {
		return manualFinding(chk, "could not query the server", "SHOW DATABASES LIKE 'test';")
	}
	if count, ok := parseCount(out); ok && count == 0 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "absent", Target: "absent"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "present", Target: "absent"}
}

// manualFinding is used when the check needs credentials the tool does not have.
// StatusManual keeps it out of the score while leaving the guidance visible.
func manualFinding(chk modules.Check, current, stmt string) modules.Finding {
	return modules.Finding{
		Check:   chk,
		Status:  modules.StatusManual,
		Current: current,
		Target:  "verify manually",
		Detail:  "run: " + stmt,
	}
}

func parseCount(out string) (int, bool) {
	out = strings.TrimSpace(out)
	if out == "" {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscanf(out, "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

func isLoopbackAddress(v string) bool {
	switch strings.TrimSpace(v) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

func isFalsey(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "off", "false", "no", "disabled":
		return true
	}
	return false
}

// Plan writes the MySQL drop-in for the two configuration checks. Everything else
// is audit-only on purpose: pg_hba.conf edits can lock the operator out, and the
// account checks require DDL that rollback cannot undo.
func (m *Module) Plan(ctx context.Context, _ modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, nil)
	if err != nil {
		return nil, err
	}

	needBind, needInfile := false, false
	for _, f := range findings {
		if f.IsCompliant() {
			continue
		}
		switch f.Check.ID {
		case "db-001":
			needBind = true
		case "db-002":
			needInfile = true
		}
	}
	if !needBind && !needInfile {
		return nil, nil
	}

	var body strings.Builder
	body.WriteString("# Generated by hardbox — do not edit manually\n[mysqld]\n")
	if needBind {
		body.WriteString("bind-address = 127.0.0.1\n")
	}
	if needInfile {
		body.WriteString("local_infile = 0\n")
	}

	path := m.dropInPath()
	content := body.String()

	return []modules.Change{{
		Description:  "Databases: restrict MySQL/MariaDB exposure and LOCAL INFILE",
		DryRunOutput: "  write " + path + ":\n" + indent(content),
		Files:        []string{path},
		Apply: func() error {
			dir := filepath.Dir(path)
			if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
				return fmt.Errorf("databases: %s does not exist; is the MySQL server installed?", dir)
			}
			// Atomic write, per the project's file-write rule: a half-written
			// drop-in would leave the server unstartable.
			return util.AtomicWrite(path, []byte(content), 0o644)
		},
		Revert: func() error {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		},
	}}, nil
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}
