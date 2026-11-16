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

package databases_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/databases"
)

// writeFile creates dir/name with content and returns the path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// noQuery is a query function that always fails, standing in for a host with no
// usable credentials.
func noQuery(context.Context, string) (string, error) {
	return "", errors.New("access denied")
}

// absent returns a path that does not exist, so a module built with it reports the
// corresponding family as not installed. Tests must never rely on the host: the
// GitHub runner ships /etc/mysql, which made a "" argument fall back to the real
// globs and turned skipped checks into findings.
func absent(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent")
}

func find(t *testing.T, findings []modules.Finding, id string) modules.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			return f
		}
	}
	t.Fatalf("finding %s not found", id)
	return modules.Finding{}
}

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = &databases.Module{}
}

// TestAudit_NoDatabaseServer covers a host without any database server: every
// check must be skipped, and the module must not error.
func TestAudit_NoDatabaseServer(t *testing.T) {
	m := databases.NewModuleForTest(
		filepath.Join(t.TempDir(), "none.cnf"),
		filepath.Join(t.TempDir(), "pg_hba.conf"),
		filepath.Join(t.TempDir(), "postgresql.conf"),
		"", noQuery)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 8 {
		t.Fatalf("want one finding per check, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Status != modules.StatusSkipped {
			t.Errorf("%s: want skipped on a host with no database server, got %s", f.Check.ID, f.Status)
		}
	}
}

func TestAudit_MySQL_Compliant(t *testing.T) {
	dir := t.TempDir()
	mycnf := writeFile(t, dir, "my.cnf", `[mysqld]
bind-address = 127.0.0.1
local-infile = 0
`)
	m := databases.NewModuleForTest(mycnf, absent(t), absent(t),
		"",
		func(context.Context, string) (string, error) { return "0", nil })

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, id := range []string{"db-001", "db-002", "db-006", "db-007", "db-008"} {
		if got := find(t, findings, id).Status; got != modules.StatusCompliant {
			t.Errorf("%s: want compliant, got %s", id, got)
		}
	}
}

func TestAudit_MySQL_NonCompliant(t *testing.T) {
	dir := t.TempDir()
	mycnf := writeFile(t, dir, "my.cnf", `[mysqld]
bind-address = 0.0.0.0
`)
	m := databases.NewModuleForTest(mycnf, absent(t), absent(t),
		"",
		func(context.Context, string) (string, error) { return "2", nil })

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	// local_infile absent means the default (on), which is non-compliant.
	for _, id := range []string{"db-001", "db-002", "db-006", "db-007", "db-008"} {
		if got := find(t, findings, id).Status; got != modules.StatusNonCompliant {
			t.Errorf("%s: want non-compliant, got %s", id, got)
		}
	}
}

// TestAudit_MySQLQueryFailureIsManual is the honest degradation path: without
// credentials the account checks report manual with the statement to run, rather
// than claiming compliance.
func TestAudit_MySQLQueryFailureIsManual(t *testing.T) {
	dir := t.TempDir()
	mycnf := writeFile(t, dir, "my.cnf", "[mysqld]\nbind-address = 127.0.0.1\nlocal_infile = 0\n")
	m := databases.NewModuleForTest(mycnf, absent(t), absent(t), "", noQuery)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, id := range []string{"db-006", "db-007", "db-008"} {
		f := find(t, findings, id)
		if f.Status != modules.StatusManual {
			t.Errorf("%s: want manual when the server cannot be queried, got %s", id, f.Status)
		}
		if !strings.Contains(f.Detail, "SELECT") && !strings.Contains(f.Detail, "SHOW") {
			t.Errorf("%s: detail should carry the statement to run, got %q", id, f.Detail)
		}
	}
}

func TestAudit_PostgreSQL(t *testing.T) {
	dir := t.TempDir()
	hba := writeFile(t, dir, "pg_hba.conf", `# TYPE  DATABASE  USER  ADDRESS  METHOD
local   all       postgres               peer
host    all       all     127.0.0.1/32   trust
host    all       all     10.0.0.0/8     scram-sha-256
`)
	conf := writeFile(t, dir, "postgresql.conf", `
password_encryption = 'md5'
listen_addresses = '*'
`)

	m := databases.NewModuleForTest(absent(t), hba, conf, "", noQuery)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}

	trust := find(t, findings, "db-003")
	if trust.Status != modules.StatusNonCompliant {
		t.Errorf("db-003: want non-compliant for a trust rule, got %s", trust.Status)
	}
	if !strings.Contains(trust.Detail, "pg_hba.conf:3") {
		t.Errorf("db-003: detail should name the offending rule, got %q", trust.Detail)
	}
	if got := find(t, findings, "db-004").Status; got != modules.StatusNonCompliant {
		t.Errorf("db-004: want non-compliant for md5, got %s", got)
	}
	if got := find(t, findings, "db-005").Status; got != modules.StatusNonCompliant {
		t.Errorf("db-005: want non-compliant for listen_addresses = '*', got %s", got)
	}
	// MySQL is absent, so its checks must be skipped, not failed.
	for _, id := range []string{"db-001", "db-002", "db-006", "db-007", "db-008"} {
		if got := find(t, findings, id).Status; got != modules.StatusSkipped {
			t.Errorf("%s: want skipped without MySQL, got %s", id, got)
		}
	}
}

func TestAudit_PostgreSQL_Compliant(t *testing.T) {
	dir := t.TempDir()
	hba := writeFile(t, dir, "pg_hba.conf", "local all all peer\nhost all all 127.0.0.1/32 scram-sha-256\n")
	conf := writeFile(t, dir, "postgresql.conf", "password_encryption = 'scram-sha-256'\nlisten_addresses = 'localhost'\n")

	m := databases.NewModuleForTest(absent(t), hba, conf, "", noQuery)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, id := range []string{"db-003", "db-004", "db-005"} {
		if got := find(t, findings, id).Status; got != modules.StatusCompliant {
			t.Errorf("%s: want compliant, got %s", id, got)
		}
	}
}

// TestPlan_WritesMySQLDropIn covers the only automated remediation: a drop-in
// file, declared in Files so rollback can remove it.
func TestPlan_WritesMySQLDropIn(t *testing.T) {
	dir := t.TempDir()
	mycnf := writeFile(t, dir, "my.cnf", "[mysqld]\n")
	dropIn := filepath.Join(dir, "99-hardbox.cnf")

	m := databases.NewModuleForTest(mycnf, absent(t), absent(t), dropIn, noQuery)
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("want exactly one change, got %d", len(changes))
	}
	if len(changes[0].Files) != 1 || changes[0].Files[0] != dropIn {
		t.Errorf("change must declare the drop-in path, got %v", changes[0].Files)
	}

	if err := changes[0].Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	content, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatalf("reading drop-in: %v", err)
	}
	for _, want := range []string{"[mysqld]", "bind-address = 127.0.0.1", "local_infile = 0"} {
		if !strings.Contains(string(content), want) {
			t.Errorf("drop-in missing %q:\n%s", want, content)
		}
	}

	// Rollback removes the file it created.
	if err := changes[0].Revert(); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if _, err := os.Stat(dropIn); !os.IsNotExist(err) {
		t.Errorf("revert should remove the drop-in, stat err = %v", err)
	}
}

func TestPlan_NoChangesWhenCompliant(t *testing.T) {
	dir := t.TempDir()
	mycnf := writeFile(t, dir, "my.cnf", "[mysqld]\nbind-address = 127.0.0.1\nlocal_infile = 0\n")
	m := databases.NewModuleForTest(mycnf, absent(t), absent(t), filepath.Join(dir, "drop.cnf"),
		func(context.Context, string) (string, error) { return "0", nil })

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("want no changes, got %d", len(changes))
	}
}

// TestPlan_PostgresIsAuditOnly pins the documented exception: pg_hba edits would
// be able to lock the operator out, so nothing is automated for PostgreSQL.
func TestPlan_PostgresIsAuditOnly(t *testing.T) {
	dir := t.TempDir()
	hba := writeFile(t, dir, "pg_hba.conf", "host all all 0.0.0.0/0 trust\n")
	conf := writeFile(t, dir, "postgresql.conf", "password_encryption = 'md5'\nlisten_addresses = '*'\n")

	m := databases.NewModuleForTest(absent(t), hba, conf, filepath.Join(dir, "drop.cnf"), noQuery)
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, c := range changes {
		for _, f := range c.Files {
			if f == hba || f == conf {
				t.Fatalf("PostgreSQL config must not be rewritten automatically, got %q", c.Description)
			}
		}
	}
}

// ── parser tests ────────────────────────────────────────────────────────────

func TestParseMySQLOptions(t *testing.T) {
	dir := t.TempDir()
	first := writeFile(t, dir, "a.cnf", "[mysqld]\nbind-address = 0.0.0.0\nlocal-infile = 1\n")
	second := writeFile(t, dir, "b.cnf", "[mysqld]\nbind-address = 127.0.0.1\n[client]\nlocal_infile = 0\n")

	opts := databases.ParseMySQLOptions([]string{first, second})
	if opts["bind_address"] != "127.0.0.1" {
		t.Errorf("later file must win, got %q", opts["bind_address"])
	}
	if opts["local_infile"] != "1" {
		t.Errorf("[client] section must not be read as [mysqld], got %q", opts["local_infile"])
	}
}

func TestHbaTrustRules(t *testing.T) {
	dir := t.TempDir()
	hba := writeFile(t, dir, "pg_hba.conf", `local all all trust
host  all all 10.0.0.0/8 scram-sha-256
host  all all 0.0.0.0/0 trust
`)
	rules := databases.HbaTrustRules([]string{hba})
	if len(rules) != 2 {
		t.Fatalf("want 2 trust rules (local uses index 3, host index 4), got %d: %v", len(rules), rules)
	}
}

func TestParsePGConf(t *testing.T) {
	dir := t.TempDir()
	conf := writeFile(t, dir, "postgresql.conf", `# comment
listen_addresses = 'localhost'
password_encryption = "scram-sha-256"
`)
	opts := databases.ParsePGConf([]string{conf})
	if opts["listen_addresses"] != "localhost" {
		t.Errorf("listen_addresses = %q", opts["listen_addresses"])
	}
	if opts["password_encryption"] != "scram-sha-256" {
		t.Errorf("quotes not stripped: %q", opts["password_encryption"])
	}
}

// TestExpandGlobs covers the resolution that decides whether a family is
// considered installed. Explicit paths are used by every test above precisely to
// avoid the fallback branch, so it needs its own coverage.
func TestExpandGlobs(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.cnf", "")
	writeFile(t, dir, "b.cnf", "")

	got := databases.ExpandGlobs(filepath.Join(dir, "*.cnf"), "")
	if len(got) != 2 {
		t.Fatalf("want 2 matches, got %v", got)
	}

	if got := databases.ExpandGlobs(a, ""); len(got) != 1 || got[0] != a {
		t.Errorf("literal existing path must resolve: %v", got)
	}
	if got := databases.ExpandGlobs(filepath.Join(dir, "nope.cnf"), ""); len(got) != 0 {
		t.Errorf("missing literal path must resolve to nothing: %v", got)
	}
	if got := databases.ExpandGlobs("", filepath.Join(dir, "*.cnf")); len(got) != 2 {
		t.Errorf("empty input must fall back to the default globs: %v", got)
	}
}
