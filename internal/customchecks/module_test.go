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

package customchecks_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/customchecks"
	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
)

const validFile = `version: "1"
checks:
  - id: corp-001
    title: Corporate banner is set
    description: /etc/issue.net must carry the approved banner
    severity: medium
    compliance:
      - framework: NIST
        control: AC-8
    assert:
      file:
        path: /etc/issue.net
        contains: "Authorized use only"
        mode: "0644"
    remediate:
      write:
        path: /etc/issue.net
        content: "Authorized use only\n"
        mode: "0644"
`

func writeYAML(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return dir
}

func TestLoad_Valid(t *testing.T) {
	dir := writeYAML(t, "corp.yaml", validFile)

	checks, err := customchecks.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(checks) != 1 {
		t.Fatalf("want 1 check, got %d", len(checks))
	}
	if checks[0].ID != "corp-001" {
		t.Errorf("id = %q", checks[0].ID)
	}
}

// TestLoad_MissingDir is the default case: no custom checks configured.
func TestLoad_MissingDir(t *testing.T) {
	checks, err := customchecks.Load(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("a missing directory must not be an error: %v", err)
	}
	if len(checks) != 0 {
		t.Errorf("want no checks, got %d", len(checks))
	}

	if checks, err := customchecks.Load(""); err != nil || checks != nil {
		t.Errorf("empty dir must be a no-op, got %v %v", checks, err)
	}
}

func TestLoad_Rejections(t *testing.T) {
	cases := map[string]string{
		"bad version": `version: "2"
checks:
  - id: corp-001
    title: x
    severity: low
    assert:
      sysctl: {key: kernel.pid_max, equals: "1"}
    audit_only: true
`,
		"no checks": `version: "1"
checks: []
`,
		"builtin prefix": `version: "1"
checks:
  - id: ssh-001
    title: x
    severity: low
    audit_only: true
    assert:
      file: {path: /etc/x, exists: true}
`,
		"bad severity": `version: "1"
checks:
  - id: corp-001
    title: x
    severity: urgent
    audit_only: true
    assert:
      file: {path: /etc/x, exists: true}
`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := writeYAML(t, "x.yaml", content)
			if _, err := customchecks.Load(dir); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestLoad_RejectsDuplicateIDsAcrossFiles matters because the report keys findings
// by check id; two files defining the same id would silently shadow one another.
func TestLoad_RejectsDuplicateIDsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(validFile), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := customchecks.Load(dir); err == nil {
		t.Fatal("expected a duplicate id error")
	}
}

// TestValidate_Rules pins the safety rules that keep a check file from becoming
// arbitrary execution or an unsafe write.
func TestValidate_Rules(t *testing.T) {
	base := func(mut func(*customchecks.Check)) *customchecks.Check {
		yes := true
		c := &customchecks.Check{
			ID:       "corp-001",
			Title:    "t",
			Severity: "low",
			Assert: customchecks.Assertion{
				File: &customchecks.FileAssertion{Path: "/etc/x", Exists: &yes},
			},
		}
		if mut != nil {
			mut(c)
		}
		return c
	}

	if err := customchecks.Validate(base(nil)); err == nil {
		t.Error("remediable check without remediate must be rejected")
	}
	if err := customchecks.Validate(base(func(c *customchecks.Check) {
		c.AuditOnly = true
	})); err != nil {
		t.Errorf("audit_only check should be valid: %v", err)
	}

	// A sysctl check cannot be remediated in this version.
	sysctl := base(func(c *customchecks.Check) {
		c.Assert = customchecks.Assertion{Sysctl: &customchecks.SysctlAssertion{Key: "kernel.pid_max", Equals: "4194304"}}
		c.Remediate = &customchecks.Remediation{Write: &customchecks.WriteRemediation{Path: "/etc/x", Content: "x"}}
	})
	if err := customchecks.Validate(sysctl); err == nil {
		t.Error("sysctl remediation must be rejected in v1")
	}

	// Path must be absolute and must match the assertion.
	rel := base(func(c *customchecks.Check) {
		c.Remediate = &customchecks.Remediation{Write: &customchecks.WriteRemediation{Path: "etc/x", Content: "x"}}
	})
	if err := customchecks.Validate(rel); err == nil {
		t.Error("relative remediate path must be rejected")
	}
	mismatch := base(func(c *customchecks.Check) {
		c.Remediate = &customchecks.Remediation{Write: &customchecks.WriteRemediation{Path: "/etc/y", Content: "x"}}
	})
	if err := customchecks.Validate(mismatch); err == nil {
		t.Error("remediate path that differs from assert path must be rejected")
	}

	both := base(func(c *customchecks.Check) {
		c.Assert.Sysctl = &customchecks.SysctlAssertion{Key: "kernel.pid_max", Equals: "1"}
		c.AuditOnly = true
	})
	if err := customchecks.Validate(both); err == nil {
		t.Error("setting both file and sysctl must be rejected")
	}
}

func TestParseMode(t *testing.T) {
	if m, err := customchecks.ParseMode("0644"); err != nil || m.Perm() != 0o644 {
		t.Errorf("ParseMode(0644) = %o, %v", m, err)
	}
	if m, err := customchecks.ParseMode(""); err != nil || m != 0 {
		t.Errorf("empty mode should be zero, got %o %v", m, err)
	}
	if _, err := customchecks.ParseMode("rw-r--r--"); err == nil {
		t.Error("non-octal mode must be rejected")
	}
}

// ── audit ───────────────────────────────────────────────────────────────────

func sysctlDir(t *testing.T, key, value string) string {
	t.Helper()
	dir := t.TempDir()
	parts := strings.Split(key, ".")
	path := filepath.Join(append([]string{dir}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAudit_FileAssertions(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "issue.net"), []byte("Authorized use only\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	yes := true
	checks := []customchecks.Check{{
		ID: "corp-001", Title: "banner", Severity: "medium",
		AuditOnly: true,
		Assert: customchecks.Assertion{File: &customchecks.FileAssertion{
			Path: "/issue.net", Contains: "Authorized use only",
		}},
	}, {
		ID: "corp-002", Title: "absent file", Severity: "low",
		AuditOnly: true,
		Assert: customchecks.Assertion{File: &customchecks.FileAssertion{
			Path: "/nope", Exists: boolPtr(false),
		}},
	}, {
		ID: "corp-003", Title: "missing file", Severity: "low",
		AuditOnly: true,
		Assert: customchecks.Assertion{File: &customchecks.FileAssertion{
			Path: "/absent", Exists: &yes,
		}},
	}, {
		ID: "corp-004", Title: "forbidden string", Severity: "low",
		AuditOnly: true,
		Assert: customchecks.Assertion{File: &customchecks.FileAssertion{
			Path: "/issue.net", NotContains: "Ubuntu",
		}},
	}, {
		ID: "corp-005", Title: "exact content", Severity: "low",
		AuditOnly: true,
		Assert: customchecks.Assertion{File: &customchecks.FileAssertion{
			Path: "/issue.net", Equals: "Authorized use only\n",
		}},
	}}

	m := customchecks.NewModuleForTest(checks, root, "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 5 {
		t.Fatalf("want 5 findings, got %d", len(findings))
	}
	// corp-001, corp-002, corp-004 and corp-005 should pass; corp-003 requires a
	// file that does not exist.
	for _, i := range []int{0, 1, 3, 4} {
		if findings[i].Status != modules.StatusCompliant {
			t.Errorf("%s: want compliant, got %s (%s)", findings[i].Check.ID, findings[i].Status, findings[i].Current)
		}
	}
	if got := findings[2].Status; got != modules.StatusNonCompliant {
		t.Errorf("corp-003: a missing required file must be non-compliant, got %s", got)
	}
}

// TestAudit_ModeAssertion covers the mode expectation, which only means something
// where POSIX mode bits are enforced.
func TestAudit_ModeAssertion(t *testing.T) {
	testutil.RequireUnixPerms(t)

	root := t.TempDir()
	path := filepath.Join(root, "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := []customchecks.Check{{
		ID: "corp-040", Title: "mode", Severity: "low", AuditOnly: true,
		Assert: customchecks.Assertion{File: &customchecks.FileAssertion{Path: "/f", Mode: "0644"}},
	}}
	findings, err := customchecks.NewModuleForTest(checks, root, "").Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if findings[0].Status != modules.StatusNonCompliant {
		t.Errorf("0600 must not satisfy a 0644 assertion, got %s", findings[0].Status)
	}
}

func TestAudit_Sysctl(t *testing.T) {
	dir := sysctlDir(t, "kernel.pid_max", "4194304")
	checks := []customchecks.Check{{
		ID: "corp-010", Title: "pid_max", Severity: "low", AuditOnly: true,
		Assert: customchecks.Assertion{Sysctl: &customchecks.SysctlAssertion{Key: "kernel.pid_max", Equals: "4194304"}},
	}, {
		ID: "corp-011", Title: "pid_max wrong", Severity: "low", AuditOnly: true,
		Assert: customchecks.Assertion{Sysctl: &customchecks.SysctlAssertion{Key: "kernel.pid_max", Equals: "1"}},
	}, {
		ID: "corp-012", Title: "missing key", Severity: "low", AuditOnly: true,
		Assert: customchecks.Assertion{Sysctl: &customchecks.SysctlAssertion{Key: "kernel.nope", Equals: "1"}},
	}}

	m := customchecks.NewModuleForTest(checks, t.TempDir(), dir)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if findings[0].Status != modules.StatusCompliant {
		t.Errorf("corp-010: want compliant, got %s", findings[0].Status)
	}
	if findings[1].Status != modules.StatusNonCompliant {
		t.Errorf("corp-011: want non-compliant, got %s", findings[1].Status)
	}
	if findings[2].Status != modules.StatusNonCompliant {
		t.Errorf("corp-012: a missing sysctl must be non-compliant, got %s", findings[2].Status)
	}
}

// TestAudit_OwnerIsManualOffUnix keeps the check honest instead of wrong where
// ownership is not readable.
func TestAudit_OwnerIsManualOffUnix(t *testing.T) {
	if testutil.UnixPermsSupported() {
		t.Skip("this test covers the non-Unix degradation")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	checks := []customchecks.Check{{
		ID: "corp-020", Title: "owner", Severity: "low", AuditOnly: true,
		Assert: customchecks.Assertion{File: &customchecks.FileAssertion{Path: "/f", Owner: "root"}},
	}}
	findings, err := customchecks.NewModuleForTest(checks, root, "").Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if findings[0].Status != modules.StatusManual {
		t.Errorf("want manual where ownership is unreadable, got %s", findings[0].Status)
	}
}

// ── plan ────────────────────────────────────────────────────────────────────

func TestPlan_WritesFileAndDeclaresIt(t *testing.T) {
	dir := t.TempDir()
	// Apply refuses to create missing parent directories: a wrong path in a check
	// file must fail loudly rather than scatter directories across the host.
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	yes := true
	checks, err := parseYAML(t, validFile)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	_ = yes

	m := customchecks.NewModuleForTest(checks, dir, "")
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("want 1 change, got %d", len(changes))
	}
	// Files must point at the resolved path so the snapshot backs up the real file.
	want := filepath.Join(dir, "etc/issue.net")
	if len(changes[0].Files) != 1 || changes[0].Files[0] != want {
		t.Fatalf("change must declare %q, got %v", want, changes[0].Files)
	}
	if err := changes[0].Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	content, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}
	if string(content) != "Authorized use only\n" {
		t.Errorf("content = %q", content)
	}

	// The check must now pass. The mode part of the assertion needs POSIX bits:
	// on Windows the file reads back as 0666 no matter what was written.
	if testutil.UnixPermsSupported() {
		findings, err := m.Audit(context.Background(), nil)
		if err != nil {
			t.Fatalf("Audit: %v", err)
		}
		if findings[0].Status != modules.StatusCompliant {
			t.Errorf("after apply the check should pass, got %s (%s)", findings[0].Status, findings[0].Current)
		}
	}
}

// TestPlan_AuditOnlyProducesNothing guards the documented exception behaviour.
func TestPlan_AuditOnlyProducesNothing(t *testing.T) {
	root := t.TempDir()
	yes := true
	checks := []customchecks.Check{{
		ID: "corp-030", Title: "manual", Severity: "low", AuditOnly: true,
		Assert: customchecks.Assertion{File: &customchecks.FileAssertion{Path: "/missing", Exists: &yes}},
	}}
	changes, err := customchecks.NewModuleForTest(checks, root, "").Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("audit-only check must not produce a change, got %d", len(changes))
	}
}

func boolPtr(b bool) *bool { return &b }

// parseYAML writes the document to a temp dir and loads it, exercising the real
// parse path rather than hand-built structs.
func parseYAML(t *testing.T, content string) ([]customchecks.Check, error) {
	t.Helper()
	dir := writeYAML(t, "checks.yaml", content)
	return customchecks.Load(dir)
}
