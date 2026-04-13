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
package users_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/users"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func tdPath(elem ...string) string {
	return filepath.Join(append([]string{"testdata"}, elem...)...)
}

func noSudoersDir() string { return tdPath("nonexistent_sudoers_d") }

func assertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Errorf("check %s: got %q, want %q (current=%q)", id, f.Status, want, f.Current)
			}
			return
		}
	}
	t.Errorf("check %s: not found in findings", id)
}

func newHardenedModule() *users.Module {
	return users.NewModuleForTest(
		nil,
		tdPath("login_defs_hardened"),
		tdPath("pam_hardened"),
		tdPath("passwd_clean"),
		tdPath("sudoers_compliant"),
		noSudoersDir(),
		tdPath("default_useradd_hardened"),
	)
}

// ── interface ─────────────────────────────────────────────────────────────────

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = users.NewModuleForTest(nil, "", "", "", "", "", "")
}

func TestModule_NameAndVersion(t *testing.T) {
	m := users.NewModuleForTest(nil, "", "", "", "", "", "")
	if m.Name() != "users" {
		t.Fatalf("Name(): got %q, want users", m.Name())
	}
	if m.Version() == "" {
		t.Fatal("Version() must not be empty")
	}
}

// ── unit: pure helpers ────────────────────────────────────────────────────────

func TestSetLoginDefsKey_Replace(t *testing.T) {
	content := "PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\n"
	got := users.SetLoginDefsKey(content, "PASS_MAX_DAYS", "90")
	if !strings.Contains(got, "PASS_MAX_DAYS\t90") {
		t.Errorf("expected PASS_MAX_DAYS\\t90; got:\n%s", got)
	}
	if strings.Contains(got, "99999") {
		t.Error("old value should be gone")
	}
}

func TestSetLoginDefsKey_Append(t *testing.T) {
	content := "PASS_MIN_DAYS\t0\n"
	got := users.SetLoginDefsKey(content, "PASS_MIN_LEN", "14")
	if !strings.Contains(got, "PASS_MIN_LEN\t14") {
		t.Errorf("expected appended key; got:\n%s", got)
	}
}

func TestSetSimpleKey_Replace(t *testing.T) {
	content := "INACTIVE=-1\nEXPIRE=\n"
	got := users.SetSimpleKey(content, "INACTIVE", "30")
	if !strings.Contains(got, "INACTIVE=30") {
		t.Errorf("expected INACTIVE=30; got:\n%s", got)
	}
	if strings.Contains(got, "INACTIVE=-1") {
		t.Error("old value should be gone")
	}
}

// ── audit: all compliant ──────────────────────────────────────────────────────

func TestAudit_AllCompliant(t *testing.T) {
	m := newHardenedModule()
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	if len(findings) != 17 {
		t.Fatalf("expected 17 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Status == modules.StatusNonCompliant {
			t.Errorf("check %s: unexpected non-compliant (current=%q)", f.Check.ID, f.Current)
		}
	}
}

// ── audit: default login.defs ─────────────────────────────────────────────────

func TestAudit_DefaultLoginDefs_NonCompliant(t *testing.T) {
	m := users.NewModuleForTest(
		nil,
		tdPath("login_defs_default"),
		tdPath("pam_hardened"),
		tdPath("passwd_clean"),
		tdPath("sudoers_compliant"),
		noSudoersDir(),
		tdPath("default_useradd_hardened"),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "usr-001", modules.StatusNonCompliant) // 99999 > 90
	assertStatus(t, findings, "usr-002", modules.StatusNonCompliant) // 0 < 1
	assertStatus(t, findings, "usr-004", modules.StatusNonCompliant) // not set
	assertStatus(t, findings, "usr-015", modules.StatusNonCompliant) // 022 not ≥ 027 bits
}

// ── audit: dirty passwd ───────────────────────────────────────────────────────

func TestAudit_DirtyPasswd_NonCompliant(t *testing.T) {
	m := users.NewModuleForTest(
		nil,
		tdPath("login_defs_hardened"),
		tdPath("pam_hardened"),
		tdPath("passwd_dirty"),
		tdPath("sudoers_compliant"),
		noSudoersDir(),
		tdPath("default_useradd_hardened"),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "usr-010", modules.StatusNonCompliant) // toor has UID 0
	assertStatus(t, findings, "usr-011", modules.StatusNonCompliant) // daemon has /bin/bash
}

// ── audit: nopasswd sudoers ───────────────────────────────────────────────────

func TestAudit_NopasswdSudoers_NonCompliant(t *testing.T) {
	m := users.NewModuleForTest(
		nil,
		tdPath("login_defs_hardened"),
		tdPath("pam_hardened"),
		tdPath("passwd_clean"),
		tdPath("sudoers_nopasswd"),
		noSudoersDir(),
		tdPath("default_useradd_hardened"),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "usr-013", modules.StatusNonCompliant)
}

// ── audit: default PAM ────────────────────────────────────────────────────────

func TestAudit_DefaultPAM_NonCompliant(t *testing.T) {
	m := users.NewModuleForTest(
		nil,
		tdPath("login_defs_hardened"),
		tdPath("pam_default"),
		tdPath("passwd_clean"),
		tdPath("sudoers_compliant"),
		noSudoersDir(),
		tdPath("default_useradd_hardened"),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "usr-005", modules.StatusNonCompliant) // no pwquality
	assertStatus(t, findings, "usr-006", modules.StatusNonCompliant) // no history
	assertStatus(t, findings, "usr-007", modules.StatusNonCompliant) // no faillock
	assertStatus(t, findings, "usr-008", modules.StatusNonCompliant) // no unlock_time
	assertStatus(t, findings, "usr-009", modules.StatusNonCompliant) // no even_deny_root
}

// ── audit: default useradd ────────────────────────────────────────────────────

func TestAudit_DefaultUseradd_NonCompliant(t *testing.T) {
	m := users.NewModuleForTest(
		nil,
		tdPath("login_defs_hardened"),
		tdPath("pam_hardened"),
		tdPath("passwd_clean"),
		tdPath("sudoers_compliant"),
		noSudoersDir(),
		tdPath("default_useradd_default"),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "usr-017", modules.StatusNonCompliant) // INACTIVE=-1
}

// ── plan: fixes login.defs ────────────────────────────────────────────────────

func TestPlan_FixesLoginDefs(t *testing.T) {
	dir := t.TempDir()
	loginDefsPath := filepath.Join(dir, "login.defs")
	if err := os.WriteFile(loginDefsPath, []byte("PASS_MAX_DAYS\t99999\nUMASK\t022\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := users.NewModuleForTest(
		nil,
		loginDefsPath,
		tdPath("pam_hardened"),
		tdPath("passwd_clean"),
		tdPath("sudoers_compliant"),
		noSudoersDir(),
		tdPath("default_useradd_hardened"),
	)

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan(): %v", err)
	}
	if len(changes) == 0 {
		t.Fatal("expected at least one change")
	}

	for _, ch := range changes {
		if err := ch.Apply(); err != nil {
			t.Fatalf("Apply(): %v", err)
		}
	}

	data, _ := os.ReadFile(loginDefsPath)
	content := string(data)
	if !strings.Contains(content, "PASS_MAX_DAYS\t90") {
		t.Errorf("expected PASS_MAX_DAYS=90 after apply; got:\n%s", content)
	}
}

// ── plan: revert ──────────────────────────────────────────────────────────────

func TestPlan_Revert(t *testing.T) {
	dir := t.TempDir()
	loginDefsPath := filepath.Join(dir, "login.defs")
	original := "PASS_MAX_DAYS\t99999\nUMASK\t022\n"
	if err := os.WriteFile(loginDefsPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	m := users.NewModuleForTest(
		nil,
		loginDefsPath,
		tdPath("pam_hardened"),
		tdPath("passwd_clean"),
		tdPath("sudoers_compliant"),
		noSudoersDir(),
		tdPath("default_useradd_hardened"),
	)

	changes, _ := m.Plan(context.Background(), nil)
	for _, ch := range changes {
		_ = ch.Apply()
	}
	for _, ch := range changes {
		if err := ch.Revert(); err != nil {
			t.Fatalf("Revert(): %v", err)
		}
	}

	data, _ := os.ReadFile(loginDefsPath)
	if string(data) != original {
		t.Errorf("after revert got:\n%q\nwant:\n%q", string(data), original)
	}
}

// ── plan: already compliant ───────────────────────────────────────────────────

func TestPlan_AlreadyCompliant_NoChanges(t *testing.T) {
	m := newHardenedModule()
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan(): %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes when already compliant, got %d", len(changes))
	}
}

