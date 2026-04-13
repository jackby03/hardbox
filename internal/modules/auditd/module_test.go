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
package auditd_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/auditd"
)

// ── helpers ───────────────────────────────────────────────────────────────────

type fakeResult struct {
	out string
	err bool
}

func fakeRunner(m map[string]fakeResult) func(ctx context.Context, name string, args ...string) (string, error) {
	return func(ctx context.Context, name string, args ...string) (string, error) {
		key := name + " " + strings.Join(args, " ")
		if r, ok := m[key]; ok {
			var err error
			if r.err {
				err = context.DeadlineExceeded // any non-nil error
			}
			return r.out, err
		}
		return "", context.DeadlineExceeded
	}
}

func serviceEnabled() map[string]fakeResult {
	return map[string]fakeResult{
		"systemctl is-enabled auditd.service": {out: "enabled"},
		"systemctl is-active auditd.service":  {out: "active"},
	}
}

func serviceDisabled() map[string]fakeResult {
	return map[string]fakeResult{
		"systemctl is-enabled auditd.service": {out: "disabled", err: true},
		"systemctl is-active auditd.service":  {out: "inactive", err: true},
	}
}

func assertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Errorf("check %s: got status %q, want %q (current=%q)", id, f.Status, want, f.Current)
			}
			return
		}
	}
	t.Errorf("check %s: not found in findings", id)
}

func testdataPath(elem ...string) string {
	return filepath.Join(append([]string{"testdata"}, elem...)...)
}

// ── interface ─────────────────────────────────────────────────────────────────

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = auditd.NewModuleForTest(nil, "", "")
}

func TestModule_NameAndVersion(t *testing.T) {
	m := auditd.NewModuleForTest(nil, "", "")
	if m.Name() != "auditd" {
		t.Fatalf("Name(): got %q, want auditd", m.Name())
	}
	if m.Version() == "" {
		t.Fatal("Version() should not be empty")
	}
}

// ── audit: all compliant ──────────────────────────────────────────────────────

func TestAudit_AllCompliant(t *testing.T) {
	m := auditd.NewModuleForTest(
		fakeRunner(serviceEnabled()),
		testdataPath("rules_hardened"),
		testdataPath("auditd_conf_hardened"),
	)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	if len(findings) != 13 {
		t.Fatalf("expected 13 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Status != modules.StatusCompliant {
			t.Errorf("check %s: expected compliant, got %s (current=%q)", f.Check.ID, f.Status, f.Current)
		}
	}
}

// ── audit: non-compliant rules dir ───────────────────────────────────────────

func TestAudit_DefaultRules_RuleChecksNonCompliant(t *testing.T) {
	m := auditd.NewModuleForTest(
		fakeRunner(serviceEnabled()),
		testdataPath("rules_default"),
		testdataPath("auditd_conf_hardened"),
	)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}

	ruleIDs := []string{"aud-001", "aud-002", "aud-003", "aud-004", "aud-005", "aud-006", "aud-007", "aud-008", "aud-009"}
	for _, id := range ruleIDs {
		assertStatus(t, findings, id, modules.StatusNonCompliant)
	}
	// conf checks still pass
	assertStatus(t, findings, "aud-010", modules.StatusCompliant)
	assertStatus(t, findings, "aud-011", modules.StatusCompliant)
	assertStatus(t, findings, "aud-012", modules.StatusCompliant)
	assertStatus(t, findings, "aud-013", modules.StatusCompliant)
}

// ── audit: non-compliant conf ─────────────────────────────────────────────────

func TestAudit_DefaultConf_ConfChecksNonCompliant(t *testing.T) {
	m := auditd.NewModuleForTest(
		fakeRunner(serviceEnabled()),
		testdataPath("rules_hardened"),
		testdataPath("auditd_conf_default"),
	)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}

	// Default conf: max_log_file=5 (< 8), action=ROTATE (ok), space_left=SYSLOG (ok)
	assertStatus(t, findings, "aud-010", modules.StatusNonCompliant)
	assertStatus(t, findings, "aud-011", modules.StatusCompliant) // ROTATE is acceptable
	assertStatus(t, findings, "aud-012", modules.StatusCompliant) // SYSLOG is acceptable
}

// ── audit: service disabled ───────────────────────────────────────────────────

func TestAudit_ServiceDisabled_AUD013NonCompliant(t *testing.T) {
	m := auditd.NewModuleForTest(
		fakeRunner(serviceDisabled()),
		testdataPath("rules_hardened"),
		testdataPath("auditd_conf_hardened"),
	)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	assertStatus(t, findings, "aud-013", modules.StatusNonCompliant)
}

// ── audit: missing rules dir ──────────────────────────────────────────────────

func TestAudit_MissingRulesDir_AllRuleChecksNonCompliant(t *testing.T) {
	m := auditd.NewModuleForTest(
		fakeRunner(serviceEnabled()),
		testdataPath("rules_nonexistent"),
		testdataPath("auditd_conf_hardened"),
	)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	for _, id := range []string{"aud-001", "aud-009"} {
		assertStatus(t, findings, id, modules.StatusNonCompliant)
	}
}

// ── plan: writes rules when non-compliant ─────────────────────────────────────

func TestPlan_WritesRulesFile(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules.d")
	confPath := testdataPath("auditd_conf_hardened")

	m := auditd.NewModuleForTest(
		fakeRunner(serviceEnabled()),
		rulesDir,
		confPath,
	)

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}

	if err := changes[0].Apply(); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}

	written, err := os.ReadFile(filepath.Join(rulesDir, "99-hardbox.rules"))
	if err != nil {
		t.Fatalf("rules file not written: %v", err)
	}
	if !strings.Contains(string(written), "-e 2") {
		t.Error("written rules missing immutability flag (-e 2)")
	}
	if !strings.Contains(string(written), "-k exec") {
		t.Error("written rules missing exec audit key")
	}
}

// ── plan: nothing to do when already hardened ────────────────────────────────

func TestPlan_AlreadyCompliant_NoChanges(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules.d")
	if err := os.MkdirAll(rulesDir, 0o750); err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(rulesDir, "99-hardbox.rules")
	if err := os.WriteFile(rulesPath, []byte(auditd.HardboxRulesContent()), 0o640); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	m := auditd.NewModuleForTest(
		fakeRunner(serviceEnabled()),
		rulesDir,
		testdataPath("auditd_conf_hardened"),
	)

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes when already compliant, got %d", len(changes))
	}
}

// ── plan: apply/revert round trip ─────────────────────────────────────────────

func TestPlan_ApplyRevert(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules.d")
	rulesPath := filepath.Join(rulesDir, "99-hardbox.rules")

	m := auditd.NewModuleForTest(
		fakeRunner(serviceEnabled()),
		rulesDir,
		testdataPath("auditd_conf_hardened"),
	)

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}

	// Apply
	if err := changes[0].Apply(); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if _, err := os.Stat(rulesPath); err != nil {
		t.Fatalf("rules file missing after Apply(): %v", err)
	}

	// Revert (file didn't exist before, so it should be removed)
	if err := changes[0].Revert(); err != nil {
		t.Fatalf("Revert() error: %v", err)
	}
	if _, err := os.Stat(rulesPath); !os.IsNotExist(err) {
		t.Error("expected rules file to be removed after Revert()")
	}
}

