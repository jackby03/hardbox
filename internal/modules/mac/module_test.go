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
package mac_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/mac"
)

type fakeResult struct {
	out string
	err bool
}

func fakeRunner(results map[string]fakeResult) func(context.Context, string, ...string) (string, error) {
	return func(_ context.Context, name string, args ...string) (string, error) {
		key := strings.TrimSpace(name + " " + strings.Join(args, " "))
		res, ok := results[key]
		if !ok {
			return "", fmt.Errorf("unexpected command: %s", key)
		}
		if res.err {
			return res.out, fmt.Errorf("failed: %s", key)
		}
		return res.out, nil
	}
}

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = mac.NewModuleForTest(mac.TestOptions{})
}

func TestModule_NameAndVersion(t *testing.T) {
	m := mac.NewModuleForTest(mac.TestOptions{})
	if m.Name() != "mac" {
		t.Fatalf("Name()=%q, want mac", m.Name())
	}
	if m.Version() == "" {
		t.Fatal("Version() should not be empty")
	}
}

func TestAudit_AppArmor_Compliant(t *testing.T) {
	tmp := t.TempDir()
	enabledPath := filepath.Join(tmp, "apparmor-enabled")
	if err := os.WriteFile(enabledPath, []byte("Y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := mac.NewModuleForTest(mac.TestOptions{
		Backend:         "apparmor",
		AppArmorEnabled: enabledPath,
		Runner: fakeRunner(map[string]fakeResult{
			"aa-status": {out: "17 profiles are loaded.\n17 profiles are in enforce mode.\n0 profiles are in complain mode.\n0 processes are unconfined but have a profile defined.\n"},
		}),
	})

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	assertStatus(t, findings, "mac-001", modules.StatusCompliant)
	assertStatus(t, findings, "mac-002", modules.StatusCompliant)
	assertStatus(t, findings, "mac-003", modules.StatusCompliant)
	assertStatus(t, findings, "mac-004", modules.StatusCompliant)
	assertStatus(t, findings, "mac-005", modules.StatusSkipped)
}

func TestAudit_SELinux_Compliant(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "selinux-config")
	if err := os.WriteFile(cfgPath, []byte("SELINUX=enforcing\nSELINUXTYPE=targeted\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := mac.NewModuleForTest(mac.TestOptions{
		Backend:       "selinux",
		SELinuxConfig: cfgPath,
		Runner: fakeRunner(map[string]fakeResult{
			"sestatus": {out: "SELinux status:                 enabled\nCurrent mode:                   enforcing\nLoaded policy name:             targeted\n"},
		}),
	})

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	assertStatus(t, findings, "mac-001", modules.StatusCompliant)
	assertStatus(t, findings, "mac-002", modules.StatusCompliant)
	assertStatus(t, findings, "mac-003", modules.StatusCompliant)
	assertStatus(t, findings, "mac-004", modules.StatusSkipped)
	assertStatus(t, findings, "mac-005", modules.StatusCompliant)
}

func TestAudit_AppArmor_NonCompliantUnconfined(t *testing.T) {
	tmp := t.TempDir()
	enabledPath := filepath.Join(tmp, "apparmor-enabled")
	if err := os.WriteFile(enabledPath, []byte("N\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := mac.NewModuleForTest(mac.TestOptions{
		Backend:         "apparmor",
		AppArmorEnabled: enabledPath,
		Runner: fakeRunner(map[string]fakeResult{
			"aa-status": {out: "12 profiles are loaded.\n0 profiles are in enforce mode.\n4 processes are unconfined.\n"},
		}),
	})

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	assertStatus(t, findings, "mac-002", modules.StatusNonCompliant)
	assertStatus(t, findings, "mac-003", modules.StatusNonCompliant)
	assertStatus(t, findings, "mac-004", modules.StatusNonCompliant)
}

func TestPlan_AuditOnly(t *testing.T) {
	tmp := t.TempDir()
	enabledPath := filepath.Join(tmp, "apparmor-enabled")
	if err := os.WriteFile(enabledPath, []byte("Y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := mac.NewModuleForTest(mac.TestOptions{
		Backend:         "apparmor",
		AppArmorEnabled: enabledPath,
		Runner: fakeRunner(map[string]fakeResult{
			"aa-status": {out: "1 profiles are in enforce mode.\n0 processes are unconfined.\n"},
		}),
	})

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("Plan returned %d changes, want 0", len(changes))
	}
}

func assertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Fatalf("%s: got %s, want %s", id, f.Status, want)
			}
			return
		}
	}
	t.Fatalf("check %s not found", id)
}

