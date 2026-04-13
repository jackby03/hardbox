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
package updates_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/updates"
)

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = updates.NewModuleForTest(updates.TestOptions{})
}

func TestModule_NameAndVersion(t *testing.T) {
	m := updates.NewModuleForTest(updates.TestOptions{})
	if m.Name() != "updates" {
		t.Fatalf("Name() = %q, want %q", m.Name(), "updates")
	}
	if m.Version() == "" {
		t.Fatal("Version() should not be empty")
	}
}

func TestAudit_Debian_Compliant(t *testing.T) {
	tmp := t.TempDir()
	paths := buildDebianFixture(t, tmp, true)

	m := updates.NewModuleForTest(paths)
	findings, err := m.Audit(context.Background(), modules.ModuleConfig{"auto_reboot_after_kernel": true})
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}

	assertStatus(t, findings, "upd-001", modules.StatusCompliant)
	assertStatus(t, findings, "upd-002", modules.StatusCompliant)
	assertStatus(t, findings, "upd-003", modules.StatusCompliant)
	assertStatus(t, findings, "upd-004", modules.StatusCompliant)
	assertStatus(t, findings, "upd-005", modules.StatusCompliant)
}

func TestAudit_RHEL_Compliant(t *testing.T) {
	tmp := t.TempDir()
	dnfPath := filepath.Join(tmp, "automatic.conf")
	gpgDir := filepath.Join(tmp, "rpm-gpg")
	if err := os.MkdirAll(gpgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gpgDir, "RPM-GPG-KEY-test"), []byte("key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dnfPath, []byte("[commands]\nupgrade_type = security\napply_updates = yes\nreboot = when-needed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := updates.NewModuleForTest(updates.TestOptions{
		Family:             "rhel",
		DNFAutomaticConfig: dnfPath,
	})
	findings, err := m.Audit(context.Background(), modules.ModuleConfig{"auto_reboot_after_kernel": true})
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}

	assertStatus(t, findings, "upd-002", modules.StatusCompliant)
	assertStatus(t, findings, "upd-003", modules.StatusCompliant)
	assertStatus(t, findings, "upd-004", modules.StatusCompliant)
}

func TestAudit_Debian_MissingGPG_NonCompliant(t *testing.T) {
	tmp := t.TempDir()
	paths := buildDebianFixture(t, tmp, false)

	m := updates.NewModuleForTest(paths)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}

	assertStatus(t, findings, "upd-001", modules.StatusNonCompliant)
}

func TestPlan_AuditOnly(t *testing.T) {
	tmp := t.TempDir()
	paths := buildDebianFixture(t, tmp, true)

	m := updates.NewModuleForTest(paths)
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan(): %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("Plan(): got %d changes, want 0", len(changes))
	}
}

func buildDebianFixture(t *testing.T, root string, withKey bool) updates.TestOptions {
	t.Helper()
	sourcesDir := filepath.Join(root, "sources.list.d")
	aptConfDir := filepath.Join(root, "apt.conf.d")
	trustedDir := filepath.Join(root, "trusted.gpg.d")
	keyringsDir := filepath.Join(root, "keyrings")

	for _, d := range []string{sourcesDir, aptConfDir, trustedDir, keyringsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	sourcesPath := filepath.Join(root, "sources.list")
	sourcesExtra := filepath.Join(sourcesDir, "security.list")
	autoUpgrades := filepath.Join(aptConfDir, "20auto-upgrades")
	unattended := filepath.Join(aptConfDir, "50unattended-upgrades")
	trustedGPG := filepath.Join(root, "trusted.gpg")

	if err := os.WriteFile(sourcesPath, []byte("deb http://archive.ubuntu.com/ubuntu jammy main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcesExtra, []byte("deb http://mirror.internal/ubuntu jammy-security main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(autoUpgrades, []byte("APT::Periodic::Unattended-Upgrade \"1\";\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unattended, []byte("Unattended-Upgrade::Automatic-Reboot \"true\";\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if withKey {
		if err := os.WriteFile(trustedGPG, []byte("key"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return updates.TestOptions{
		Family:            "debian",
		APTSourcesList:    sourcesPath,
		APTSourcesListDir: sourcesDir,
		APTAutoUpgrades:   autoUpgrades,
		APTUnattended:     unattended,
		APTTrustedGPG:     trustedGPG,
		APTTrustedGPGDir:  trustedDir,
		USRShareKeyrings:  keyringsDir,
	}
}

func assertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Fatalf("check %s status = %s, want %s", id, f.Status, want)
			}
			return
		}
	}
	t.Fatalf("check %s not found", id)
}

