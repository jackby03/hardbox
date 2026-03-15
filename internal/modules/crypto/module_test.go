package crypto_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/crypto"
)

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = crypto.NewModuleForTest(nil, "", "", "", "", "", "")
}

func TestModule_NameAndVersion(t *testing.T) {
	m := crypto.NewModuleForTest(nil, "", "", "", "", "", "")
	if m.Name() != "crypto" {
		t.Fatalf("Name() = %q", m.Name())
	}
	if m.Version() == "" {
		t.Fatal("Version() should not be empty")
	}
}

func TestAudit_RHEL_Compliant(t *testing.T) {
	m := crypto.NewModuleForTest(
		crypto.FakeDistroRHEL,
		td("rhel_crypto_default"),
		td("openssl_weak.cnf"),
		td("fips_enabled_1"),
		td("gpg_long.conf"),
		"",
		"",
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cry-001", modules.StatusCompliant)
	assertStatus(t, findings, "cry-002", modules.StatusCompliant)
	assertStatus(t, findings, "cry-003", modules.StatusCompliant)
	assertStatus(t, findings, "cry-004", modules.StatusCompliant)
	assertStatus(t, findings, "cry-005", modules.StatusCompliant)
	assertStatus(t, findings, "cry-006", modules.StatusCompliant)
}

func TestAudit_RHEL_Legacy(t *testing.T) {
	m := crypto.NewModuleForTest(
		crypto.FakeDistroRHEL,
		td("rhel_crypto_legacy"),
		td("openssl_hardened.cnf"),
		td("fips_enabled_0"),
		td("gpg_short.conf"),
		"",
		"",
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cry-001", modules.StatusNonCompliant)
	assertStatus(t, findings, "cry-002", modules.StatusNonCompliant)
	assertStatus(t, findings, "cry-003", modules.StatusNonCompliant)
	assertStatus(t, findings, "cry-004", modules.StatusNonCompliant)
	assertStatus(t, findings, "cry-005", modules.StatusManual)
	assertStatus(t, findings, "cry-006", modules.StatusNonCompliant)
}

func TestAudit_Debian_Hardened(t *testing.T) {
	m := crypto.NewModuleForTest(
		crypto.FakeDistroDebian,
		"",
		td("openssl_hardened.cnf"),
		td("fips_enabled_0"),
		td("gpg_long.conf"),
		"",
		"",
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cry-001", modules.StatusCompliant)
	assertStatus(t, findings, "cry-002", modules.StatusCompliant)
	assertStatus(t, findings, "cry-003", modules.StatusCompliant)
	assertStatus(t, findings, "cry-004", modules.StatusCompliant)
	assertStatus(t, findings, "cry-005", modules.StatusManual)
	assertStatus(t, findings, "cry-006", modules.StatusCompliant)
}

func TestAudit_Debian_Weak(t *testing.T) {
	m := crypto.NewModuleForTest(
		crypto.FakeDistroDebian,
		"",
		td("openssl_weak.cnf"),
		td("fips_enabled_0"),
		td("gpg_short.conf"),
		"",
		"",
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cry-001", modules.StatusNonCompliant)
	assertStatus(t, findings, "cry-002", modules.StatusNonCompliant)
	assertStatus(t, findings, "cry-003", modules.StatusNonCompliant)
	assertStatus(t, findings, "cry-004", modules.StatusNonCompliant)
	assertStatus(t, findings, "cry-006", modules.StatusNonCompliant)
}

func TestPlan_NoChanges(t *testing.T) {
	m := crypto.NewModuleForTest(nil, "", "", "", "", "", "")
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan(): %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("expected 0 changes, got %d", len(changes))
	}
}

func TestHelpers(t *testing.T) {
	if !crypto.PolicyIsDefaultOrStronger("DEFAULT") {
		t.Fatal("DEFAULT should be stronger")
	}
	if crypto.PolicyIsDefaultOrStronger("LEGACY") {
		t.Fatal("LEGACY should not be stronger")
	}
	if got := crypto.ParseOpenSSLMinProtocol("MinProtocol = TLSv1.2"); got != "TLSv1.2" {
		t.Fatalf("unexpected MinProtocol %q", got)
	}
	if got := crypto.ParseOpenSSLCipherString("CipherString = DEFAULT:@SECLEVEL=2:!RC4:!DES:!3DES:!EXP"); got == "" {
		t.Fatal("expected cipher string")
	}
	if !crypto.GPGUsesLongKeyID("keyid-format 0xlong") {
		t.Fatal("expected long keyid")
	}
}

func td(name string) string {
	return filepath.Join("testdata", name)
}

func assertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Fatalf("%s: got %s want %s (current=%q detail=%q)", id, f.Status, want, f.Current, f.Detail)
			}
			return
		}
	}
	t.Fatalf("check %s not found", id)
}
