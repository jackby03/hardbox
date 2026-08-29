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
package crypto_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/crypto"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
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
	testutil.AssertStatus(t, findings, "cry-001", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "cry-002", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "cry-003", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "cry-004", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "cry-005", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "cry-006", modules.StatusCompliant)
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
	testutil.AssertStatus(t, findings, "cry-001", modules.StatusNonCompliant)
	testutil.AssertStatus(t, findings, "cry-002", modules.StatusNonCompliant)
	testutil.AssertStatus(t, findings, "cry-003", modules.StatusNonCompliant)
	testutil.AssertStatus(t, findings, "cry-004", modules.StatusNonCompliant)
	testutil.AssertStatus(t, findings, "cry-005", modules.StatusManual)
	testutil.AssertStatus(t, findings, "cry-006", modules.StatusNonCompliant)
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
	testutil.AssertStatus(t, findings, "cry-001", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "cry-002", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "cry-003", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "cry-004", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "cry-005", modules.StatusManual)
	testutil.AssertStatus(t, findings, "cry-006", modules.StatusCompliant)
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
	testutil.AssertStatus(t, findings, "cry-001", modules.StatusNonCompliant)
	testutil.AssertStatus(t, findings, "cry-002", modules.StatusNonCompliant)
	testutil.AssertStatus(t, findings, "cry-003", modules.StatusNonCompliant)
	testutil.AssertStatus(t, findings, "cry-004", modules.StatusNonCompliant)
	testutil.AssertStatus(t, findings, "cry-006", modules.StatusNonCompliant)
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

func TestReadStringIfExists_PermissionDenied(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("Skipping test on root as root can read files with 000 permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "noperm")
	if err := os.WriteFile(path, []byte("test"), 0000); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := crypto.ReadStringIfExists(path)
	if err == nil {
		t.Fatal("expected an error due to permission denied, but got nil")
	}
}

func td(name string) string {
	return filepath.Join("testdata", name)
}

