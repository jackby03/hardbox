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
package network_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/network"
)

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = network.NewModuleForTest(network.TestOptions{})
}

func TestModule_NameAndVersion(t *testing.T) {
	m := network.NewModuleForTest(network.TestOptions{})
	if m.Name() != "network" {
		t.Fatalf("Name()=%q, want network", m.Name())
	}
	if m.Version() == "" {
		t.Fatal("Version() should not be empty")
	}
}

func TestAudit_CompliantScenario(t *testing.T) {
	tmp := t.TempDir()
	opts := buildFixture(t, tmp)

	cfg := modules.ModuleConfig{
		"disable_ipv6":     true,
		"disable_dccp":     true,
		"disable_sctp":     true,
		"disable_rds":      true,
		"disable_tipc":     true,
		"disable_wireless": true,
	}

	m := network.NewModuleForTest(opts)
	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}

	for _, id := range []string{"net-001", "net-002", "net-003", "net-004", "net-005", "net-006", "net-007", "net-008"} {
		assertStatus(t, findings, id, modules.StatusCompliant)
	}
}

func TestPlan_WritesBlacklistFile(t *testing.T) {
	tmp := t.TempDir()
	opts := buildFixture(t, tmp)

	// Remove existing hardening entries to force non-compliance.
	if err := os.WriteFile(filepath.Join(opts.ModprobeDir, "baseline.conf"), []byte("# empty\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := modules.ModuleConfig{
		"disable_dccp": true,
		"disable_sctp": true,
		"disable_rds":  true,
		"disable_tipc": true,
	}

	m := network.NewModuleForTest(opts)
	changes, err := m.Plan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Plan(): %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("Plan(): got %d changes, want 1", len(changes))
	}
	if !strings.Contains(changes[0].DryRunOutput, "blacklist dccp") {
		t.Fatalf("DryRunOutput missing blacklist entry: %q", changes[0].DryRunOutput)
	}

	if err := changes[0].Apply(); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	content, err := os.ReadFile(filepath.Join(opts.ModprobeDir, "hardbox-disable.conf"))
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	if !strings.Contains(string(content), "install tipc /bin/true") {
		t.Fatalf("hardbox-disable.conf missing expected line, got:\n%s", string(content))
	}
}

func TestAudit_DetectsNetrcInHome(t *testing.T) {
	tmp := t.TempDir()
	opts := buildFixture(t, tmp)

	home := filepath.Join(tmp, "home", "alice")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".netrc"), []byte("machine internal\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := network.NewModuleForTest(opts)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "net-008", modules.StatusNonCompliant)
}

func buildFixture(t *testing.T, root string) network.TestOptions {
	t.Helper()

	ipv6Path := filepath.Join(root, "disable_ipv6")
	modprobeDir := filepath.Join(root, "modprobe.d")
	hostsAllow := filepath.Join(root, "hosts.allow")
	hostsDeny := filepath.Join(root, "hosts.deny")
	wirelessPath := filepath.Join(root, "wireless")
	passwdPath := filepath.Join(root, "passwd")

	if err := os.MkdirAll(modprobeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "home", "alice"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(ipv6Path, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostsAllow, []byte("sshd: 10.0.0.0/8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostsDeny, []byte("ALL: ALL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wirelessContent := "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n"
	if err := os.WriteFile(wirelessPath, []byte(wirelessContent), 0o644); err != nil {
		t.Fatal(err)
	}
	passwd := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:" + filepath.Join(root, "home", "alice") + ":/bin/bash\n"
	if err := os.WriteFile(passwdPath, []byte(passwd), 0o644); err != nil {
		t.Fatal(err)
	}

	baseline := strings.Join([]string{
		"blacklist dccp",
		"install dccp /bin/true",
		"blacklist sctp",
		"install sctp /bin/true",
		"blacklist rds",
		"install rds /bin/true",
		"blacklist tipc",
		"install tipc /bin/true",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(modprobeDir, "baseline.conf"), []byte(baseline), 0o644); err != nil {
		t.Fatal(err)
	}

	return network.TestOptions{
		IPv6DisablePath: ipv6Path,
		ModprobeDir:     modprobeDir,
		HostsAllowPath:  hostsAllow,
		HostsDenyPath:   hostsDeny,
		WirelessPath:    wirelessPath,
		PasswdPath:      passwdPath,
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

