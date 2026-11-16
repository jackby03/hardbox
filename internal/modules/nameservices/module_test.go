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

package nameservices_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/nameservices"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// absent returns a path that does not exist, so no test reads the host's files.
func absent(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent")
}

// env builds a module over a temp dir with the given files. Files named "" are
// replaced with a non-existent path.
type env struct {
	dir      string
	hosts    string
	nsswc    string
	resolv   string
	resolved string
	unbound  string
	dnsmasq  string
}

func newEnv(t *testing.T, hosts, nsswitch, resolv, resolved, unbound, dnsmasq string) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{dir: dir}
	pick := func(name, content string) string {
		if content == "" {
			return absent(t)
		}
		return writeFile(t, dir, name, content)
	}
	e.hosts = pick("hosts", hosts)
	e.nsswc = pick("nsswitch.conf", nsswitch)
	e.resolv = pick("resolv.conf", resolv)
	e.resolved = pick("resolved.conf", resolved)
	e.unbound = pick("unbound.conf", unbound)
	e.dnsmasq = pick("dnsmasq.conf", dnsmasq)
	return e
}

func (e *env) module() *nameservices.Module {
	return nameservices.NewModuleForTest(e.hosts, e.nsswc, e.resolv, e.resolved, e.unbound, e.dnsmasq)
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
	var _ modules.Module = &nameservices.Module{}
}

func TestAudit_AllCompliant(t *testing.T) {
	e := newEnv(t,
		"127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n",
		"passwd: compat\nhosts:          files dns\nnetworks:       files\n",
		"nameserver 127.0.0.53\n",
		"[Resolve]\nDNSSEC=yes\n", "", "")

	findings, err := e.module().Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, id := range []string{"dns-001", "dns-003", "dns-004", "dns-005"} {
		if got := find(t, findings, id).Status; got != modules.StatusCompliant {
			t.Errorf("%s: want compliant, got %s", id, got)
		}
	}
	// Windows ignores everything outside 0777, so the file is never 0644 there.
	if testutil.UnixPermsSupported() {
		if got := find(t, findings, "dns-002").Status; got != modules.StatusCompliant {
			t.Errorf("dns-002: want compliant, got %s", got)
		}
	}
}

func TestAudit_HostsMissingLoopback(t *testing.T) {
	e := newEnv(t, "127.0.0.1 localhost\n", "hosts: files dns\n", "nameserver 127.0.0.53\n", "[Resolve]\nDNSSEC=yes\n", "", "")

	findings, err := e.module().Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	f := find(t, findings, "dns-001")
	if f.Status != modules.StatusNonCompliant || !strings.Contains(f.Current, "::1") {
		t.Errorf("want the missing IPv6 mapping named, got %s %q", f.Status, f.Current)
	}
}

// TestAudit_HostsAcceptsIPv6Aliases covers families that spell the IPv6 loopback
// name differently; ip6-localhost is a valid mapping.
func TestAudit_HostsAcceptsIPv6Aliases(t *testing.T) {
	e := newEnv(t,
		"127.0.0.1 localhost\n::1 ip6-localhost ip6-loopback\n",
		"hosts: files dns\n", "nameserver 127.0.0.53\n", "[Resolve]\nDNSSEC=yes\n", "", "")

	findings, err := e.module().Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if got := find(t, findings, "dns-001").Status; got != modules.StatusCompliant {
		t.Errorf("ip6-localhost must satisfy the IPv6 check, got %s", got)
	}
}

func TestAudit_HostsPermissions(t *testing.T) {
	testutil.RequireUnixPerms(t)

	e := newEnv(t, "127.0.0.1 localhost\n::1 localhost\n", "hosts: files dns\n", "nameserver 127.0.0.53\n", "[Resolve]\nDNSSEC=yes\n", "", "")
	if err := os.Chmod(e.hosts, 0o666); err != nil {
		t.Fatal(err)
	}

	findings, err := e.module().Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	f := find(t, findings, "dns-002")
	if f.Status != modules.StatusNonCompliant {
		t.Errorf("want non-compliant for 0666, got %s", f.Status)
	}
}

// TestAudit_NsswitchOrdering covers the case that matters: dns before files lets a
// resolver answer override /etc/hosts.
func TestAudit_NsswitchOrdering(t *testing.T) {
	e := newEnv(t,
		"127.0.0.1 localhost\n::1 localhost\n",
		"hosts:          dns files\n",
		"nameserver 127.0.0.53\n", "[Resolve]\nDNSSEC=yes\n", "", "")

	findings, err := e.module().Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	f := find(t, findings, "dns-003")
	if f.Status != modules.StatusNonCompliant {
		t.Errorf("want non-compliant when dns precedes files, got %s", f.Status)
	}
}

// TestAudit_NsswitchFilesOnlyIsCompliant: no dns token at all is a deliberate
// hosts-only setup, not a weakness.
func TestAudit_NsswitchFilesOnlyIsCompliant(t *testing.T) {
	e := newEnv(t,
		"127.0.0.1 localhost\n::1 localhost\n",
		"hosts: files myhostname\n",
		"nameserver 127.0.0.53\n", "[Resolve]\nDNSSEC=yes\n", "", "")

	findings, err := e.module().Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if got := find(t, findings, "dns-003").Status; got != modules.StatusCompliant {
		t.Errorf("files-only should be compliant, got %s", got)
	}
}

func TestAudit_DNSSEC_Resolvers(t *testing.T) {
	cases := []struct {
		name              string
		resolved, unbound string
		dnsmasq           string
		want              modules.Status
	}{
		{"resolved yes", "[Resolve]\nDNSSEC=yes\n", "", "", modules.StatusCompliant},
		{"resolved unset", "[Resolve]\nDNSStubListener=yes\n", "", "", modules.StatusNonCompliant},
		{"resolved allow-downgrade", "[Resolve]\nDNSSEC=allow-downgrade\n", "", "", modules.StatusNonCompliant},
		{"unbound validating", "", "auto-trust-anchor-file: /var/lib/unbound/root.key\n", "", modules.StatusCompliant},
		{"unbound permissive", "", "auto-trust-anchor-file: /x\nval-permissive-mode: yes\n", "", modules.StatusNonCompliant},
		{"dnsmasq dnssec", "", "", "dnssec\n", modules.StatusCompliant},
		{"dnsmasq plain", "", "", "domain-needed\n", modules.StatusNonCompliant},
		{"no resolver", "", "", "", modules.StatusManual},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, "127.0.0.1 localhost\n::1 localhost\n", "hosts: files dns\n",
				"nameserver 127.0.0.53\n", c.resolved, c.unbound, c.dnsmasq)
			findings, err := e.module().Audit(context.Background(), nil)
			if err != nil {
				t.Fatalf("Audit: %v", err)
			}
			if got := find(t, findings, "dns-004").Status; got != c.want {
				t.Errorf("want %s, got %s", c.want, got)
			}
		})
	}
}

func TestAudit_PlaintextDNS(t *testing.T) {
	e := newEnv(t, "127.0.0.1 localhost\n::1 localhost\n", "hosts: files dns\n",
		"nameserver 8.8.8.8\nnameserver 1.1.1.1\n#[Resolve]\n", "[Resolve]\nDNSSEC=yes\n", "", "")

	findings, err := e.module().Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	f := find(t, findings, "dns-005")
	if f.Status != modules.StatusNonCompliant {
		t.Errorf("want non-compliant for external nameservers, got %s", f.Status)
	}
	if !strings.Contains(f.Current, "8.8.8.8") {
		t.Errorf("want the external server named, got %q", f.Current)
	}

	if !nameservices.IsLoopbackNS("127.0.0.53") || nameservices.IsLoopbackNS("8.8.8.8") {
		t.Error("loopback predicate is wrong")
	}
}

// TestPlan_AppendsLoopbackAndReordersNsswitch covers the two content changes.
// The ownership change needs CAP_CHOWN and is covered separately.
func TestPlan_AppendsLoopbackAndReordersNsswitch(t *testing.T) {
	// On Windows a written file is always 0666, which adds the permissions change
	// and therefore a chown the test cannot perform.
	testutil.RequireUnixPerms(t)

	e := newEnv(t,
		"127.0.0.1 localhost\n",
		"passwd: compat\nhosts:          dns files mdns4_minimal\nnetworks:       files\n",
		"nameserver 127.0.0.53\n", "[Resolve]\nDNSSEC=yes\n", "", "")

	m := e.module()
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("want 2 changes (loopback, nsswitch), got %d", len(changes))
	}
	for _, c := range changes {
		if len(c.Files) != 1 {
			t.Errorf("change %q must declare its file", c.Description)
		}
		if err := c.Apply(); err != nil {
			t.Fatalf("Apply %q: %v", c.Description, err)
		}
	}

	hosts, err := os.ReadFile(e.hosts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hosts), "127.0.0.1 localhost") {
		t.Errorf("existing hosts content was lost:\n%s", hosts)
	}
	if !strings.Contains(string(hosts), "::1 localhost") {
		t.Errorf("IPv6 loopback was not appended:\n%s", hosts)
	}

	nsswitch, err := os.ReadFile(e.nsswc)
	if err != nil {
		t.Fatal(err)
	}
	line := nameservices.HostsLine(string(nsswitch))
	files, dns, ok := nameservices.FilesBeforeDNS(line)
	if !ok || files == -1 || dns == -1 || files > dns {
		t.Errorf("hosts line not reordered: %q (files=%d dns=%d)", line, files, dns)
	}
	if !strings.Contains(string(nsswitch), "passwd: compat") {
		t.Errorf("unrelated nsswitch lines must be preserved:\n%s", nsswitch)
	}
	if !strings.Contains(line, "mdns4_minimal") {
		t.Errorf("other tokens must be preserved: %q", line)
	}

	// Re-auditing after apply should clear the three file checks.
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, id := range []string{"dns-001", "dns-002", "dns-003"} {
		if got := find(t, findings, id).Status; got != modules.StatusCompliant {
			t.Errorf("%s: still %s after apply", id, got)
		}
	}
}

// TestPlan_PermissionsChangeNeedsRoot applies the ownership remediation, which
// requires CAP_CHOWN.
func TestPlan_PermissionsChangeNeedsRoot(t *testing.T) {
	testutil.RequireRoot(t)

	e := newEnv(t,
		"127.0.0.1 localhost\n::1 localhost\n",
		"hosts: files dns\n",
		"nameserver 127.0.0.53\n", "[Resolve]\nDNSSEC=yes\n", "", "")
	if err := os.Chmod(e.hosts, 0o664); err != nil {
		t.Fatal(err)
	}

	changes, err := e.module().Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("want only the permissions change, got %d", len(changes))
	}
	if err := changes[0].Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	info, err := os.Stat(e.hosts)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode not fixed: %04o", info.Mode().Perm())
	}
}

// TestPlan_ResolverIsAuditOnly pins the two documented exceptions.
func TestPlan_ResolverIsAuditOnly(t *testing.T) {
	e := newEnv(t,
		"127.0.0.1 localhost\n::1 localhost\n",
		"hosts: files dns\n",
		"nameserver 8.8.8.8\n",
		"[Resolve]\nDNSSEC=no\n", "", "")

	changes, err := e.module().Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, c := range changes {
		for _, f := range c.Files {
			if f == e.resolved || f == e.resolv {
				t.Fatalf("resolver configuration must not be rewritten automatically (%q)", c.Description)
			}
		}
	}
}

func TestNormalizeHostsLine(t *testing.T) {
	cases := map[string]string{
		"hosts:          dns files mdns4_minimal": "hosts:          files dns mdns4_minimal",
		"hosts: files dns":                        "hosts:          files dns",
		"hosts: files":                            "hosts:          files",
	}
	for in, want := range cases {
		if got := nameservices.NormalizeHostsLine(in); got != want {
			t.Errorf("NormalizeHostsLine(%q) = %q, want %q", in, got, want)
		}
	}
}
