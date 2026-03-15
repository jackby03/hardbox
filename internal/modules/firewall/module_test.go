package firewall_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/distro"
	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/firewall"
)

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = firewall.NewModuleForTest(nil, nil, nil, "", "")
}

func TestModule_NameAndVersion(t *testing.T) {
	m := firewall.NewModuleForTest(nil, nil, nil, "", "")
	if m.Name() != "firewall" {
		t.Fatalf("Name(): got %q", m.Name())
	}
	if m.Version() == "" {
		t.Fatal("Version() should not be empty")
	}
}

func TestAudit_UFWCompliant(t *testing.T) {
	ipv6 := writeIPv6DisableFile(t, "0\n")
	m := firewall.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"ufw status verbose": {out: "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n22/tcp ALLOW 10.0.0.0/24\nAnywhere on lo ALLOW IN Anywhere\n22/tcp (v6) ALLOW ::/0\n"},
	}), firewall.FakeDistroDebian, nil, "", ipv6)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	if len(findings) != 6 {
		t.Fatalf("expected 6 findings, got %d", len(findings))
	}
	assertStatus(t, findings, "fw-001", modules.StatusCompliant)
	assertStatus(t, findings, "fw-002", modules.StatusCompliant)
	assertStatus(t, findings, "fw-003", modules.StatusCompliant)
	assertStatus(t, findings, "fw-004", modules.StatusCompliant)
	assertStatus(t, findings, "fw-005", modules.StatusCompliant)
	assertStatus(t, findings, "fw-006", modules.StatusCompliant)
}

func TestAudit_UFWSensitivePortOpen(t *testing.T) {
	ipv6 := writeIPv6DisableFile(t, "0\n")
	m := firewall.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"ufw status verbose": {out: "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n22/tcp ALLOW Anywhere\nAnywhere on lo ALLOW IN Anywhere\n"},
	}), firewall.FakeDistroDebian, nil, "", ipv6)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "fw-005", modules.StatusNonCompliant)
	assertStatus(t, findings, "fw-006", modules.StatusNonCompliant)
}

func TestAudit_FirewalldInboundNotDrop(t *testing.T) {
	ipv6 := writeIPv6DisableFile(t, "0\n")
	m := firewall.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"firewall-cmd --state":    {out: "running"},
		"firewall-cmd --list-all": {out: "public (active)\n  target: ACCEPT\n  interfaces: eth0 lo\n  ports: \n"},
	}), firewall.FakeDistroRHEL, nil, "", ipv6)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "fw-001", modules.StatusCompliant)
	assertStatus(t, findings, "fw-002", modules.StatusNonCompliant)
	assertStatus(t, findings, "fw-003", modules.StatusSkipped)
	assertStatus(t, findings, "fw-004", modules.StatusCompliant)
	assertStatus(t, findings, "fw-005", modules.StatusCompliant)
	assertStatus(t, findings, "fw-006", modules.StatusCompliant)
}

func TestAudit_NftablesCompliant(t *testing.T) {
	ipv6 := writeIPv6DisableFile(t, "0\n")
	ruleset := `table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
table ip6 filter {
  chain input {
    type filter hook input priority 0; policy drop;
  }
}`
	m := firewall.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-enabled nftables": {out: "enabled"},
		"systemctl is-active nftables":  {out: "active"},
		"nft list ruleset":              {out: ruleset},
	}), nil, alwaysFalse, "nftables", ipv6)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	for _, id := range []string{"fw-001", "fw-002", "fw-003", "fw-004", "fw-005", "fw-006"} {
		assertStatus(t, findings, id, modules.StatusCompliant)
	}
}

func TestAudit_IPv6DisabledSkipsFW006(t *testing.T) {
	ipv6 := writeIPv6DisableFile(t, "1\n")
	m := firewall.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"ufw status verbose": {out: "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nAnywhere on lo ALLOW IN Anywhere\n"},
	}), firewall.FakeDistroDebian, nil, "", ipv6)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "fw-006", modules.StatusSkipped)
}

func TestAudit_NoBackendDetectedReturnsErrors(t *testing.T) {
	m := firewall.NewModuleForTest(nil, func() (*distro.Info, error) { return nil, fmt.Errorf("no distro") }, alwaysFalse, "", "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	if len(findings) != 6 {
		t.Fatalf("expected 6 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Status != modules.StatusError {
			t.Fatalf("check %s should be error, got %s", f.Check.ID, f.Status)
		}
	}
}

func TestPlan_NoChanges(t *testing.T) {
	m := firewall.NewModuleForTest(nil, firewall.FakeDistroDebian, alwaysTrue, "", "")
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan(): %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("expected no changes, got %d", len(changes))
	}
}

func TestParseUFWDefaults(t *testing.T) {
	in, out := firewall.ParseUFWDefaults("Default: deny (incoming), allow (outgoing), disabled (routed)")
	if in != "deny" || out != "allow" {
		t.Fatalf("unexpected defaults: in=%q out=%q", in, out)
	}
}

func TestNftHasIPv6Rules(t *testing.T) {
	if !firewall.NftHasIPv6Rules("table ip6 filter {}") {
		t.Fatal("expected ip6 table to be detected")
	}
	if firewall.NftHasIPv6Rules("table ip filter {}") {
		t.Fatal("did not expect ipv6 rules")
	}
}

func assertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID != id {
			continue
		}
		if f.Status != want {
			t.Fatalf("check %s: got %s want %s (current=%q detail=%q)", id, f.Status, want, f.Current, f.Detail)
		}
		return
	}
	t.Fatalf("check %s not found", id)
}

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
			return res.out, fmt.Errorf("command failed: %s", key)
		}
		return res.out, nil
	}
}

func writeIPv6DisableFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "disable_ipv6")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write ipv6 fixture: %v", err)
	}
	return path
}

func alwaysTrue(string) bool  { return true }
func alwaysFalse(string) bool { return false }
