package ntp_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/ntp"
)

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = ntp.NewModuleForTest(nil, "")
}

func TestModule_NameAndVersion(t *testing.T) {
	m := ntp.NewModuleForTest(nil, "")
	if m.Name() != "ntp" {
		t.Fatalf("Name(): got %q, want ntp", m.Name())
	}
	if m.Version() == "" {
		t.Fatal("Version() should not be empty")
	}
}

func TestAudit_AllCompliant(t *testing.T) {
	m := ntp.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-enabled chronyd.service":           {out: "enabled"},
		"systemctl is-active chronyd.service":            {out: "active"},
		"systemctl is-enabled systemd-timesyncd.service": {out: "disabled"},
		"systemctl is-active systemd-timesyncd.service":  {out: "inactive", err: true},
		"systemctl is-enabled ntpd.service":              {out: "not-found", err: true},
		"systemctl is-active ntpd.service":               {out: "inactive", err: true},
		"timedatectl show --property=Timezone --value":   {out: "UTC"},
	}), filepath.FromSlash("testdata/chrony_compliant.conf"))

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): unexpected error: %v", err)
	}
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Status != modules.StatusCompliant {
			t.Errorf("check %s: expected compliant, got %s", f.Check.ID, f.Status)
		}
	}
}

func TestAudit_NonCompliantScenarios(t *testing.T) {
	m := ntp.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-enabled chronyd.service":           {out: "enabled"},
		"systemctl is-active chronyd.service":            {out: "active"},
		"systemctl is-enabled systemd-timesyncd.service": {out: "enabled"},
		"systemctl is-active systemd-timesyncd.service":  {out: "active"},
		"systemctl is-enabled ntpd.service":              {out: "not-found", err: true},
		"systemctl is-active ntpd.service":               {out: "inactive", err: true},
		"timedatectl show --property=Timezone --value":   {out: "Europe/Madrid"},
	}), filepath.FromSlash("testdata/chrony_noncompliant.conf"))

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): unexpected error: %v", err)
	}

	assertStatus(t, findings, "ntp-002", modules.StatusNonCompliant)
	assertStatus(t, findings, "ntp-003", modules.StatusNonCompliant)
	assertStatus(t, findings, "ntp-004", modules.StatusNonCompliant)
	assertStatus(t, findings, "ntp-005", modules.StatusNonCompliant)
}

func TestAudit_SkipsChronyDirectivesWhenChronyNotInstalled(t *testing.T) {
	m := ntp.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-enabled chronyd.service":           {out: "not-found", err: true},
		"systemctl is-active chronyd.service":            {out: "inactive", err: true},
		"systemctl is-enabled systemd-timesyncd.service": {out: "not-found", err: true},
		"systemctl is-active systemd-timesyncd.service":  {out: "inactive", err: true},
		"systemctl is-enabled ntpd.service":              {out: "not-found", err: true},
		"systemctl is-active ntpd.service":               {out: "inactive", err: true},
		"timedatectl show --property=Timezone --value":   {out: "UTC"},
	}), filepath.FromSlash("testdata/chrony_noncompliant.conf"))

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): unexpected error: %v", err)
	}

	assertStatus(t, findings, "ntp-001", modules.StatusNonCompliant)
	assertStatus(t, findings, "ntp-003", modules.StatusSkipped)
	assertStatus(t, findings, "ntp-004", modules.StatusSkipped)
}

func TestPlan_UpdatesChronyAndReverts(t *testing.T) {
	dir := t.TempDir()
	chronyPath := filepath.Join(dir, "chrony.conf")
	initial := "pool pool.ntp.org iburst\n"
	if err := os.WriteFile(chronyPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	m := ntp.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-enabled chronyd.service":           {out: "enabled"},
		"systemctl is-active chronyd.service":            {out: "active"},
		"systemctl is-enabled systemd-timesyncd.service": {out: "not-found", err: true},
		"systemctl is-active systemd-timesyncd.service":  {out: "inactive", err: true},
		"systemctl is-enabled ntpd.service":              {out: "not-found", err: true},
		"systemctl is-active ntpd.service":               {out: "inactive", err: true},
		"timedatectl show --property=Timezone --value":   {out: "UTC"},
	}), chronyPath)

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan(): unexpected error: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}

	if err := changes[0].Apply(); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	applied, err := os.ReadFile(chronyPath)
	if err != nil {
		t.Fatalf("read applied: %v", err)
	}
	if !strings.Contains(string(applied), "makestep 1.0 3") {
		t.Fatalf("applied config missing makestep: %q", string(applied))
	}
	if !strings.Contains(string(applied), "maxdistance 16.0") {
		t.Fatalf("applied config missing maxdistance: %q", string(applied))
	}

	if err := changes[0].Revert(); err != nil {
		t.Fatalf("Revert(): %v", err)
	}
	reverted, err := os.ReadFile(chronyPath)
	if err != nil {
		t.Fatalf("read reverted: %v", err)
	}
	if string(reverted) != initial {
		t.Fatalf("revert mismatch: got %q want %q", string(reverted), initial)
	}
}

func TestPlan_NoChangesWhenCompliant(t *testing.T) {
	m := ntp.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-enabled chronyd.service":           {out: "enabled"},
		"systemctl is-active chronyd.service":            {out: "active"},
		"systemctl is-enabled systemd-timesyncd.service": {out: "disabled"},
		"systemctl is-active systemd-timesyncd.service":  {out: "inactive", err: true},
		"systemctl is-enabled ntpd.service":              {out: "not-found", err: true},
		"systemctl is-active ntpd.service":               {out: "inactive", err: true},
		"timedatectl show --property=Timezone --value":   {out: "UTC"},
	}), filepath.FromSlash("testdata/chrony_compliant.conf"))

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan(): unexpected error: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("expected 0 changes when compliant, got %d", len(changes))
	}
}

func assertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Fatalf("check %s: got %s, want %s", id, f.Status, want)
			}
			return
		}
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
