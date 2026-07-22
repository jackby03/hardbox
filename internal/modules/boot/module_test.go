package boot_test

import (
	"context"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/boot"
)

func TestModule_ImplementsInterface(t *testing.T) {
	var m modules.Module = &boot.Module{}
	if m.Name() == "" || m.Version() == "" {
		t.Error("module must implement Name() and Version()")
	}
}

func TestModule_NameAndVersion(t *testing.T) {
	m := &boot.Module{}
	if m.Name() != "boot" {
		t.Errorf("Name: got %q, want boot", m.Name())
	}
	if m.Version() != "1.0" {
		t.Errorf("Version: got %q, want 1.0", m.Version())
	}
}

func TestAudit_ProducesFindings(t *testing.T) {
	m := &boot.Module{}
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	if len(findings) != 5 {
		t.Errorf("expected 5 findings, got %d", len(findings))
	}
}

func TestPlan_GeneratesValidChanges(t *testing.T) {
	m := &boot.Module{}
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan(): %v", err)
	}
	for _, c := range changes {
		if c.Description == "" {
			t.Error("change missing description")
		}
		if c.Apply == nil || c.Revert == nil {
			t.Error("change missing apply/revert")
		}
	}
}

func TestChecks_AllHaveIDs(t *testing.T) {
	checks := []modules.Check{
		boot.CheckBOOT001(), boot.CheckBOOT002(), boot.CheckBOOT003(),
		boot.CheckBOOT004(), boot.CheckBOOT005(),
	}
	for _, c := range checks {
		if c.ID == "" || c.Title == "" {
			t.Errorf("check %+v is incomplete", c)
		}
	}
}
