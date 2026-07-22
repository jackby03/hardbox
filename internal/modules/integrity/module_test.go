package integrity_test

import (
	"context"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/integrity"
)

func TestModule_ImplementsInterface(t *testing.T) {
	var m modules.Module = &integrity.Module{}
	if m.Name() == "" || m.Version() == "" {
		t.Error("module must implement Name() and Version()")
	}
}

func TestAudit_ProducesFindings(t *testing.T) {
	m := &integrity.Module{}
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	if len(findings) != 5 {
		t.Errorf("expected 5 findings, got %d", len(findings))
	}
}

func TestPlan_GeneratesValidChanges(t *testing.T) {
	m := &integrity.Module{}
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan(): %v", err)
	}
	for _, c := range changes {
		if c.Description == "" {
			t.Error("change missing description")
		}
	}
}

func TestChecks_AllHaveIDs(t *testing.T) {
	checks := []modules.Check{
		integrity.CheckINT001(), integrity.CheckINT002(), integrity.CheckINT003(),
		integrity.CheckINT004(), integrity.CheckINT005(),
	}
	for _, c := range checks {
		if c.ID == "" || c.Title == "" {
			t.Errorf("check %+v is incomplete", c)
		}
	}
}
