package storage_test

import (
	"context"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/storage"
)

func TestModule_ImplementsInterface(t *testing.T) {
	var m modules.Module = &storage.Module{}
	if m.Name() == "" || m.Version() == "" {
		t.Error("module must implement Name() and Version()")
	}
}

func TestAudit_ProducesFindings(t *testing.T) {
	m := &storage.Module{}
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	if len(findings) != 5 {
		t.Errorf("expected 5 findings, got %d", len(findings))
	}
}

func TestPlan_GeneratesValidChanges(t *testing.T) {
	m := &storage.Module{}
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
		storage.CheckSTG001(), storage.CheckSTG002(), storage.CheckSTG003(),
		storage.CheckSTG004(), storage.CheckSTG005(),
	}
	for _, c := range checks {
		if c.ID == "" || c.Title == "" {
			t.Errorf("check %+v is incomplete", c)
		}
	}
}
