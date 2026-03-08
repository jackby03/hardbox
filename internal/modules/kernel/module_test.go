package kernel_test

import (
	"context"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/kernel"
)

const (
	hardenedBase = "testdata/proc_sys_hardened"
	defaultBase  = "testdata/proc_sys_default"
)

// ── interface compliance ──────────────────────────────────────────────────────

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = kernel.NewModuleWithProcBase("")
}

func TestModule_NameAndVersion(t *testing.T) {
	m := kernel.NewModuleWithProcBase("")
	if m.Name() != "kernel" {
		t.Errorf("Name(): got %q, want 'kernel'", m.Name())
	}
	if m.Version() == "" {
		t.Error("Version() should not be empty")
	}
}

// ── Audit with hardened fixtures (all compliant) ──────────────────────────────

func TestAudit_AllCompliant_WhenHardened(t *testing.T) {
	m := kernel.NewModuleWithProcBase(hardenedBase)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Status == modules.StatusSkipped {
			continue // fixture might not have every optional param
		}
		if f.Status != modules.StatusCompliant {
			t.Errorf("check %s: expected compliant, got %s (current=%q, target=%q)",
				f.Check.ID, f.Status, f.Current, f.Target)
		}
	}
}

// ── Audit with default (insecure) fixtures ────────────────────────────────────

func TestAudit_NonCompliant_WhenDefault(t *testing.T) {
	m := kernel.NewModuleWithProcBase(defaultBase)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nonCompliant := 0
	for _, f := range findings {
		if f.Status == modules.StatusNonCompliant {
			nonCompliant++
		}
	}

	// Fixtures have 13 bad values — at least 10 should be non-compliant.
	if nonCompliant < 10 {
		t.Errorf("expected at least 10 non-compliant findings, got %d", nonCompliant)
	}
}

func TestAudit_FindingFields_Populated(t *testing.T) {
	m := kernel.NewModuleWithProcBase(defaultBase)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Status == modules.StatusSkipped {
			continue
		}
		if f.Check.ID == "" {
			t.Error("finding has empty CheckID")
		}
		if f.Check.Title == "" {
			t.Error("finding has empty Title")
		}
		if f.Check.Severity == "" {
			t.Error("finding has empty Severity")
		}
		if f.Current == "" {
			t.Errorf("check %s: Current should not be empty", f.Check.ID)
		}
		if f.Target == "" {
			t.Errorf("check %s: Target should not be empty", f.Check.ID)
		}
	}
}

// ── Check ID format ──────────────────────────────────────────────────────────

func TestAudit_CheckIDFormat(t *testing.T) {
	m := kernel.NewModuleWithProcBase(hardenedBase)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		id := f.Check.ID
		if len(id) < 6 {
			t.Errorf("check ID %q is too short", id)
		}
		if id[:3] != "kn-" && id[:3] != "km-" {
			t.Errorf("check ID %q does not start with 'kn-' or 'km-'", id)
		}
	}
}

// ── Plan ─────────────────────────────────────────────────────────────────────

func TestPlan_NoChanges_WhenCompliant(t *testing.T) {
	m := kernel.NewModuleWithProcBase(hardenedBase)
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes when compliant, got %d", len(changes))
	}
}

func TestPlan_ReturnsChanges_WhenNonCompliant(t *testing.T) {
	m := kernel.NewModuleWithProcBase(defaultBase)
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(changes) == 0 {
		t.Fatal("expected at least 1 change when non-compliant, got 0")
	}
}

func TestPlan_SingleChange_WithAllParams(t *testing.T) {
	m := kernel.NewModuleWithProcBase(defaultBase)
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Plan() should return exactly one batched change (one sysctl.d file write)
	if len(changes) != 1 {
		t.Errorf("expected exactly 1 batched change, got %d", len(changes))
	}
	if changes[0].Description == "" {
		t.Error("Change.Description should not be empty")
	}
	if changes[0].DryRunOutput == "" {
		t.Error("Change.DryRunOutput should not be empty")
	}
	if changes[0].Apply == nil {
		t.Error("Change.Apply should not be nil")
	}
	if changes[0].Revert == nil {
		t.Error("Change.Revert should not be nil")
	}
}

// ── Skipped findings (missing sysctl param) ───────────────────────────────────

func TestAudit_SkipsUnknownParams(t *testing.T) {
	// Empty base dir — all params are missing → all should be skipped, not error.
	m := kernel.NewModuleWithProcBase("testdata/proc_sys_empty")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Status != modules.StatusSkipped {
			t.Errorf("check %s: expected skipped for missing param, got %s", f.Check.ID, f.Status)
		}
	}
}
