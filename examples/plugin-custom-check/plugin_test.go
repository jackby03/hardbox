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

package main

import (
	"context"
	"os"
	"testing"

	"github.com/hardbox-io/hardbox/internal/sdk"
)

func TestNew(t *testing.T) {
	mod := New()
	if mod == nil {
		t.Fatal("expected New() to return non-nil module")
	}
}

func TestTmpStickyModule_NameAndVersion(t *testing.T) {
	mod := New()
	if got := mod.Name(); got != "custom-tmp-sticky" {
		t.Errorf("Name() = %q, want %q", got, "custom-tmp-sticky")
	}
	if got := mod.Version(); got != "1.0.0" {
		t.Errorf("Version() = %q, want %q", got, "1.0.0")
	}
}

func TestTmpStickyModule_Audit(t *testing.T) {
	mod := New()
	findings, err := mod.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit returned unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Audit returned %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.Check.ID != "CUSTOM-001" {
		t.Errorf("finding Check.ID = %q, want %q", f.Check.ID, "CUSTOM-001")
	}
	if f.Check.Severity != sdk.SeverityMedium {
		t.Errorf("finding Check.Severity = %v, want %v", f.Check.Severity, sdk.SeverityMedium)
	}

	info, statErr := os.Stat("/tmp")
	if statErr != nil {
		if f.Status != sdk.StatusError {
			t.Errorf("Status = %v when /tmp stat fails, want StatusError", f.Status)
		}
	} else if info.Mode()&os.ModeSticky != 0 {
		if f.Status != sdk.StatusCompliant {
			t.Errorf("Status = %v, want StatusCompliant", f.Status)
		}
	} else {
		if f.Status != sdk.StatusNonCompliant {
			t.Errorf("Status = %v, want StatusNonCompliant", f.Status)
		}
	}
}

func TestTmpStickyModule_Plan(t *testing.T) {
	mod := New()
	changes, err := mod.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan returned unexpected error: %v", err)
	}

	info, statErr := os.Stat("/tmp")
	if statErr != nil {
		return
	}

	if info.Mode()&os.ModeSticky != 0 {
		if len(changes) != 0 {
			t.Errorf("Plan returned %d changes for compliant system, want 0", len(changes))
		}
	} else {
		if len(changes) != 1 {
			t.Fatalf("Plan returned %d changes for non-compliant system, want 1", len(changes))
		}
		change := changes[0]
		if change.Description == "" {
			t.Error("Change description should not be empty")
		}
	}
}

func TestMainFunction(t *testing.T) {
	main()
}
