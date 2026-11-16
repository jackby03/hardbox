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

package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardbox-io/hardbox/internal/engine"
	"github.com/hardbox-io/hardbox/internal/modules"
)

// writingModule stands in for a real hardening module: its single change
// rewrites one existing file and creates another.
type writingModule struct {
	modify   string
	create   string
	observed bool
}

func (m *writingModule) Name() string    { return "writer" }
func (m *writingModule) Version() string { return "1.0" }

func (m *writingModule) Audit(context.Context, modules.ModuleConfig) ([]modules.Finding, error) {
	return []modules.Finding{{
		Check:  modules.Check{ID: "wr-001", Title: "config hardened", Severity: modules.SeverityHigh},
		Status: modules.StatusCompliant,
	}}, nil
}

func (m *writingModule) Plan(context.Context, modules.ModuleConfig) ([]modules.Change, error) {
	return []modules.Change{{
		Description: "writer: harden config",
		Files:       []string{m.modify, m.create},
		Apply: func() error {
			m.observed = true
			if err := os.WriteFile(m.modify, []byte("hardened\n"), 0o600); err != nil {
				return err
			}
			return os.WriteFile(m.create, []byte("created by apply\n"), 0o644)
		},
	}}, nil
}

// TestApplyThenRollback_RestoresFiles is the end-to-end regression test for
// rollback being a no-op: it drove Apply, then Rollback, and the system stayed
// hardened while rollback reported success.
func TestApplyThenRollback_RestoresFiles(t *testing.T) {
	snapshotDir := t.TempDir()
	restore := engine.SetSnapshotBaseDirForTest(snapshotDir)
	defer restore()

	work := t.TempDir()
	modify := filepath.Join(work, "sshd_config")
	if err := os.WriteFile(modify, []byte("PermitRootLogin yes\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	create := filepath.Join(work, "hardbox.conf")

	e := engine.NewEngineForTest(nil, &writingModule{modify: modify, create: create})

	if err := e.Apply(context.Background(), "", ""); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Precondition: apply really changed the system.
	after, err := os.ReadFile(modify)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "hardened\n" {
		t.Fatalf("apply did not run: %q", after)
	}
	if _, err := os.Stat(create); err != nil {
		t.Fatalf("apply did not create the new file: %v", err)
	}

	if err := e.Rollback(context.Background(), "", true); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	restored, err := os.ReadFile(modify)
	if err != nil {
		t.Fatalf("reading restored file: %v", err)
	}
	if string(restored) != "PermitRootLogin yes\n" {
		t.Errorf("rollback did not restore content, got %q", restored)
	}

	if _, err := os.Stat(create); !os.IsNotExist(err) {
		t.Errorf("rollback must remove files created by apply, stat err = %v", err)
	}
}
