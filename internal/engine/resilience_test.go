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
	"errors"
	"testing"

	"github.com/hardbox-io/hardbox/internal/engine"
	"github.com/hardbox-io/hardbox/internal/modules"
)

// failingModule is a module whose Audit always errors, standing in for a module
// that cannot read a required configuration file.
type failingModule struct{ name string }

func (m *failingModule) Name() string    { return m.name }
func (m *failingModule) Version() string { return "1.0" }

func (m *failingModule) Audit(context.Context, modules.ModuleConfig) ([]modules.Finding, error) {
	return nil, errors.New("reading /etc/example.conf: no such file or directory")
}

func (m *failingModule) Plan(context.Context, modules.ModuleConfig) ([]modules.Change, error) {
	return nil, errors.New("cannot plan without config")
}

// healthyModule returns a single compliant finding.
type healthyModule struct{ name string }

func (m *healthyModule) Name() string    { return m.name }
func (m *healthyModule) Version() string { return "1.0" }

func (m *healthyModule) Audit(context.Context, modules.ModuleConfig) ([]modules.Finding, error) {
	return []modules.Finding{{
		Check:  modules.Check{ID: "ok-001", Title: "fine", Severity: modules.SeverityLow},
		Status: modules.StatusCompliant,
	}}, nil
}

func (m *healthyModule) Plan(context.Context, modules.ModuleConfig) ([]modules.Change, error) {
	return nil, nil
}

// TestRunAudit_ModuleFailureDoesNotAbort is the regression test for the audit
// aborting on the first missing config file: one host without an SSH server
// produced no report at all.
func TestRunAudit_ModuleFailureDoesNotAbort(t *testing.T) {
	e := engine.NewEngineForTest(nil, &failingModule{name: "broken"}, &healthyModule{name: "ok"})

	rep, err := e.RunAudit(context.Background())
	if err != nil {
		t.Fatalf("audit must not fail because one module failed, got: %v", err)
	}

	if rep.ModuleErrors["broken"] == "" {
		t.Error("errored module must be reported as a partial audit")
	}
	if _, ok := rep.ModuleErrors["ok"]; ok {
		t.Error("healthy module must not be reported as failed")
	}

	found := 0
	for _, m := range rep.Modules {
		if m.Name == "ok" {
			found = len(m.Findings)
		}
	}
	if found != 1 {
		t.Errorf("healthy module findings were lost: got %d", found)
	}
}
