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

package services_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/services"
)

// TestAudit_ExpectedServiceIsSkipped covers the reason services.expected exists:
// a profile that inherits cis-level1 also inherits "disable nginx", which would
// otherwise tell a web server to shut down its own web server.
func TestAudit_ExpectedServiceIsSkipped(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active nginx":   {out: "active"},
		"systemctl is-enabled nginx":  {out: "enabled"},
		"systemctl is-active xinetd":  {out: "inactive"},
		"systemctl is-enabled xinetd": {out: "disabled"},
	}))
	cfg := modules.ModuleConfig{
		"disable":  []any{"nginx", "xinetd"},
		"expected": []any{"nginx"},
	}

	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want one finding per listed service, got %d", len(findings))
	}

	var nginx *modules.Finding
	for i := range findings {
		if findings[i].Check.ID == "svc-011" {
			nginx = &findings[i]
		}
	}
	if nginx == nil {
		t.Fatal("nginx finding not found")
	}
	if nginx.Status != modules.StatusSkipped {
		t.Errorf("expected service must be skipped, got %q", nginx.Status)
	}
	if !strings.Contains(nginx.Detail, "expected") {
		t.Errorf("detail should explain the skip, got %q", nginx.Detail)
	}
	if !strings.Contains(nginx.Detail, "overrides") {
		t.Errorf("detail should say it overrides disable, got %q", nginx.Detail)
	}
}

// TestPlan_ExpectedServiceIsNotDisabled is the safety property that matters:
// plan must never emit a disable change for an expected service, even when the
// inherited baseline lists it under disable.
func TestPlan_ExpectedServiceIsNotDisabled(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active nginx":  {out: "active"},
		"systemctl is-enabled nginx": {out: "enabled"},
	}))
	cfg := modules.ModuleConfig{
		"disable":  []any{"nginx"},
		"expected": []any{"nginx"},
	}

	changes, err := m.Plan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("plan must not touch an expected service, got %d change(s)", len(changes))
	}
}

// TestPlan_DisablesNonExpectedService guards against over-suppression: a service
// that is not declared expected must still be disabled.
func TestPlan_DisablesNonExpectedService(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active telnet":  {out: "active"},
		"systemctl is-enabled telnet": {out: "enabled"},
		"systemctl is-active nginx":   {out: "active"},
		"systemctl is-enabled nginx":  {out: "enabled"},
	}))
	cfg := modules.ModuleConfig{
		"disable":  []any{"telnet", "nginx"},
		"expected": []any{"nginx"},
	}

	changes, err := m.Plan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected exactly one change (telnet), got %d", len(changes))
	}
	if !strings.Contains(changes[0].DryRunOutput, "telnet") {
		t.Errorf("wrong change selected: %q", changes[0].DryRunOutput)
	}
}

// TestAudit_ExpectedAliasMatchesUnit checks that declaring an alias suppresses
// the check for the canonical unit as well: bind and named are one service.
func TestAudit_ExpectedAliasMatchesUnit(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active named":  {out: "active"},
		"systemctl is-enabled named": {out: "enabled"},
	}))
	cfg := modules.ModuleConfig{
		"disable":  []any{"named"},
		"expected": []any{"bind"},
	}

	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != modules.StatusSkipped {
		t.Fatalf("bind must suppress the named check, got %+v", findings)
	}
}

// TestAudit_NoExpectedKeepsBehaviour guards the existing contract.
func TestAudit_NoExpectedKeepsBehaviour(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active nginx":  {out: "active"},
		"systemctl is-enabled nginx": {out: "enabled"},
	}))
	cfg := modules.ModuleConfig{"disable": []any{"nginx"}}

	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != modules.StatusNonCompliant {
		t.Fatalf("without expected, nginx must be non-compliant, got %+v", findings)
	}
}

// TestAudit_ExpectedOnlyAuditsRestOfCatalog covers a profile that sets expected
// but no disable list: the catalog fallback still applies, minus what is expected.
func TestAudit_ExpectedOnlyAuditsRestOfCatalog(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{}))
	cfg := modules.ModuleConfig{"expected": []any{"nginx"}}

	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	skipped := 0
	for _, f := range findings {
		if f.Status == modules.StatusSkipped {
			skipped++
		}
		if f.Check.ID == "svc-011" && f.Status != modules.StatusSkipped {
			t.Errorf("nginx must be skipped even without a disable list, got %q", f.Status)
		}
	}
	if skipped != 1 {
		t.Errorf("want exactly one skipped finding, got %d", skipped)
	}
}
