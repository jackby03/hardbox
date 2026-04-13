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
	"fmt"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/services"
)

type fakeResult struct {
	out string
	err bool
}

func fakeRunner(results map[string]fakeResult) func(context.Context, string, ...string) (string, error) {
	return func(_ context.Context, name string, args ...string) (string, error) {
		key := strings.TrimSpace(name + " " + strings.Join(args, " "))
		res, ok := results[key]
		if !ok {
			// Default: service not found / inactive — treat as compliant.
			return "inactive", nil
		}
		if res.err {
			return res.out, fmt.Errorf("command failed: %s", key)
		}
		return res.out, nil
	}
}

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = services.NewModuleForTest(nil)
}

func TestModule_NameAndVersion(t *testing.T) {
	m := services.NewModuleForTest(nil)
	if m.Name() != "services" {
		t.Errorf("Name() = %q, want %q", m.Name(), "services")
	}
	if m.Version() == "" {
		t.Error("Version() should not be empty")
	}
}

func TestAudit_OnlyChecksServicesInDisableList(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active xinetd":  {out: "inactive"},
		"systemctl is-enabled xinetd": {out: "disabled"},
		"systemctl is-active telnet":  {out: "inactive"},
		"systemctl is-enabled telnet": {out: "disabled"},
	}))
	cfg := modules.ModuleConfig{"disable": []any{"xinetd", "telnet"}}

	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}
}

func TestAudit_DefaultCatalogUsedWhenNoDisableList(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{}))
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from default catalog, got none")
	}
}

func TestAudit_CompliantWhenInactiveAndDisabled(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active xinetd":  {out: "inactive"},
		"systemctl is-enabled xinetd": {out: "disabled"},
	}))
	cfg := modules.ModuleConfig{"disable": []any{"xinetd"}}

	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if findings[0].Status != modules.StatusCompliant {
		t.Errorf("status = %q, want compliant", findings[0].Status)
	}
}

func TestAudit_NonCompliantWhenActive(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active snmpd":  {out: "active"},
		"systemctl is-enabled snmpd": {out: "disabled"},
	}))
	cfg := modules.ModuleConfig{"disable": []any{"snmpd"}}

	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if findings[0].Status != modules.StatusNonCompliant {
		t.Errorf("active service should be non-compliant")
	}
}

func TestAudit_NonCompliantWhenEnabled(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active cups":  {out: "inactive"},
		"systemctl is-enabled cups": {out: "enabled"},
	}))
	cfg := modules.ModuleConfig{"disable": []any{"cups"}}

	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if findings[0].Status != modules.StatusNonCompliant {
		t.Errorf("enabled-only service should be non-compliant")
	}
}

func TestAudit_MixedList(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active xinetd":  {out: "inactive"},
		"systemctl is-enabled xinetd": {out: "disabled"},
		"systemctl is-active snmpd":   {out: "active"},
		"systemctl is-enabled snmpd":  {out: "enabled"},
		"systemctl is-active telnet":  {out: "inactive"},
		"systemctl is-enabled telnet": {out: "disabled"},
	}))
	cfg := modules.ModuleConfig{"disable": []any{"xinetd", "snmpd", "telnet"}}

	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(findings))
	}

	wantStatuses := []modules.Status{
		modules.StatusCompliant,
		modules.StatusNonCompliant,
		modules.StatusCompliant,
	}
	for i, want := range wantStatuses {
		if findings[i].Status != want {
			t.Errorf("findings[%d].Status = %q, want %q", i, findings[i].Status, want)
		}
	}
}

func TestAudit_CustomServiceNotInCatalog(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active my-custom-svc":  {out: "active"},
		"systemctl is-enabled my-custom-svc": {out: "enabled"},
	}))
	cfg := modules.ModuleConfig{"disable": []any{"my-custom-svc"}}

	findings, err := m.Audit(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if findings[0].Status != modules.StatusNonCompliant {
		t.Errorf("custom active service should be non-compliant")
	}
	if findings[0].Check.ID != "svc-custom" {
		t.Errorf("check ID = %q, want %q", findings[0].Check.ID, "svc-custom")
	}
}

func TestAudit_CatalogMetadata(t *testing.T) {
	cases := []struct {
		svc     string
		wantID  string
		wantSev modules.Severity
	}{
		{"telnet", "svc-018", modules.SeverityCritical},
		{"snmpd", "svc-016", modules.SeverityHigh},
		{"cups", "svc-004", modules.SeverityLow},
		{"bind", "svc-008", modules.SeverityHigh},
		{"named", "svc-008", modules.SeverityHigh}, // alias for bind
	}

	for _, tc := range cases {
		m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{}))
		cfg := modules.ModuleConfig{"disable": []any{tc.svc}}

		findings, err := m.Audit(context.Background(), cfg)
		if err != nil {
			t.Fatalf("[%s] Audit: %v", tc.svc, err)
		}
		if len(findings) != 1 {
			t.Fatalf("[%s] want 1 finding, got %d", tc.svc, len(findings))
		}
		if findings[0].Check.ID != tc.wantID {
			t.Errorf("[%s] ID = %q, want %q", tc.svc, findings[0].Check.ID, tc.wantID)
		}
		if findings[0].Check.Severity != tc.wantSev {
			t.Errorf("[%s] severity = %q, want %q", tc.svc, findings[0].Check.Severity, tc.wantSev)
		}
	}
}

func TestPlan_ReturnsChangeForNonCompliant(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{
		"systemctl is-active telnet":  {out: "active"},
		"systemctl is-enabled telnet": {out: "enabled"},
	}))
	cfg := modules.ModuleConfig{"disable": []any{"telnet"}}

	changes, err := m.Plan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("want 1 change, got %d", len(changes))
	}
	if !strings.Contains(changes[0].DryRunOutput, "telnet") {
		t.Errorf("DryRunOutput %q missing service name", changes[0].DryRunOutput)
	}
	if !strings.Contains(changes[0].DryRunOutput, "disable") {
		t.Errorf("DryRunOutput %q missing 'disable'", changes[0].DryRunOutput)
	}
}

func TestPlan_EmptyWhenAllCompliant(t *testing.T) {
	m := services.NewModuleForTest(fakeRunner(map[string]fakeResult{}))
	cfg := modules.ModuleConfig{"disable": []any{"xinetd", "cups", "snmpd"}}

	changes, err := m.Plan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("want 0 changes when all compliant, got %d", len(changes))
	}
}

