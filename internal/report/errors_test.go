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

package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/report"
)

func TestBuildWithErrors_IncludesFailedModule(t *testing.T) {
	findings := []modules.Finding{{
		Check:  modules.Check{ID: "ssh-001", Title: "Disable root login", Severity: modules.SeverityHigh},
		Status: modules.StatusCompliant,
	}}

	r := report.BuildWithErrors("sess", "cis-level1", findings,
		map[string]string{"boot": "reading /boot/grub/grub.cfg: permission denied"})

	if r.ModuleErrors["boot"] == "" {
		t.Fatal("module that failed to audit is absent from the report")
	}
	for _, m := range r.Modules {
		if m.Name == "boot" {
			t.Error("a module with no findings must not be added as a findings group")
		}
	}

	var buf bytes.Buffer
	if err := report.Write(r, "text", &buf); err != nil {
		t.Fatalf("render text: %v", err)
	}
	if !strings.Contains(buf.String(), "PARTIAL AUDIT") {
		t.Error("text report must flag a partial audit")
	}

	buf.Reset()
	if err := report.Write(r, "json", &buf); err != nil {
		t.Fatalf("render json: %v", err)
	}
	if !strings.Contains(buf.String(), `"module_errors"`) {
		t.Error("json report must serialise module_errors")
	}
}

// TestBuild_NoErrors verifies the backwards-compatible constructor still omits
// the error field entirely.
func TestBuild_NoErrors(t *testing.T) {
	findings := []modules.Finding{{
		Check:  modules.Check{ID: "ssh-001", Title: "x", Severity: modules.SeverityHigh},
		Status: modules.StatusCompliant,
	}}
	r := report.Build("sess", "p", findings)

	var buf bytes.Buffer
	if err := report.Write(r, "json", &buf); err != nil {
		t.Fatalf("render json: %v", err)
	}
	if strings.Contains(buf.String(), `"module_errors"`) {
		t.Error("no module_errors expected when no module failed")
	}
}
