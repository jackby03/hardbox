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

package ssh_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/ssh"
)

// TestAudit_MissingConfigIsSkipped covers a host with no OpenSSH server
// installed: the module must report every check as not applicable rather than
// returning an error that used to abort the whole audit.
func TestAudit_MissingConfigIsSkipped(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-sshd_config")
	m := ssh.NewModuleForTest(missing)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("missing sshd_config must not be an error, got: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected one finding per check, got none")
	}
	for _, f := range findings {
		if f.Status != modules.StatusSkipped {
			t.Errorf("%s: expected skipped, got %s", f.Check.ID, f.Status)
		}
		if !strings.Contains(f.Detail, "not present") {
			t.Errorf("%s: detail should explain why, got %q", f.Check.ID, f.Detail)
		}
	}
}

// TestPlan_MissingConfigProducesNoChanges ensures a host without sshd does not
// generate remediation for a config file that does not exist.
func TestPlan_MissingConfigProducesNoChanges(t *testing.T) {
	m := ssh.NewModuleForTest(filepath.Join(t.TempDir(), "no-such-sshd_config"))

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("plan must not error, got: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("expected no changes for an absent sshd_config, got %d", len(changes))
	}
}
