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

package customchecks

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

// ModuleName is the name reported by the loaded custom checks module.
const ModuleName = "custom"

// Module evaluates operator-defined checks. It exists only when at least one
// check file was loaded, so a host without custom checks reports nothing extra.
type Module struct {
	checks []Check
	// root prefixes every absolute path, so tests can run against a temp dir.
	// Empty means the real filesystem.
	root      string
	sysctlDir string // default /proc/sys
}

// NewModule returns a module over the given checks.
func NewModule(checks []Check) *Module { return &Module{checks: checks} }

// NewModuleForTest is NewModule with an injectable root and sysctl directory.
func NewModuleForTest(checks []Check, root, sysctlDir string) *Module {
	return &Module{checks: checks, root: root, sysctlDir: sysctlDir}
}

func (m *Module) Name() string    { return ModuleName }
func (m *Module) Version() string { return "1.0" }

// Checks exposes the loaded definitions for `hardbox plugin list`-style output.
func (m *Module) Checks() []Check { return m.checks }

func (m *Module) resolve(path string) string {
	if m.root == "" {
		return path
	}
	return filepath.Join(m.root, path)
}

func (m *Module) sysctlPath(key string) string {
	dir := m.sysctlDir
	if dir == "" {
		dir = "/proc/sys"
	}
	return filepath.Join(dir, strings.ReplaceAll(key, ".", "/"))
}

// Audit evaluates every loaded check.
func (m *Module) Audit(_ context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	findings := make([]modules.Finding, 0, len(m.checks))
	for i := range m.checks {
		findings = append(findings, m.auditOne(&m.checks[i]))
	}
	return findings, nil
}

func (m *Module) auditOne(c *Check) modules.Finding {
	chk := c.toCheck()
	if c.Assert.File != nil {
		return m.auditFile(chk, c.Assert.File)
	}
	return m.auditSysctl(chk, c.Assert.Sysctl)
}

func (m *Module) auditFile(chk modules.Check, a *FileAssertion) modules.Finding {
	path := m.resolve(a.Path)

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			if a.Exists != nil && !*a.Exists {
				return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "absent", Target: "absent"}
			}
			return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "missing", Target: "present"}
		}
		return modules.Finding{Check: chk, Status: modules.StatusError, Current: "unreadable", Detail: err.Error()}
	}

	if a.Exists != nil && !*a.Exists {
		return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "present", Target: "absent"}
	}

	// Content assertions require reading the file.
	if a.Contains != "" || a.NotContains != "" || a.Equals != "" {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return modules.Finding{Check: chk, Status: modules.StatusError, Current: "unreadable", Detail: readErr.Error()}
		}
		content := string(data)
		switch {
		case a.Equals != "" && content != a.Equals:
			return modules.Finding{
				Check: chk, Status: modules.StatusNonCompliant,
				Current: "content differs", Target: "exact content",
			}
		case a.Contains != "" && !strings.Contains(content, a.Contains):
			return modules.Finding{
				Check: chk, Status: modules.StatusNonCompliant,
				Current: fmt.Sprintf("missing %q", a.Contains), Target: fmt.Sprintf("contains %q", a.Contains),
			}
		case a.NotContains != "" && strings.Contains(content, a.NotContains):
			return modules.Finding{
				Check: chk, Status: modules.StatusNonCompliant,
				Current: fmt.Sprintf("contains %q", a.NotContains), Target: fmt.Sprintf("does not contain %q", a.NotContains),
			}
		}
	}

	if a.Mode != "" {
		want, modeErr := ParseMode(a.Mode)
		if modeErr != nil {
			return modules.Finding{Check: chk, Status: modules.StatusError, Current: "invalid mode", Detail: modeErr.Error()}
		}
		if got := info.Mode().Perm(); got != want.Perm() {
			return modules.Finding{
				Check: chk, Status: modules.StatusNonCompliant,
				Current: fmt.Sprintf("%04o", got), Target: fmt.Sprintf("%04o", want.Perm()),
			}
		}
	}

	if a.Owner != "" {
		uid, ok := ownerUID(info)
		if !ok {
			return modules.Finding{
				Check:  chk,
				Status: modules.StatusManual,
				Detail: "ownership is not readable on this platform",
			}
		}
		wantUser, lookupErr := user.Lookup(a.Owner)
		if lookupErr != nil {
			return modules.Finding{
				Check: chk, Status: modules.StatusError,
				Current: "unknown owner", Detail: fmt.Sprintf("user %q: %v", a.Owner, lookupErr),
			}
		}
		if wantUID := parseUID(wantUser.Uid); wantUID != uid {
			return modules.Finding{
				Check: chk, Status: modules.StatusNonCompliant,
				Current: fmt.Sprintf("uid %d", uid), Target: a.Owner,
			}
		}
	}

	return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "as expected", Target: "as expected"}
}

func (m *Module) auditSysctl(chk modules.Check, a *SysctlAssertion) modules.Finding {
	data, err := os.ReadFile(m.sysctlPath(a.Key))
	if err != nil {
		if os.IsNotExist(err) {
			return modules.Finding{
				Check: chk, Status: modules.StatusNonCompliant,
				Current: "missing", Target: a.Equals,
			}
		}
		return modules.Finding{Check: chk, Status: modules.StatusError, Current: "unreadable", Detail: err.Error()}
	}
	got := strings.TrimSpace(string(data))
	if got == strings.TrimSpace(a.Equals) {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: got, Target: a.Equals}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: got, Target: a.Equals}
}

// Plan returns one change per remediable, non-compliant check.
func (m *Module) Plan(ctx context.Context, _ modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, nil)
	if err != nil {
		return nil, err
	}

	var changes []modules.Change
	for i, f := range findings {
		if f.IsCompliant() {
			continue
		}
		if i >= len(m.checks) {
			break
		}
		c := &m.checks[i]
		if c.AuditOnly || c.Remediate == nil || c.Remediate.Write == nil {
			continue
		}

		w := c.Remediate.Write
		path := m.resolve(w.Path)
		mode, modeErr := ParseMode(w.Mode)
		if modeErr != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, modeErr)
		}
		if mode == 0 {
			mode = 0o644
		}
		content := w.Content

		changes = append(changes, modules.Change{
			Description:  fmt.Sprintf("Custom: %s (%s)", c.Title, c.ID),
			DryRunOutput: "  write " + w.Path,
			Files:        []string{path},
			Apply: func() error {
				dir := filepath.Dir(path)
				if _, statErr := os.Stat(dir); statErr != nil {
					return fmt.Errorf("custom check %s: directory %s does not exist", c.ID, dir)
				}
				return util.AtomicWrite(path, []byte(content), mode.Perm())
			},
			Revert: func() error { return nil }, // the snapshot restores the previous content
		})
	}
	return changes, nil
}
