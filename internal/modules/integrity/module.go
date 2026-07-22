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
package integrity

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hardbox-io/hardbox/internal/modules"
)

// Module implements file integrity monitoring checks (AIDE/Tripwire).
type Module struct{}

func (m *Module) Name() string    { return "integrity" }
func (m *Module) Version() string { return "1.0" }

func (m *Module) Audit(ctx context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	var findings []modules.Finding
	findings = append(findings, m.checkInstalled())
	findings = append(findings, m.checkDBInit())
	findings = append(findings, m.checkScheduled())
	findings = append(findings, m.checkRecentRun())
	findings = append(findings, m.checkConfigPerms())
	return findings, nil
}

func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, cfg)
	if err != nil {
		return nil, err
	}
	var changes []modules.Change
	for _, f := range findings {
		if f.IsCompliant() || f.Status == modules.StatusSkipped || f.Status == modules.StatusManual {
			continue
		}
		switch f.Check.ID {
		case "int-001":
			changes = append(changes, modules.Change{
				Description:  "Integrity: install AIDE",
				DryRunOutput: "  apt-get install -y aide",
				Apply: func() error {
					cmd := exec.CommandContext(ctx, "apt-get", "install", "-y", "aide")
					return cmd.Run()
				},
				Revert: func() error { return nil },
			})
		case "int-002":
			changes = append(changes, modules.Change{
				Description:  "Integrity: initialize AIDE database",
				DryRunOutput: "  aideinit && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
				Apply: func() error {
					if err := exec.CommandContext(ctx, "aideinit").Run(); err != nil {
						return err
					}
					_ = os.Rename("/var/lib/aide/aide.db.new", "/var/lib/aide/aide.db")
					return nil
				},
				Revert: func() error { return nil },
			})
		case "int-005":
			for _, p := range []string{"/etc/aide/aide.conf", "/etc/tripwire/tw.cfg"} {
				if _, err := os.Stat(p); err == nil {
					changes = append(changes, modules.Change{
						Description:  fmt.Sprintf("Integrity: restrict %s permissions", p),
						DryRunOutput: fmt.Sprintf("  chmod 0600 %s", p),
						Apply:       func() error { return os.Chmod(p, 0o600) },
						Revert:      func() error { return nil },
					})
				}
			}
		}
	}
	return changes, nil
}

func (m *Module) checkInstalled() modules.Finding {
	chk := checkINT001()
	for _, bin := range []string{"aide", "tripwire"} {
		if _, err := exec.LookPath(bin); err == nil {
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: bin, Target: "installed"}
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not installed", Target: "aide or tripwire installed"}
}

func (m *Module) checkDBInit() modules.Finding {
	chk := checkINT002()
	paths := []string{"/var/lib/aide/aide.db", "/var/lib/aide/aide.db.gz", "/var/lib/tripwire/db/"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: p, Target: "database exists"}
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "no database found", Target: "database initialized"}
}

func (m *Module) checkScheduled() modules.Finding {
	chk := checkINT003()
	cronPaths := []string{"/etc/cron.d/aide", "/etc/cron.daily/aide", "/etc/cron.weekly/aide", "/etc/systemd/system/aidecheck.timer", "/etc/systemd/system/aidecheck.service"}
	for _, p := range cronPaths {
		if _, err := os.Stat(p); err == nil {
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: p, Target: "scheduled"}
		}
	}
	data, _ := os.ReadFile("/etc/crontab")
	if strings.Contains(string(data), "aide") || strings.Contains(string(data), "tripwire") {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "crontab entry", Target: "scheduled"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not scheduled", Target: "cron or systemd timer"}
}

func (m *Module) checkRecentRun() modules.Finding {
	chk := checkINT004()
	reportPaths := []string{"/var/log/aide/", "/var/lib/tripwire/report/"}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for _, dir := range reportPaths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			info, _ := e.Info()
			if info.ModTime().After(cutoff) {
				return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: fmt.Sprintf("%s/%s", dir, e.Name()), Target: "recent run found"}
			}
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "no recent runs", Target: "last 7 days"}
}

func (m *Module) checkConfigPerms() modules.Finding {
	chk := checkINT005()
	for _, p := range []string{"/etc/aide/aide.conf", "/etc/tripwire/tw.cfg"} {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		mode := info.Mode().Perm()
		if mode <= 0o600 {
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: fmt.Sprintf("%s %#o", p, mode), Target: "<= 0600"}
		}
		return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: fmt.Sprintf("%s %#o", p, mode), Target: "<= 0600"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "no config file found"}
}
