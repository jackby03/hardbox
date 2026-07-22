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
package boot

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
)

const (
	grubCfg    = "/boot/grub/grub.cfg"
	bootDir    = "/boot"
	grubPass   = "/boot/grub/user.cfg"
	efiVarPath = "/sys/firmware/efi/efivars/SecureBoot-*"
)

// Module implements bootloader hardening checks.
type Module struct{}

func (m *Module) Name() string    { return "boot" }
func (m *Module) Version() string { return "1.0" }

// Audit evaluates GRUB and boot security.
func (m *Module) Audit(ctx context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	var findings []modules.Finding

	findings = append(findings, m.checkGRUBPassword())
	findings = append(findings, m.checkSecureBoot())
	findings = append(findings, m.checkBootPerms())
	findings = append(findings, m.checkGRUBCfgPerms())
	findings = append(findings, m.checkKernelCmdline())

	return findings, nil
}

// Plan generates remediation for boot security findings.
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
		case "boot-003":
			changes = append(changes, modules.Change{
				Description:  "Boot: set /boot ownership and permissions",
				DryRunOutput: "  chown -R root:root /boot && chmod 755 /boot",
				Apply: func() error {
					if err := os.Chmod(bootDir, 0o755); err != nil {
						return err
					}
					return filepathWalk(bootDir, func(path string, info os.FileInfo) error {
						return os.Chmod(path, info.Mode()&0o755)
					})
				},
				Revert: func() error { return nil },
			})
		case "boot-004":
			changes = append(changes, modules.Change{
				Description:  "Boot: restrict grub.cfg to root only",
				DryRunOutput: "  chmod 0600 /boot/grub/grub.cfg",
				Apply: func() error {
					return os.Chmod(grubCfg, 0o600)
				},
				Revert: func() error { return nil },
			})
		case "boot-005":
			changes = append(changes, modules.Change{
				Description:  "Boot: add security params to GRUB cmdline",
				DryRunOutput: "  add audit=1 to GRUB_CMDLINE_LINUX in /etc/default/grub",
				Apply: func() error {
					return m.patchGrubDefault("audit=1")
				},
				Revert: func() error { return nil },
			})
		}
	}
	return changes, nil
}

func (m *Module) checkGRUBPassword() modules.Finding {
	chk := checkBOOT001()
	if _, err := os.Stat(grubPass); err == nil {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Detail: "/boot/grub/user.cfg exists"}
	}
	data, err := os.ReadFile("/etc/grub.d/40_custom")
	if err == nil && strings.Contains(string(data), "password_pbkdf2") {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Detail: "password_pbkdf2 found in 40_custom"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not set", Target: "password set"}
}

func (m *Module) checkSecureBoot() modules.Finding {
	chk := checkBOOT002()
	entries, err := os.ReadDir("/sys/firmware/efi/efivars")
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Current: "not UEFI", Target: "enabled", Detail: "system does not use UEFI"}
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "SecureBoot-") {
			data, err := os.ReadFile("/sys/firmware/efi/efivars/" + e.Name())
			if err == nil && len(data) > 4 && data[4] == 1 {
				return modules.Finding{Check: chk, Status: modules.StatusCompliant}
			}
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "disabled", Target: "enabled"}
}

func (m *Module) checkBootPerms() modules.Finding {
	chk := checkBOOT003()
	info, err := os.Stat(bootDir)
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusError, Detail: err.Error()}
	}
	mode := info.Mode().Perm()
	if mode <= 0o755 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: fmt.Sprintf("%#o", mode), Target: "<= 0755"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: fmt.Sprintf("%#o", mode), Target: "<= 0755"}
}

func (m *Module) checkGRUBCfgPerms() modules.Finding {
	chk := checkBOOT004()
	info, err := os.Stat(grubCfg)
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "grub.cfg not found: " + err.Error()}
	}
	mode := info.Mode().Perm()
	if mode <= 0o600 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: fmt.Sprintf("%#o", mode), Target: "<= 0600"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: fmt.Sprintf("%#o", mode), Target: "<= 0600"}
}

func (m *Module) checkKernelCmdline() modules.Finding {
	chk := checkBOOT005()
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusError, Detail: err.Error()}
	}
	cmdline := string(data)
	ok := strings.Contains(cmdline, "audit=1") || strings.Contains(cmdline, "audit=1 ")
	if ok {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "audit=1 present", Target: "audit=1 present"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "audit=1 missing", Target: "audit=1 present"}
}

func (m *Module) patchGrubDefault(param string) error {
	path := "/etc/default/grub"
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "GRUB_CMDLINE_LINUX=") {
			if !strings.Contains(line, param) {
				idx := strings.Index(line, "\"")
				if idx > 0 {
					lastQuote := strings.LastIndex(line, "\"")
					if lastQuote > idx {
						newLine := line[:lastQuote] + " " + param + line[lastQuote:]
						content = strings.ReplaceAll(content, line, newLine)
					}
				}
			}
			break
		}
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	_ = exec.Command("update-grub").Run()
	return nil
}

func filepathWalk(root string, fn func(string, os.FileInfo) error) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		info, _ := e.Info()
		_ = fn(root+"/"+e.Name(), info)
	}
	return nil
}
