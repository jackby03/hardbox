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
package storage

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
)

const crypttabPath = "/etc/crypttab"
const fstabPath = "/etc/fstab"

// Module implements storage encryption hardening checks.
type Module struct{}

func (m *Module) Name() string    { return "storage" }
func (m *Module) Version() string { return "1.0" }

// Audit evaluates LUKS and swap encryption status.
func (m *Module) Audit(ctx context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	var findings []modules.Finding
	findings = append(findings, m.checkLUKS())
	findings = append(findings, m.checkEncryptedSwap())
	findings = append(findings, m.checkCrypttabPerms())
	findings = append(findings, m.checkPlainSwap())
	findings = append(findings, m.checkDMCrypt())
	return findings, nil
}

// Plan generates remediation for storage encryption findings.
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
		case "stg-003":
			changes = append(changes, modules.Change{
				Description:  "Storage: restrict /etc/crypttab permissions",
				DryRunOutput: "  chmod 0600 /etc/crypttab",
				Apply: func() error {
					return os.Chmod(crypttabPath, 0o600)
				},
				Revert: func() error { return nil },
			})
		}
	}
	return changes, nil
}

func (m *Module) checkLUKS() modules.Finding {
	chk := checkSTG001()
	data, err := os.ReadFile(crypttabPath)
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "no crypttab", Target: "at least 1 encrypted partition", Detail: "/etc/crypttab not found"}
	}
	lines := strings.TrimSpace(string(data))
	hasEncrypted := false
	for _, line := range strings.Split(lines, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			hasEncrypted = true
			break
		}
	}
	if hasEncrypted {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "encrypted partitions configured", Target: "encrypted partitions present"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "no encrypted partitions", Target: "at least 1 encrypted partition"}
}

func (m *Module) checkEncryptedSwap() modules.Finding {
	chk := checkSTG002()
	data, err := os.ReadFile(crypttabPath)
	if err != nil {
		return m.checkSwapDisabled(chk)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(strings.ToLower(line), "swap") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "encrypted swap in crypttab", Target: "encrypted swap"}
		}
	}
	return m.checkSwapDisabled(chk)
}

func (m *Module) checkSwapDisabled(chk modules.Check) modules.Finding {
	data, err := os.ReadFile(fstabPath)
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusError, Detail: err.Error()}
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "swap") && strings.Contains(trimmed, "UUID=") {
			return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "plain swap in fstab", Target: "encrypted or no swap"}
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "no swap configured", Target: "encrypted or no swap"}
}

func (m *Module) checkCrypttabPerms() modules.Finding {
	chk := checkSTG003()
	info, err := os.Stat(crypttabPath)
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusSkipped, Detail: "crypttab not found"}
	}
	mode := info.Mode().Perm()
	if mode <= 0o600 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: fmt.Sprintf("%#o", mode), Target: "<= 0600"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: fmt.Sprintf("%#o", mode), Target: "<= 0600"}
}

func (m *Module) checkPlainSwap() modules.Finding {
	chk := checkSTG004()
	data, err := os.ReadFile(fstabPath)
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusError, Detail: err.Error()}
	}
	plainCount := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(strings.ToLower(line), "swap") && !strings.Contains(line, "mapper") {
			plainCount++
		}
	}
	if plainCount == 0 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: fmt.Sprintf("%d plain swap entries", plainCount), Target: "0"}
}

func (m *Module) checkDMCrypt() modules.Finding {
	chk := checkSTG005()
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return modules.Finding{Check: chk, Status: modules.StatusError, Detail: err.Error()}
	}
	if strings.Contains(string(data), "dm_crypt") {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "not loaded", Target: "dm_crypt loaded"}
}
