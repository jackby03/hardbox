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
// Package mount implements partition existence and kernel filesystem module checks.
// It covers dedicated partition checks (mnt-001..mnt-007) and kernel module
// blacklisting for unused filesystems (mnt-011..mnt-015).
// Mount option hardening (nodev, nosuid, noexec) is handled by the filesystem module.
package mount

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

const modprobePath = "/etc/modprobe.d/hardbox.conf"

// Module implements mount and partition hardening checks.
type Module struct {
	mountsPath  string // default: /proc/mounts; injectable for testing
	modprobeDir string // default: /etc/modprobe.d; injectable for testing
	lsmodOutput string // injectable for testing (replaces lsmod execution)
}

func (m *Module) Name() string    { return "mount" }
func (m *Module) Version() string { return "1.0" }

func (m *Module) procMounts() string {
	if m.mountsPath != "" {
		return m.mountsPath
	}
	return "/proc/mounts"
}

func (m *Module) modprobeConf() string {
	if m.modprobeDir != "" {
		return m.modprobeDir + "/hardbox.conf"
	}
	return modprobePath
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func (m *Module) Audit(_ context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	var findings []modules.Finding

	partFindings, err := m.auditPartitions()
	if err != nil {
		return nil, err
	}
	findings = append(findings, partFindings...)
	findings = append(findings, m.auditKernelModules()...)

	return findings, nil
}

// ── Partition existence checks (mnt-001..mnt-007) ────────────────────────────

func (m *Module) auditPartitions() ([]modules.Finding, error) {
	content, err := os.ReadFile(m.procMounts())
	if err != nil {
		if os.IsNotExist(err) {
			var findings []modules.Finding
			for _, spec := range partitionChecks() {
				findings = append(findings, modules.Finding{
					Check:  spec.check,
					Status: modules.StatusSkipped,
					Detail: "/proc/mounts not available",
				})
			}
			return findings, nil
		}
		return nil, fmt.Errorf("mount: read %s: %w", m.procMounts(), err)
	}

	mountPoints := parseMountPoints(content)
	var findings []modules.Finding

	for _, spec := range partitionChecks() {
		if mountPoints[spec.mountPoint] {
			findings = append(findings, modules.Finding{
				Check:   spec.check,
				Status:  modules.StatusCompliant,
				Current: spec.mountPoint + " has a dedicated partition",
				Target:  spec.mountPoint + " on dedicated partition",
			})
		} else {
			findings = append(findings, modules.Finding{
				Check:   spec.check,
				Status:  modules.StatusNonCompliant,
				Current: spec.mountPoint + " is not a separate mountpoint",
				Target:  spec.mountPoint + " on dedicated partition",
				Detail:  fmt.Sprintf("no dedicated partition found for %s in /proc/mounts", spec.mountPoint),
			})
		}
	}

	return findings, nil
}

// parseMountPoints returns the set of active mountpoints from /proc/mounts.
func parseMountPoints(data []byte) map[string]bool {
	result := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		result[fields[1]] = true
	}
	return result
}

// ── Kernel module blacklist checks (mnt-011..mnt-015) ─────────────────────────

func (m *Module) auditKernelModules() []modules.Finding {
	conf := m.readModprobeConf()
	loaded := m.loadedModules()
	var findings []modules.Finding

	for _, spec := range kernelModuleChecks() {
		blacklisted := isBlacklisted(conf, spec.moduleName)
		installFalse := hasInstallFalse(conf, spec.moduleName)
		isLoaded := loaded[normaliseModName(spec.moduleName)]

		switch {
		case isLoaded:
			// Module is currently loaded — non-compliant regardless of config.
			findings = append(findings, modules.Finding{
				Check:   spec.check,
				Status:  modules.StatusNonCompliant,
				Current: spec.moduleName + " is currently loaded",
				Target:  spec.moduleName + " disabled and not loaded",
				Detail:  "module is loaded; reboot required after blacklisting",
			})
		case blacklisted && installFalse:
			findings = append(findings, modules.Finding{
				Check:   spec.check,
				Status:  modules.StatusCompliant,
				Current: "blacklisted and install /bin/false",
				Target:  spec.moduleName + " disabled",
			})
		case blacklisted || installFalse:
			// Partial — only one of the two mitigations is in place.
			findings = append(findings, modules.Finding{
				Check:   spec.check,
				Status:  modules.StatusNonCompliant,
				Current: partialStatus(blacklisted, installFalse),
				Target:  "blacklisted and install /bin/false",
				Detail:  fmt.Sprintf("add both 'blacklist %s' and 'install %s /bin/false' to modprobe.d", spec.moduleName, spec.moduleName),
			})
		default:
			findings = append(findings, modules.Finding{
				Check:   spec.check,
				Status:  modules.StatusNonCompliant,
				Current: spec.moduleName + " is not blacklisted",
				Target:  spec.moduleName + " disabled",
				Detail:  fmt.Sprintf("add 'blacklist %s' and 'install %s /bin/false' to /etc/modprobe.d/hardbox.conf", spec.moduleName, spec.moduleName),
			})
		}
	}

	return findings
}

// readModprobeConf reads all *.conf files under /etc/modprobe.d/ and returns
// the combined content. Falls back to empty string if unreadable.
func (m *Module) readModprobeConf() string {
	dir := "/etc/modprobe.d"
	if m.modprobeDir != "" {
		dir = m.modprobeDir
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var sb strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		data, err := os.ReadFile(dir + "/" + e.Name())
		if err != nil {
			continue
		}
		sb.Write(data)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// loadedModules returns the set of currently-loaded kernel module names
// (normalised: hyphens replaced with underscores).
func (m *Module) loadedModules() map[string]bool {
	var output string
	if m.lsmodOutput != "" {
		output = m.lsmodOutput
	} else {
		out, err := exec.Command("lsmod").Output()
		if err != nil {
			return map[string]bool{}
		}
		output = string(out)
	}

	loaded := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(output))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			loaded[normaliseModName(fields[0])] = true
		}
	}
	return loaded
}

func normaliseModName(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}

func isBlacklisted(conf, module string) bool {
	norm := normaliseModName(module)
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "blacklist" && normaliseModName(fields[1]) == norm {
			return true
		}
	}
	return false
}

func hasInstallFalse(conf, module string) bool {
	norm := normaliseModName(module)
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		// install <module> /bin/false  (or /bin/true as alternative)
		if len(fields) >= 3 && fields[0] == "install" && normaliseModName(fields[1]) == norm {
			return strings.Contains(line, "/bin/false") || strings.Contains(line, "/bin/true")
		}
	}
	return false
}

func partialStatus(blacklisted, installFalse bool) string {
	if blacklisted {
		return "blacklisted but missing install /bin/false"
	}
	return "install /bin/false set but not blacklisted"
}

// ── Plan ──────────────────────────────────────────────────────────────────────

// Plan returns Changes to add kernel module blacklist entries.
// Partition creation cannot be automated — those findings are reported as manual.
func (m *Module) Plan(ctx context.Context, _ modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, nil)
	if err != nil {
		return nil, err
	}

	// Partition findings require manual intervention.
	partIDs := make(map[string]bool)
	for _, spec := range partitionChecks() {
		partIDs[spec.check.ID] = true
	}

	// Collect kernel modules that need blacklisting.
	specByID := make(map[string]kernelModuleCheckSpec)
	for _, spec := range kernelModuleChecks() {
		specByID[spec.check.ID] = spec
	}

	var toBlacklist []kernelModuleCheckSpec
	for _, f := range findings {
		if f.Status != modules.StatusNonCompliant {
			continue
		}
		if partIDs[f.Check.ID] {
			// Can't auto-remediate partition layout — skip.
			continue
		}
		if spec, ok := specByID[f.Check.ID]; ok {
			// Only remediate if module is not currently loaded.
			if !strings.Contains(f.Current, "currently loaded") {
				toBlacklist = append(toBlacklist, spec)
			}
		}
	}

	if len(toBlacklist) == 0 {
		return nil, nil
	}

	confPath := m.modprobeConf()

	// Read existing content (may not exist yet).
	existing, readErr := os.ReadFile(confPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("mount: read %s: %w", confPath, readErr)
	}
	fileExisted := readErr == nil

	var additions strings.Builder
	for _, spec := range toBlacklist {
		if !isBlacklisted(string(existing), spec.moduleName) {
			fmt.Fprintf(&additions, "blacklist %s\n", spec.moduleName)
		}
		if !hasInstallFalse(string(existing), spec.moduleName) {
			fmt.Fprintf(&additions, "install %s /bin/false\n", spec.moduleName)
		}
	}

	addText := additions.String()
	if addText == "" {
		return nil, nil
	}

	newContent := string(existing) + addText

	var dryRun strings.Builder
	fmt.Fprintf(&dryRun, "  append to %s:\n", confPath)
	for _, line := range strings.Split(strings.TrimSpace(addText), "\n") {
		fmt.Fprintf(&dryRun, "    %s\n", line)
	}

	return []modules.Change{{
		Description:  fmt.Sprintf("mount: blacklist %d kernel module(s) in %s", len(toBlacklist), confPath),
		DryRunOutput: strings.TrimRight(dryRun.String(), "\n"),
		Apply: func() error {
			return util.AtomicWrite(confPath, []byte(newContent), 0o644)
		},
		Revert: func() error {
			if !fileExisted {
				return os.Remove(confPath)
			}
			return util.AtomicWrite(confPath, existing, 0o644)
		},
	}}, nil
}

