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
package updates

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
)

const (
	defaultAPTSourceList       = "/etc/apt/sources.list"
	defaultAPTSourcesListDir   = "/etc/apt/sources.list.d"
	defaultAPTAutoUpgradesPath = "/etc/apt/apt.conf.d/20auto-upgrades"
	defaultAPTUnattendedPath   = "/etc/apt/apt.conf.d/50unattended-upgrades"
	defaultAPTTrustedGPG       = "/etc/apt/trusted.gpg"
	defaultAPTTrustedGPGDir    = "/etc/apt/trusted.gpg.d"
	defaultUSRShareKeyringsDir = "/usr/share/keyrings"
	defaultDNFAutomaticConf    = "/etc/dnf/automatic.conf"
)

// Module implements automatic updates hardening checks.
type Module struct {
	familyOverride string

	aptSourcesListPath     string
	aptSourcesListDir      string
	aptAutoUpgradesPath    string
	aptUnattendedPath      string
	aptTrustedGPGPath      string
	aptTrustedGPGDir       string
	usrShareKeyringsDir    string
	dnfAutomaticConfigPath string
}

func (m *Module) Name() string    { return "updates" }
func (m *Module) Version() string { return "0.1.0" }

// Audit evaluates update hardening controls for Debian-family and RHEL-family hosts.
func (m *Module) Audit(_ context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	family := m.detectFamily(cfg)
	if family == "" {
		return []modules.Finding{
			newSkippedFinding(checkUPD001(), "unknown", "debian/rhel", "could not detect package-manager family"),
			newSkippedFinding(checkUPD002(), "unknown", "enabled", "could not detect package-manager family"),
			newSkippedFinding(checkUPD003(), "unknown", "configured", "could not detect package-manager family"),
			newSkippedFinding(checkUPD004(), "unknown", "configured", "could not detect package-manager family"),
			newSkippedFinding(checkUPD005(), "unknown", "optional", "check applies to apt sources only"),
		}, nil
	}

	findings := make([]modules.Finding, 0, 5)
	findings = append(findings, m.auditGPGKeys(family))
	findings = append(findings, m.auditSecurityRepo(family))
	findings = append(findings, m.auditUnattended(family))
	findings = append(findings, m.auditAutoReboot(family, cfgBool(cfg, "auto_reboot_after_kernel", false)))
	findings = append(findings, m.auditLocalMirror(family))

	return findings, nil
}

// Plan currently returns no changes; this module is audit-only in v0.1.
func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	_, err := m.Audit(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (m *Module) detectFamily(cfg modules.ModuleConfig) string {
	if f := strings.ToLower(strings.TrimSpace(cfgString(cfg, "family", m.familyOverride))); f != "" {
		switch f {
		case "debian", "apt", "ubuntu":
			return "debian"
		case "rhel", "dnf", "yum", "centos", "fedora", "rocky", "amzn", "almalinux":
			return "rhel"
		}
	}

	if fileExists(m.aptAutoPath()) || fileExists(m.aptUnattendedCfg()) || fileExists(m.aptSourcesPath()) {
		return "debian"
	}
	if fileExists(m.dnfAutomaticPath()) {
		return "rhel"
	}

	if dirHasEntries(m.aptSourcesDirPath()) {
		return "debian"
	}
	return ""
}

func (m *Module) auditGPGKeys(family string) modules.Finding {
	count := 0
	paths := make([]string, 0, 8)

	switch family {
	case "debian":
		for _, p := range []string{m.aptTrustedGPGPathValue(), m.aptTrustedGPGDirPath() + "/*.gpg", m.usrShareKeyringsPath() + "/*.gpg"} {
			paths = append(paths, expandPath(p)...)
		}
	case "rhel":
		paths = append(paths, expandPath("/etc/pki/rpm-gpg/RPM-GPG-KEY*")...)
	}

	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Size() > 0 {
			count++
		}
	}

	status := modules.StatusNonCompliant
	if count > 0 {
		status = modules.StatusCompliant
	}

	return modules.Finding{
		Check:   checkUPD001(),
		Status:  status,
		Current: fmt.Sprintf("%d non-empty key files", count),
		Target:  "at least 1 non-empty key file",
		Detail:  fmt.Sprintf("family=%s", family),
	}
}

func (m *Module) auditSecurityRepo(family string) modules.Finding {
	switch family {
	case "debian":
		hasSecurity, detail := hasDebianSecurityRepo(m.aptSourcesPath(), m.aptSourcesDirPath())
		return modules.Finding{
			Check:   checkUPD002(),
			Status:  complianceStatus(hasSecurity),
			Current: detail,
			Target:  "security repository enabled",
			Detail:  "parsed apt sources for security repositories",
		}
	case "rhel":
		cfg, err := parseKeyValueFile(m.dnfAutomaticPath())
		if err != nil {
			return newErrorFinding(checkUPD002(), "missing dnf automatic config", "upgrade_type=security", err)
		}
		upgradeType := strings.ToLower(strings.TrimSpace(cfg["upgrade_type"]))
		ok := upgradeType == "security"
		return modules.Finding{
			Check:   checkUPD002(),
			Status:  complianceStatus(ok),
			Current: valueOrMissing(upgradeType),
			Target:  "security",
			Detail:  "dnf-automatic upgrade_type should be security",
		}
	default:
		return newSkippedFinding(checkUPD002(), "unknown", "enabled", "unsupported package-manager family")
	}
}

func (m *Module) auditUnattended(family string) modules.Finding {
	switch family {
	case "debian":
		cfg, err := parseAptConfPairs(m.aptAutoPath())
		if err != nil {
			return newErrorFinding(checkUPD003(), "missing apt auto-upgrades config", "APT::Periodic::Unattended-Upgrade \"1\";", err)
		}
		val := strings.TrimSpace(cfg["apt::periodic::unattended-upgrade"])
		ok := val == "1"
		return modules.Finding{
			Check:   checkUPD003(),
			Status:  complianceStatus(ok),
			Current: valueOrMissing(val),
			Target:  "1",
			Detail:  "APT::Periodic::Unattended-Upgrade must be enabled",
		}
	case "rhel":
		cfg, err := parseKeyValueFile(m.dnfAutomaticPath())
		if err != nil {
			return newErrorFinding(checkUPD003(), "missing dnf automatic config", "apply_updates=yes", err)
		}
		val := strings.ToLower(strings.TrimSpace(cfg["apply_updates"]))
		ok := val == "yes" || val == "true" || val == "1"
		return modules.Finding{
			Check:   checkUPD003(),
			Status:  complianceStatus(ok),
			Current: valueOrMissing(val),
			Target:  "yes",
			Detail:  "dnf-automatic apply_updates should be enabled",
		}
	default:
		return newSkippedFinding(checkUPD003(), "unknown", "configured", "unsupported package-manager family")
	}
}

func (m *Module) auditAutoReboot(family string, targetEnabled bool) modules.Finding {
	target := "disabled"
	if targetEnabled {
		target = "enabled"
	}

	switch family {
	case "debian":
		cfg, err := parseAptConfPairs(m.aptUnattendedCfg())
		if err != nil {
			return newErrorFinding(checkUPD004(), "missing unattended-upgrades config", target, err)
		}
		current := strings.ToLower(strings.TrimSpace(cfg["unattended-upgrade::automatic-reboot"]))
		currentEnabled := current == "true" || current == "1" || current == "yes"
		return modules.Finding{
			Check:   checkUPD004(),
			Status:  complianceStatus(currentEnabled == targetEnabled),
			Current: boolLabel(currentEnabled),
			Target:  target,
			Detail:  "Unattended-Upgrade::Automatic-Reboot is configurable via module config",
		}
	case "rhel":
		cfg, err := parseKeyValueFile(m.dnfAutomaticPath())
		if err != nil {
			return newErrorFinding(checkUPD004(), "missing dnf automatic config", target, err)
		}
		current := strings.ToLower(strings.TrimSpace(cfg["reboot"]))
		currentEnabled := current == "when-needed" || current == "yes" || current == "true" || current == "1"
		return modules.Finding{
			Check:   checkUPD004(),
			Status:  complianceStatus(currentEnabled == targetEnabled),
			Current: boolLabel(currentEnabled),
			Target:  target,
			Detail:  "dnf-automatic reboot should match module config",
		}
	default:
		return newSkippedFinding(checkUPD004(), "unknown", target, "unsupported package-manager family")
	}
}

func (m *Module) auditLocalMirror(family string) modules.Finding {
	if family != "debian" {
		return newSkippedFinding(checkUPD005(), family, "optional", "check applies to apt sources only")
	}

	local, detail := hasLocalAPTSource(m.aptSourcesPath(), m.aptSourcesDirPath())
	status := modules.StatusManual
	if local {
		status = modules.StatusCompliant
	}
	return modules.Finding{
		Check:   checkUPD005(),
		Status:  status,
		Current: detail,
		Target:  "local mirror (optional)",
		Detail:  "informational check",
	}
}

func (m *Module) aptSourcesPath() string {
	if m.aptSourcesListPath != "" {
		return m.aptSourcesListPath
	}
	return defaultAPTSourceList
}

func (m *Module) aptSourcesDirPath() string {
	if m.aptSourcesListDir != "" {
		return m.aptSourcesListDir
	}
	return defaultAPTSourcesListDir
}

func (m *Module) aptAutoPath() string {
	if m.aptAutoUpgradesPath != "" {
		return m.aptAutoUpgradesPath
	}
	return defaultAPTAutoUpgradesPath
}

func (m *Module) aptUnattendedCfg() string {
	if m.aptUnattendedPath != "" {
		return m.aptUnattendedPath
	}
	return defaultAPTUnattendedPath
}

func (m *Module) aptTrustedGPGPathValue() string {
	if m.aptTrustedGPGPath != "" {
		return m.aptTrustedGPGPath
	}
	return defaultAPTTrustedGPG
}

func (m *Module) aptTrustedGPGDirPath() string {
	if m.aptTrustedGPGDir != "" {
		return m.aptTrustedGPGDir
	}
	return defaultAPTTrustedGPGDir
}

func (m *Module) usrShareKeyringsPath() string {
	if m.usrShareKeyringsDir != "" {
		return m.usrShareKeyringsDir
	}
	return defaultUSRShareKeyringsDir
}

func (m *Module) dnfAutomaticPath() string {
	if m.dnfAutomaticConfigPath != "" {
		return m.dnfAutomaticConfigPath
	}
	return defaultDNFAutomaticConf
}

func checkUPD001() modules.Check {
	return modules.Check{
		ID:       "upd-001",
		Title:    "Package manager GPG keys configured",
		Severity: modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "1.2.1"},
			{Framework: "NIST", Control: "SI-2"},
		},
	}
}

func checkUPD002() modules.Check {
	return modules.Check{
		ID:       "upd-002",
		Title:    "Security updates repository enabled",
		Severity: modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "1.2.2"},
			{Framework: "NIST", Control: "SI-2"},
		},
	}
}

func checkUPD003() modules.Check {
	return modules.Check{
		ID:       "upd-003",
		Title:    "Unattended security upgrades configured",
		Severity: modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "1.9"},
			{Framework: "NIST", Control: "SI-2"},
		},
	}
}

func checkUPD004() modules.Check {
	return modules.Check{
		ID:       "upd-004",
		Title:    "Auto-reboot after kernel updates (configurable)",
		Severity: modules.SeverityMedium,
	}
}

func checkUPD005() modules.Check {
	return modules.Check{
		ID:       "upd-005",
		Title:    "apt-get update via local mirror (optional)",
		Severity: modules.SeverityInfo,
	}
}

func hasDebianSecurityRepo(sourceListPath, sourceListDir string) (bool, string) {
	entries := make([]string, 0)
	for _, p := range append([]string{sourceListPath}, expandPath(filepath.Join(sourceListDir, "*.list"))...) {
		lines := readNonCommentLines(p)
		for _, line := range lines {
			if isAPTSourceLine(line) && strings.Contains(strings.ToLower(line), "security") {
				entries = append(entries, line)
			}
		}
	}
	if len(entries) == 0 {
		return false, "no security source entries found"
	}
	return true, fmt.Sprintf("%d security source entries", len(entries))
}

func hasLocalAPTSource(sourceListPath, sourceListDir string) (bool, string) {
	for _, p := range append([]string{sourceListPath}, expandPath(filepath.Join(sourceListDir, "*.list"))...) {
		lines := readNonCommentLines(p)
		for _, line := range lines {
			if !isAPTSourceLine(line) {
				continue
			}
			for _, tok := range strings.Fields(line) {
				if strings.HasPrefix(tok, "[") {
					continue
				}
				if !strings.Contains(tok, "://") && !strings.HasPrefix(tok, "file:") {
					continue
				}
				if isLocalMirrorToken(tok) {
					return true, fmt.Sprintf("local mirror source: %s", tok)
				}
				break
			}
		}
	}
	return false, "no local mirror source detected"
}

func isLocalMirrorToken(tok string) bool {
	if strings.HasPrefix(tok, "file:") {
		return true
	}
	u, err := url.Parse(tok)
	if err != nil || u.Hostname() == "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".lan") || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".corp") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	privateBlocks := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	for _, cidr := range privateBlocks {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseAptConfPairs(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSuffix(line, ";")
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.Trim(strings.Join(parts[1:], " "), "\"")
		out[key] = value
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseKeyValueFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.ToLower(strings.TrimSpace(parts[1]))
		out[key] = value
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func readNonCommentLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	out := make([]string, 0)
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func isAPTSourceLine(line string) bool {
	l := strings.TrimSpace(strings.ToLower(line))
	return strings.HasPrefix(l, "deb ") || strings.HasPrefix(l, "deb-src ")
}

func expandPath(pattern string) []string {
	if strings.ContainsAny(pattern, "*?[") {
		matches, _ := filepath.Glob(pattern)
		return matches
	}
	return []string{pattern}
}

func complianceStatus(ok bool) modules.Status {
	if ok {
		return modules.StatusCompliant
	}
	return modules.StatusNonCompliant
}

func boolLabel(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

func valueOrMissing(v string) string {
	if strings.TrimSpace(v) == "" {
		return "missing"
	}
	return v
}

func cfgString(cfg modules.ModuleConfig, key, fallback string) string {
	if cfg != nil {
		if val, ok := cfg[key]; ok {
			s, ok := val.(string)
			if ok {
				return s
			}
		}
	}
	return fallback
}

func cfgBool(cfg modules.ModuleConfig, key string, fallback bool) bool {
	if cfg != nil {
		if val, ok := cfg[key]; ok {
			if b, ok := val.(bool); ok {
				return b
			}
		}
	}
	return fallback
}

func newSkippedFinding(chk modules.Check, current, target, detail string) modules.Finding {
	return modules.Finding{Check: chk, Status: modules.StatusSkipped, Current: current, Target: target, Detail: detail}
}

func newErrorFinding(chk modules.Check, current, target string, err error) modules.Finding {
	return modules.Finding{Check: chk, Status: modules.StatusError, Current: current, Target: target, Detail: err.Error()}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirHasEntries(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

