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

// Package nameservices audits name resolution: /etc/hosts, /etc/nsswitch.conf and
// the configuration of whichever resolver the host runs.
package nameservices

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

const (
	defaultHostsPath    = "/etc/hosts"
	defaultNsswitchPath = "/etc/nsswitch.conf"
	defaultResolvPath   = "/etc/resolv.conf"
	defaultResolvedConf = "/etc/systemd/resolved.conf"
	defaultUnboundConf  = "/etc/unbound/unbound.conf"
	defaultDnsmasqConf  = "/etc/dnsmasq.conf"

	// canonical IPv6 loopback line; several families spell it differently.
	canonicalV6Loopback = "::1 localhost ip6-localhost ip6-loopback"
	canonicalV4Loopback = "127.0.0.1 localhost"
)

// Module implements name service hardening checks.
type Module struct {
	hostsPath    string
	nsswitchPath string
	resolvPath   string
	resolvedConf string
	unboundConf  string
	dnsmasqConf  string
}

func (m *Module) Name() string    { return "nameservices" }
func (m *Module) Version() string { return "1.0" }

func (m *Module) hosts() string {
	if m.hostsPath != "" {
		return m.hostsPath
	}
	return defaultHostsPath
}

func (m *Module) nsswitch() string {
	if m.nsswitchPath != "" {
		return m.nsswitchPath
	}
	return defaultNsswitchPath
}

func (m *Module) resolv() string {
	if m.resolvPath != "" {
		return m.resolvPath
	}
	return defaultResolvPath
}

func (m *Module) resolved() string {
	if m.resolvedConf != "" {
		return m.resolvedConf
	}
	return defaultResolvedConf
}

func (m *Module) unbound() string {
	if m.unboundConf != "" {
		return m.unboundConf
	}
	return defaultUnboundConf
}

func (m *Module) dnsmasq() string {
	if m.dnsmasqConf != "" {
		return m.dnsmasqConf
	}
	return defaultDnsmasqConf
}

// Audit inspects hosts, nsswitch and the resolver configuration.
func (m *Module) Audit(_ context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	return []modules.Finding{
		m.auditHostsLoopback(),
		m.auditHostsPermissions(),
		m.auditNsswitchOrder(),
		m.auditDNSSEC(),
		m.auditPlaintextDNS(),
	}, nil
}

// ── /etc/hosts ──────────────────────────────────────────────────────────────

// hostsEntries returns ip → lower-cased names for every active line.
func hostsEntries(path string) map[string][]string {
	entries := make(map[string][]string)
	f, err := os.Open(path)
	if err != nil {
		return entries
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		for _, name := range fields[1:] {
			entries[ip] = append(entries[ip], strings.ToLower(name))
		}
	}
	return entries
}

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

func hasName(names []string, want ...string) bool {
	for _, n := range names {
		for _, w := range want {
			if n == w {
				return true
			}
		}
	}
	return false
}

func (m *Module) auditHostsLoopback() modules.Finding {
	chk := checkDNS001()
	entries := hostsEntries(m.hosts())

	var missing []string
	if !hasName(entries["127.0.0.1"], "localhost") {
		missing = append(missing, "127.0.0.1 localhost")
	}
	// Some families use ip6-localhost or localhost6 instead of localhost.
	if !hasName(entries["::1"], "localhost", "ip6-localhost", "localhost6") {
		missing = append(missing, "::1 localhost")
	}

	if len(missing) == 0 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "both loopback mappings present", Target: "both present"}
	}
	return modules.Finding{
		Check:   chk,
		Status:  modules.StatusNonCompliant,
		Current: "missing " + strings.Join(missing, ", "),
		Target:  "both loopback mappings present",
	}
}

func (m *Module) auditHostsPermissions() modules.Finding {
	chk := checkDNS002()
	info, err := os.Stat(m.hosts())
	if err != nil {
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusError,
			Current: "unreadable",
			Detail:  err.Error(),
		}
	}
	mode := info.Mode().Perm()
	if mode&0o022 == 0 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: fmt.Sprintf("%04o", mode), Target: "0644"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: fmt.Sprintf("%04o", mode), Target: "0644"}
}

// ── /etc/nsswitch.conf ──────────────────────────────────────────────────────

// hostsLine returns the hosts entry from an nsswitch-style config, or "".
func hostsLine(content string) string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if strings.HasPrefix(strings.ToLower(line), "hosts:") {
			return line
		}
	}
	return ""
}

// filesBeforeDNS reports whether the hosts line consults files before dns.
func filesBeforeDNS(line string) (files, dns int, ok bool) {
	if line == "" {
		return -1, -1, false
	}
	tokens := strings.Fields(strings.TrimPrefix(strings.ToLower(line), "hosts:"))
	files, dns = -1, -1
	for i, t := range tokens {
		switch t {
		case "files":
			if files == -1 {
				files = i
			}
		case "dns":
			if dns == -1 {
				dns = i
			}
		}
	}
	return files, dns, true
}

func (m *Module) auditNsswitchOrder() modules.Finding {
	chk := checkDNS003()
	content, err := os.ReadFile(m.nsswitch())
	if err != nil {
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusError,
			Current: "unreadable",
			Detail:  err.Error(),
		}
	}
	line := hostsLine(string(content))
	files, dns, ok := filesBeforeDNS(line)
	if !ok {
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: "no hosts line",
			Target:  "files before dns",
		}
	}
	switch {
	case files == -1:
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: line,
			Target:  "files before dns",
			Detail:  "'files' does not appear, so /etc/hosts is never consulted",
		}
	case dns == -1:
		// files only: no DNS at all. That resolves names from hosts only, which is
		// a deliberate (if unusual) configuration and not a weakness.
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: line, Target: "files before dns"}
	case files < dns:
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: line, Target: "files before dns"}
	default:
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: line,
			Target:  "files before dns",
			Detail:  "dns precedes files, so a resolver answer overrides /etc/hosts",
		}
	}
}

// normalizeHostsLine reorders a hosts line so files precedes dns, preserving the
// other tokens.
func normalizeHostsLine(line string) string {
	trimmed := strings.TrimSpace(line)
	colon := strings.IndexByte(trimmed, ':')
	if colon < 0 {
		return line
	}
	tokens := strings.Fields(trimmed[colon+1:])
	var files, dns, rest []string
	for _, t := range tokens {
		switch strings.ToLower(t) {
		case "files":
			files = append(files, t)
		case "dns":
			dns = append(dns, t)
		default:
			rest = append(rest, t)
		}
	}
	out := append(append(append([]string{}, files...), dns...), rest...)
	return "hosts:          " + strings.Join(out, " ")
}

// ── resolver configuration ──────────────────────────────────────────────────

// configKeyValue returns key → value for a systemd-style config file.
func configKeyValue(path string) map[string]string {
	out := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return out
}

// readIfExists returns file content, or "" when it cannot be read.
func readIfExists(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func (m *Module) auditDNSSEC() modules.Finding {
	chk := checkDNS004()

	// systemd-resolved
	if resolved := configKeyValue(m.resolved()); len(resolved) > 0 {
		value := strings.ToLower(resolved["dnssec"])
		switch value {
		case "yes", "true", "allow-downgrade":
			if value == "allow-downgrade" {
				return modules.Finding{
					Check:   chk,
					Status:  modules.StatusNonCompliant,
					Current: "DNSSEC=allow-downgrade",
					Target:  "DNSSEC=yes",
					Detail:  "allow-downgrade silently falls back to unsigned answers when validation fails",
				}
			}
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "systemd-resolved DNSSEC=yes", Target: "validating resolver"}
		case "":
			return modules.Finding{
				Check:   chk,
				Status:  modules.StatusNonCompliant,
				Current: "systemd-resolved DNSSEC not set",
				Target:  "DNSSEC=yes",
				Detail:  "systemd-resolved defaults to DNSSEC=no",
			}
		default:
			return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "systemd-resolved DNSSEC=" + value, Target: "DNSSEC=yes"}
		}
	}

	// unbound
	if unbound := readIfExists(m.unbound()); unbound != "" {
		hasAnchor := strings.Contains(unbound, "auto-trust-anchor-file") || strings.Contains(unbound, "trust-anchor-file")
		permissive := strings.Contains(strings.ReplaceAll(unbound, " ", ""), "val-permissive-mode:yes")
		if hasAnchor && !permissive {
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "unbound validating", Target: "validating resolver"}
		}
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: "unbound without validation",
			Target:  "auto-trust-anchor-file",
		}
	}

	// dnsmasq
	if dnsmasq := readIfExists(m.dnsmasq()); dnsmasq != "" {
		enabled := false
		scanner := bufio.NewScanner(strings.NewReader(dnsmasq))
		for scanner.Scan() {
			line := strings.TrimSpace(stripComment(scanner.Text()))
			if line == "dnssec" || strings.HasPrefix(line, "dnssec,") || strings.HasPrefix(line, "trust-anchor=") {
				enabled = true
			}
		}
		if enabled {
			return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "dnsmasq dnssec", Target: "validating resolver"}
		}
		return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: "dnsmasq without dnssec", Target: "dnssec"}
	}

	return modules.Finding{
		Check:   chk,
		Status:  modules.StatusManual,
		Current: "no local resolver configuration found",
		Target:  "validating resolver",
		Detail:  "checked systemd-resolved, unbound and dnsmasq; verify DNSSEC validation of the resolver in use",
	}
}

// resolvNameservers returns the nameserver addresses from resolv.conf.
func resolvNameservers(content string) []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(stripComment(scanner.Text()))
		if len(fields) >= 2 && strings.EqualFold(fields[0], "nameserver") {
			out = append(out, fields[1])
		}
	}
	return out
}

func isLoopbackNS(ip string) bool {
	switch ip {
	case "127.0.0.1", "::1", "127.0.0.53", "127.0.0.54", "127.0.0.11":
		return true
	}
	return strings.HasPrefix(ip, "127.")
}

func (m *Module) auditPlaintextDNS() modules.Finding {
	chk := checkDNS005()
	servers := resolvNameservers(readIfExists(m.resolv()))
	if len(servers) == 0 {
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusManual,
			Current: "no nameserver entries",
			Detail:  "resolv.conf has no readable nameserver; resolution may be handled elsewhere",
		}
	}
	var external []string
	for _, s := range servers {
		if !isLoopbackNS(s) {
			external = append(external, s)
		}
	}
	if len(external) == 0 {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: strings.Join(servers, ", "), Target: "local resolver"}
	}
	return modules.Finding{
		Check:   chk,
		Status:  modules.StatusNonCompliant,
		Current: strings.Join(external, ", "),
		Target:  "local resolver",
		Detail:  "external nameservers receive unencrypted queries",
	}
}

// ── plan ────────────────────────────────────────────────────────────────────

// Plan fixes the three file-based checks. dns-004 and dns-005 stay audit-only:
// see docs/MODULES.md.
func (m *Module) Plan(ctx context.Context, _ modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, nil)
	if err != nil {
		return nil, err
	}

	var wantLoopback, wantPerms, wantNsswitch bool
	for _, f := range findings {
		if f.IsCompliant() {
			continue
		}
		switch f.Check.ID {
		case "dns-001":
			wantLoopback = true
		case "dns-002":
			wantPerms = true
		case "dns-003":
			wantNsswitch = true
		}
	}

	var changes []modules.Change
	hostsPath := m.hosts()

	if wantLoopback {
		changes = append(changes, modules.Change{
			Description:  "Nameservices: add missing localhost mappings to " + hostsPath,
			DryRunOutput: "  append the missing loopback entries (existing lines are preserved)",
			Files:        []string{hostsPath},
			Apply: func() error {
				content := readIfExists(hostsPath)
				entries := hostsEntries(hostsPath)
				var add []string
				if !hasName(entries["127.0.0.1"], "localhost") {
					add = append(add, canonicalV4Loopback)
				}
				if !hasName(entries["::1"], "localhost", "ip6-localhost", "localhost6") {
					add = append(add, canonicalV6Loopback)
				}
				if len(add) == 0 {
					return nil
				}
				if content != "" && !strings.HasSuffix(content, "\n") {
					content += "\n"
				}
				content += strings.Join(add, "\n") + "\n"
				return util.AtomicWrite(hostsPath, []byte(content), 0o644)
			},
			Revert: func() error { return nil }, // the snapshot restores the file
		})
	}

	if wantPerms {
		changes = append(changes, modules.Change{
			Description:  "Nameservices: restrict " + hostsPath + " to root:root 0644",
			DryRunOutput: "  chown root:root " + hostsPath + " && chmod 0644 " + hostsPath,
			Files:        []string{hostsPath},
			Apply: func() error {
				if err := os.Chmod(hostsPath, 0o644); err != nil {
					return err
				}
				return os.Chown(hostsPath, 0, 0)
			},
			Revert: func() error { return nil }, // the snapshot restores mode
		})
	}

	if wantNsswitch {
		path := m.nsswitch()
		changes = append(changes, modules.Change{
			Description:  "Nameservices: order hosts resolution as files before dns",
			DryRunOutput: "  set 'hosts:          files dns ...' in " + path,
			Files:        []string{path},
			Apply: func() error {
				content := readIfExists(path)
				if content == "" {
					return fmt.Errorf("nameservices: %s is empty or unreadable", path)
				}
				lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
				found := false
				for i, line := range lines {
					if strings.HasPrefix(strings.ToLower(strings.TrimSpace(stripComment(line))), "hosts:") {
						lines[i] = normalizeHostsLine(line)
						found = true
						break
					}
				}
				if !found {
					lines = append(lines, "hosts:          files dns")
				}
				return util.AtomicWrite(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
			},
			Revert: func() error { return nil }, // the snapshot restores the file
		})
	}
	return changes, nil
}
