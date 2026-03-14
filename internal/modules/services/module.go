// Package services implements CIS Benchmark 2.x service-state hardening checks.
// It audits whether unnecessary network services are inactive and disabled,
// using systemctl to query active and enabled states.
package services

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
)

type commandRunner func(ctx context.Context, name string, args ...string) (string, error)

// svcEntry holds catalog metadata for a well-known service.
type svcEntry struct {
	unit     string           // canonical systemctl unit name
	id       string           // check ID (svc-001…svc-020)
	title    string           // human-readable check title
	severity modules.Severity // CIS-derived severity
	cisRef   string           // CIS control reference (e.g. "CIS 2.2.5")
}

// catalog maps service name aliases to hardbox check metadata.
var catalog = map[string]svcEntry{
	"xinetd":       {"xinetd", "svc-001", "xinetd (extended inetd) disabled", modules.SeverityHigh, "CIS 2.1.1"},
	"inetd":        {"inetd", "svc-002", "inetd super-server disabled", modules.SeverityHigh, "CIS 2.1.2"},
	"avahi-daemon": {"avahi-daemon", "svc-003", "Avahi mDNS daemon disabled", modules.SeverityMedium, "CIS 2.2.3"},
	"cups":         {"cups", "svc-004", "CUPS print server disabled", modules.SeverityLow, "CIS 2.2.4"},
	"dhcpd":        {"dhcpd", "svc-005", "DHCP server disabled", modules.SeverityHigh, "CIS 2.2.5"},
	"slapd":        {"slapd", "svc-006", "LDAP server (slapd) disabled", modules.SeverityHigh, "CIS 2.2.6"},
	"nfs-server":   {"nfs-server", "svc-007", "NFS server disabled", modules.SeverityHigh, "CIS 2.2.7"},
	"bind":         {"named", "svc-008", "DNS server (bind/named) disabled", modules.SeverityHigh, "CIS 2.2.8"},
	"named":        {"named", "svc-008", "DNS server (bind/named) disabled", modules.SeverityHigh, "CIS 2.2.8"},
	"vsftpd":       {"vsftpd", "svc-009", "FTP server (vsftpd) disabled", modules.SeverityHigh, "CIS 2.2.9"},
	"httpd":        {"httpd", "svc-010", "HTTP server (httpd) disabled", modules.SeverityMedium, "CIS 2.2.10"},
	"apache2":      {"apache2", "svc-010", "HTTP server (Apache2) disabled", modules.SeverityMedium, "CIS 2.2.10"},
	"nginx":        {"nginx", "svc-011", "HTTP server (nginx) disabled", modules.SeverityMedium, "CIS 2.2.11"},
	"dovecot":      {"dovecot", "svc-012", "IMAP/POP3 server (dovecot) disabled", modules.SeverityHigh, "CIS 2.2.12"},
	"sendmail":     {"sendmail", "svc-013", "Mail server (sendmail) disabled", modules.SeverityHigh, "CIS 2.2.13"},
	"samba":        {"smbd", "svc-014", "Samba file server disabled", modules.SeverityHigh, "CIS 2.2.14"},
	"squid":        {"squid", "svc-015", "Web proxy (squid) disabled", modules.SeverityMedium, "CIS 2.2.15"},
	"snmpd":        {"snmpd", "svc-016", "SNMP daemon disabled", modules.SeverityHigh, "CIS 2.2.16"},
	"nis":          {"ypbind", "svc-017", "NIS client (nis/ypbind) disabled", modules.SeverityHigh, "CIS 2.2.17"},
	"ypbind":       {"ypbind", "svc-017", "NIS client (nis/ypbind) disabled", modules.SeverityHigh, "CIS 2.2.17"},
	"telnet":       {"telnet", "svc-018", "Telnet server disabled", modules.SeverityCritical, "CIS 2.2.18"},
	"rsh-server":   {"rsh", "svc-019", "rsh/rlogin server disabled", modules.SeverityCritical, "CIS 2.2.18"},
	"rsync":        {"rsync", "svc-020", "rsync daemon disabled", modules.SeverityMedium, "CIS 2.2.20"},
}

// Module implements service-state hardening checks.
type Module struct {
	run commandRunner
}

func (m *Module) Name() string    { return "services" }
func (m *Module) Version() string { return "1.0" }

func (m *Module) runner() commandRunner {
	if m.run != nil {
		return m.run
	}
	return runCommand
}

// runCommand is the default production command runner.
func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output() //nolint:gosec
	return strings.TrimSpace(string(out)), err
}

// serviceList returns the ordered list of service names to audit.
// Config key "disable" ([]string or []any) takes precedence over the built-in catalog.
func serviceList(cfg modules.ModuleConfig) []string {
	if cfg != nil {
		if raw, ok := cfg["disable"]; ok {
			switch v := raw.(type) {
			case []string:
				if len(v) > 0 {
					return v
				}
			case []any:
				out := make([]string, 0, len(v))
				for _, item := range v {
					if s, ok := item.(string); ok {
						out = append(out, s)
					}
				}
				if len(out) > 0 {
					return out
				}
			}
		}
	}
	// Fall back to the full catalog (de-duplicated by name).
	out := make([]string, 0, len(catalog))
	for name := range catalog {
		out = append(out, name)
	}
	return out
}

// entryFor returns catalog metadata for svc, generating a generic entry for
// service names absent from the built-in catalog.
func entryFor(svc string) svcEntry {
	if e, ok := catalog[svc]; ok {
		return e
	}
	return svcEntry{
		unit:     svc,
		id:       "svc-custom",
		title:    fmt.Sprintf("Service %q disabled", svc),
		severity: modules.SeverityMedium,
		cisRef:   "CIS 2.x",
	}
}

// Audit checks whether each service in the disable list is both inactive
// (not running) and not enabled (will not start on boot).
func (m *Module) Audit(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Finding, error) {
	services := serviceList(cfg)
	run := m.runner()
	findings := make([]modules.Finding, 0, len(services))

	for _, svc := range services {
		entry := entryFor(svc)
		chk := modules.Check{
			ID:          entry.id,
			Title:       entry.title,
			Description: fmt.Sprintf("Service %q should not be running or enabled on this host.", svc),
			Remediation: fmt.Sprintf("Run: systemctl disable --now %s", entry.unit),
			Severity:    entry.severity,
			Compliance: []modules.ComplianceRef{
				{Framework: "CIS", Control: entry.cisRef},
			},
		}

		activeOut, _ := run(ctx, "systemctl", "is-active", entry.unit)
		enabledOut, _ := run(ctx, "systemctl", "is-enabled", entry.unit)
		isActive := activeOut == "active"
		isEnabled := enabledOut == "enabled"
		current := fmt.Sprintf("is-active=%s, is-enabled=%s", activeOut, enabledOut)

		if !isActive && !isEnabled {
			findings = append(findings, modules.Finding{
				Check:   chk,
				Status:  modules.StatusCompliant,
				Current: current,
				Target:  "inactive/disabled",
				Detail:  fmt.Sprintf("service %q is not running and not enabled", svc),
			})
		} else {
			findings = append(findings, modules.Finding{
				Check:   chk,
				Status:  modules.StatusNonCompliant,
				Current: current,
				Target:  "inactive/disabled",
				Detail:  fmt.Sprintf("service %q should be disabled; %s", svc, current),
			})
		}
	}

	return findings, nil
}

// Plan builds one reversible Change per non-compliant service.
// Apply runs `systemctl disable --now <unit>`.
// Revert re-enables and/or restarts the unit to its pre-apply state.
func (m *Module) Plan(ctx context.Context, cfg modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, cfg)
	if err != nil {
		return nil, err
	}

	services := serviceList(cfg)
	run := m.runner()
	changes := make([]modules.Change, 0, len(findings))

	for i, f := range findings {
		if f.IsCompliant() {
			continue
		}
		if i >= len(services) {
			continue
		}

		entry := entryFor(services[i])
		unit := entry.unit

		// Capture current state at plan time so Revert can restore it.
		prevActive, _ := run(ctx, "systemctl", "is-active", unit)
		prevEnabled, _ := run(ctx, "systemctl", "is-enabled", unit)

		changes = append(changes, modules.Change{
			Description:  fmt.Sprintf("services: disable %s (%s)", unit, entry.cisRef),
			DryRunOutput: fmt.Sprintf("systemctl disable --now %s", unit),
			Apply: func() error {
				out, err := exec.Command("systemctl", "disable", "--now", unit).CombinedOutput() //nolint:gosec
				if err != nil {
					return fmt.Errorf("services: disable %s: %w — %s", unit, err, strings.TrimSpace(string(out)))
				}
				return nil
			},
			Revert: func() error {
				if prevEnabled == "enabled" {
					exec.Command("systemctl", "enable", unit).Run() //nolint:gosec
				}
				if prevActive == "active" {
					exec.Command("systemctl", "start", unit).Run() //nolint:gosec
				}
				return nil
			},
		})
	}

	return changes, nil
}
