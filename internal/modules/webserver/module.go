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

// Package webserver audits nginx and Apache configuration.
//
// Both servers are config-file systems, so unlike the databases module almost
// everything here is remediable: the fixes are directives, and rollback can
// remove the drop-in file that carries them.
package webserver

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

const (
	// nginx reads conf.d from inside the http context on both families.
	defaultNginxGlobs = "/etc/nginx/nginx.conf,/etc/nginx/conf.d/*.conf,/etc/nginx/sites-enabled/*"
	// Apache: Debian keeps conf-enabled, RHEL keeps conf.d, both inside the server config.
	defaultApacheGlobs = "/etc/apache2/apache2.conf,/etc/apache2/conf-enabled/*.conf,/etc/apache2/sites-enabled/*.conf," +
		"/etc/httpd/conf/httpd.conf,/etc/httpd/conf.d/*.conf"

	defaultNginxDropIn        = "/etc/nginx/conf.d/99-hardbox.conf"
	defaultApacheDropInDebian = "/etc/apache2/conf-enabled/99-hardbox.conf"
	defaultApacheDropInRHEL   = "/etc/httpd/conf.d/99-hardbox.conf"

	// Header names checked by web-004 and web-008.
	hdrContentType = "x-content-type-options"
	hdrFrame       = "x-frame-options"
	hdrReferrer    = "referrer-policy"
)

// Module implements web server hardening checks.
type Module struct {
	nginxGlobs  string
	apacheGlobs string
	nginxDropIn string
	// apacheDropIn is the path written by remediation; empty means autodetect.
	apacheDropIn string
}

func (m *Module) Name() string    { return "webserver" }
func (m *Module) Version() string { return "1.0" }

func (m *Module) nginxFiles() []string {
	return expandGlobs(m.nginxGlobs, defaultNginxGlobs)
}

func (m *Module) apacheFiles() []string {
	return expandGlobs(m.apacheGlobs, defaultApacheGlobs)
}

func (m *Module) nginxPresent() bool  { return len(m.nginxFiles()) > 0 }
func (m *Module) apachePresent() bool { return len(m.apacheFiles()) > 0 }

func (m *Module) nginxConfigPath() string {
	if m.nginxDropIn != "" {
		return m.nginxDropIn
	}
	return defaultNginxDropIn
}

func (m *Module) apacheConfigPath() string {
	if m.apacheDropIn != "" {
		return m.apacheDropIn
	}
	if info, err := os.Stat("/etc/apache2/conf-enabled"); err == nil && info.IsDir() {
		return defaultApacheDropInDebian
	}
	return defaultApacheDropInRHEL
}

// expandGlobs resolves a comma-separated list of globs to existing files.
func expandGlobs(in, fallback string) []string {
	if in == "" {
		in = fallback
	}
	var out []string
	for _, pattern := range strings.Split(in, ",") {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.ContainsAny(pattern, "*?[") {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}
			out = append(out, matches...)
			continue
		}
		if _, err := os.Stat(pattern); err == nil {
			out = append(out, pattern)
		}
	}
	return out
}

// ── parsers ─────────────────────────────────────────────────────────────────

// stripComment removes an nginx/apache comment from a line, honouring neither
// quoting nor escaping beyond the common case: a '#' inside a quoted string is
// rare in these configs and treating it as a comment only makes the scan more
// conservative.
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// nginxStatements returns every directive statement across the given files, with
// whitespace collapsed. Continuation across lines is not handled: these configs
// are written one directive per line in practice.
func nginxStatements(files []string) []string {
	var out []string
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(stripComment(scanner.Text()))
			if line == "" {
				continue
			}
			for _, stmt := range strings.Split(line, ";") {
				stmt = strings.Join(strings.Fields(stmt), " ")
				if stmt != "" {
					out = append(out, stmt)
				}
			}
		}
		f.Close()
	}
	return out
}

// apacheDirective is one "Directive arg arg" line.
type apacheDirective struct{ name, args string }

func apacheDirectives(files []string) []apacheDirective {
	var out []apacheDirective
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(stripComment(scanner.Text()))
			if line == "" || strings.HasPrefix(line, "<") {
				continue
			}
			fields := strings.Fields(line)
			out = append(out, apacheDirective{
				name: strings.ToLower(fields[0]),
				args: strings.Join(fields[1:], " "),
			})
		}
		f.Close()
	}
	return out
}

// ── audit ───────────────────────────────────────────────────────────────────

func (m *Module) Audit(_ context.Context, _ modules.ModuleConfig) ([]modules.Finding, error) {
	findings := make([]modules.Finding, 0, 8)

	nginx := m.nginxPresent()
	apache := m.apachePresent()

	findings = append(findings, m.auditNginxTokens(nginx))
	findings = append(findings, m.auditNginxAutoindex(nginx))
	findings = append(findings, m.auditNginxTLS(nginx))
	findings = append(findings, m.auditNginxHeaders(nginx))
	findings = append(findings, m.auditApacheTokens(apache))
	findings = append(findings, m.auditApacheIndexes(apache))
	findings = append(findings, m.auditApacheTLS(apache))
	findings = append(findings, m.auditApacheHeaders(apache))

	return findings, nil
}

func notInstalled(chk modules.Check, server string) modules.Finding {
	return modules.Finding{
		Check:  chk,
		Status: modules.StatusSkipped,
		Detail: "no " + server + " configuration found",
	}
}

func (m *Module) auditNginxTokens(installed bool) modules.Finding {
	chk := checkWEB001()
	if !installed {
		return notInstalled(chk, "nginx")
	}
	for _, stmt := range nginxStatements(m.nginxFiles()) {
		lower := strings.ToLower(stmt)
		if strings.HasPrefix(lower, "server_tokens ") {
			value := strings.TrimSpace(strings.TrimPrefix(lower, "server_tokens "))
			if value == "off" {
				return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "off", Target: "off"}
			}
			return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: value, Target: "off"}
		}
	}
	return modules.Finding{
		Check:   chk,
		Status:  modules.StatusNonCompliant,
		Current: "not set",
		Target:  "off",
		Detail:  "server_tokens defaults to on, which advertises the nginx version",
	}
}

func (m *Module) auditNginxAutoindex(installed bool) modules.Finding {
	chk := checkWEB002()
	if !installed {
		return notInstalled(chk, "nginx")
	}
	var enabling []string
	seen := false
	for _, stmt := range nginxStatements(m.nginxFiles()) {
		lower := strings.ToLower(stmt)
		if !strings.HasPrefix(lower, "autoindex ") {
			continue
		}
		seen = true
		if strings.TrimSpace(strings.TrimPrefix(lower, "autoindex ")) == "on" {
			enabling = append(enabling, stmt)
		}
	}
	if len(enabling) > 0 {
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: fmt.Sprintf("%d autoindex on", len(enabling)),
			Target:  "autoindex off",
			Detail:  strings.Join(enabling, "\n"),
		}
	}
	current := "off (default)"
	if seen {
		current = "autoindex off"
	}
	return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: current, Target: "off"}
}

func (m *Module) auditNginxTLS(installed bool) modules.Finding {
	chk := checkWEB003()
	if !installed {
		return notInstalled(chk, "nginx")
	}
	for _, stmt := range nginxStatements(m.nginxFiles()) {
		lower := strings.ToLower(stmt)
		if !strings.HasPrefix(lower, "ssl_protocols ") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(lower, "ssl_protocols "))
		if strings.Contains(value, "tlsv1 ") || strings.HasSuffix(value, "tlsv1") ||
			strings.Contains(value, "tlsv1.1") || strings.Contains(value, "sslv") {
			return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: value, Target: "TLSv1.2 TLSv1.3"}
		}
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: value, Target: "TLSv1.2 TLSv1.3"}
	}
	return modules.Finding{
		Check:   chk,
		Status:  modules.StatusNonCompliant,
		Current: "not set",
		Target:  "TLSv1.2 TLSv1.3",
		Detail:  "ssl_protocols is not configured; the build default may still allow TLS 1.0 and 1.1",
	}
}

// headerSet returns the lower-cased header names present in the configuration.
func headerSet(names []string) map[string]bool {
	seen := make(map[string]bool)
	for _, n := range names {
		seen[strings.ToLower(n)] = true
	}
	return seen
}

func missingHeaders(seen map[string]bool) []string {
	var missing []string
	for _, h := range []string{hdrContentType, hdrFrame, hdrReferrer} {
		if !seen[h] {
			missing = append(missing, h)
		}
	}
	return missing
}

func (m *Module) auditNginxHeaders(installed bool) modules.Finding {
	chk := checkWEB004()
	if !installed {
		return notInstalled(chk, "nginx")
	}
	var names []string
	for _, stmt := range nginxStatements(m.nginxFiles()) {
		fields := strings.Fields(stmt)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "add_header") {
			names = append(names, fields[1])
		}
	}
	if missing := missingHeaders(headerSet(names)); len(missing) > 0 {
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: "missing " + strings.Join(missing, ", "),
			Target:  strings.Join([]string{hdrContentType, hdrFrame, hdrReferrer}, ", "),
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "all three set", Target: "all three set"}
}

func (m *Module) auditApacheTokens(installed bool) modules.Finding {
	chk := checkWEB005()
	if !installed {
		return notInstalled(chk, "Apache")
	}
	tokens, signature := "", ""
	for _, d := range apacheDirectives(m.apacheFiles()) {
		switch d.name {
		case "servertokens":
			tokens = d.args
		case "serversignature":
			signature = d.args
		}
	}
	tokensOK := strings.EqualFold(tokens, "prod")
	signatureOK := strings.EqualFold(signature, "off")
	if tokensOK && signatureOK {
		return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "ServerTokens Prod, ServerSignature Off", Target: "Prod / Off"}
	}
	current := fmt.Sprintf("ServerTokens=%s, ServerSignature=%s", orDefault(tokens, "not set"), orDefault(signature, "not set"))
	return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: current, Target: "Prod / Off"}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func (m *Module) auditApacheIndexes(installed bool) modules.Finding {
	chk := checkWEB006()
	if !installed {
		return notInstalled(chk, "Apache")
	}
	var enabling []string
	for _, d := range apacheDirectives(m.apacheFiles()) {
		if d.name != "options" {
			continue
		}
		for _, opt := range strings.Fields(d.args) {
			if strings.EqualFold(opt, "indexes") || strings.EqualFold(opt, "+indexes") {
				enabling = append(enabling, "Options "+d.args)
			}
		}
	}
	if len(enabling) > 0 {
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: fmt.Sprintf("%d Options Indexes", len(enabling)),
			Target:  "no Options Indexes",
			Detail:  strings.Join(enabling, "\n"),
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "no Options Indexes", Target: "no Options Indexes"}
}

func (m *Module) auditApacheTLS(installed bool) modules.Finding {
	chk := checkWEB007()
	if !installed {
		return notInstalled(chk, "Apache")
	}
	value := ""
	for _, d := range apacheDirectives(m.apacheFiles()) {
		if d.name == "sslprotocol" {
			value = d.args
		}
	}
	if value == "" {
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: "not set",
			Target:  "-all +TLSv1.2 +TLSv1.3",
			Detail:  "SSLProtocol is not configured; the default still enables TLS 1.0 and 1.1",
		}
	}
	if sslProtocolAllowsLegacy(value) {
		return modules.Finding{Check: chk, Status: modules.StatusNonCompliant, Current: value, Target: "-all +TLSv1.2 +TLSv1.3"}
	}
	return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: value, Target: "-all +TLSv1.2 +TLSv1.3"}
}

// sslProtocolAllowsLegacy evaluates an Apache SSLProtocol spec and reports
// whether TLS 1.0, TLS 1.1, SSLv2 or SSLv3 remain enabled.
//
// The spec is a set of +/- modifiers applied to a starting point, so string
// matching gets it wrong: "+TLSv1.2" alone still leaves the defaults enabled,
// while "-all +TLSv1.2 +TLSv1.3" does not.
func sslProtocolAllowsLegacy(spec string) bool {
	enabled := map[string]bool{
		"sslv2": true, "sslv3": true, "tlsv1": true, "tlsv1.1": true, "tlsv1.2": true, "tlsv1.3": true,
	}
	for _, token := range strings.Fields(spec) {
		t := strings.ToLower(token)
		switch {
		case t == "all":
			for k := range enabled {
				enabled[k] = true
			}
		case t == "-all":
			for k := range enabled {
				enabled[k] = false
			}
		case strings.HasPrefix(t, "+"):
			enabled[strings.TrimPrefix(t, "+")] = true
		case strings.HasPrefix(t, "-"):
			enabled[strings.TrimPrefix(t, "-")] = false
		}
	}
	return enabled["sslv2"] || enabled["sslv3"] || enabled["tlsv1"] || enabled["tlsv1.1"]
}

func (m *Module) auditApacheHeaders(installed bool) modules.Finding {
	chk := checkWEB008()
	if !installed {
		return notInstalled(chk, "Apache")
	}
	var names []string
	for _, d := range apacheDirectives(m.apacheFiles()) {
		if d.name != "header" {
			continue
		}
		// Header always set <name> <value>
		fields := strings.Fields(d.args)
		for i, f := range fields {
			if strings.EqualFold(f, "set") && i+1 < len(fields) {
				names = append(names, fields[i+1])
				break
			}
		}
	}
	if missing := missingHeaders(headerSet(names)); len(missing) > 0 {
		return modules.Finding{
			Check:   chk,
			Status:  modules.StatusNonCompliant,
			Current: "missing " + strings.Join(missing, ", "),
			Target:  strings.Join([]string{hdrContentType, hdrFrame, hdrReferrer}, ", "),
		}
	}
	return modules.Finding{Check: chk, Status: modules.StatusCompliant, Current: "all three set", Target: "all three set"}
}

// ── plan ────────────────────────────────────────────────────────────────────

// nginxDropInBody returns the directives needed to fix every non-compliant nginx
// check, or "" when nothing needs fixing.
func nginxDropInBody(findings []modules.Finding) string {
	var b strings.Builder
	b.WriteString("# Generated by hardbox — do not edit manually\n")
	for _, f := range findings {
		if f.IsCompliant() {
			continue
		}
		switch f.Check.ID {
		case "web-001":
			b.WriteString("server_tokens off;\n")
		case "web-002":
			b.WriteString("autoindex off;\n")
		case "web-003":
			b.WriteString("ssl_protocols TLSv1.2 TLSv1.3;\n")
		case "web-004":
			b.WriteString("add_header X-Content-Type-Options nosniff always;\n")
			b.WriteString("add_header X-Frame-Options SAMEORIGIN always;\n")
			b.WriteString("add_header Referrer-Policy no-referrer-when-downgrade always;\n")
		}
	}
	if b.Len() == len("# Generated by hardbox — do not edit manually\n") {
		return ""
	}
	return b.String()
}

func apacheDropInBody(findings []modules.Finding) string {
	var b strings.Builder
	b.WriteString("# Generated by hardbox — do not edit manually\n")
	for _, f := range findings {
		if f.IsCompliant() {
			continue
		}
		switch f.Check.ID {
		case "web-005":
			b.WriteString("ServerTokens Prod\nServerSignature Off\n")
		case "web-007":
			b.WriteString("SSLProtocol -all +TLSv1.2 +TLSv1.3\n")
		case "web-008":
			b.WriteString("<IfModule mod_headers.c>\n")
			b.WriteString("  Header always set X-Content-Type-Options \"nosniff\"\n")
			b.WriteString("  Header always set X-Frame-Options \"SAMEORIGIN\"\n")
			b.WriteString("  Header always set Referrer-Policy \"no-referrer-when-downgrade\"\n")
			b.WriteString("</IfModule>\n")
		}
	}
	if b.Len() == len("# Generated by hardbox — do not edit manually\n") {
		return ""
	}
	return b.String()
}

// Plan writes one drop-in per installed server. web-006 stays audit-only: Apache
// only accepts Options inside a <Directory> block, and guessing the document root
// is how a hardening tool breaks a site.
func (m *Module) Plan(ctx context.Context, _ modules.ModuleConfig) ([]modules.Change, error) {
	findings, err := m.Audit(ctx, nil)
	if err != nil {
		return nil, err
	}

	var changes []modules.Change

	if body := nginxDropInBody(findings); body != "" {
		path := m.nginxConfigPath()
		changes = append(changes, dropInChange("nginx", path, body))
	}
	if body := apacheDropInBody(findings); body != "" {
		path := m.apacheConfigPath()
		changes = append(changes, dropInChange("Apache", path, body))
	}

	return changes, nil
}

func dropInChange(server, path, body string) modules.Change {
	return modules.Change{
		Description:  fmt.Sprintf("Webserver: harden %s via %s", server, path),
		DryRunOutput: "  write " + path + ":\n" + indentBlock(body),
		Files:        []string{path},
		Apply: func() error {
			dir := filepath.Dir(path)
			if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
				return fmt.Errorf("webserver: %s does not exist; is %s installed?", dir, server)
			}
			// Atomic write: a truncated drop-in makes the server refuse to start.
			return util.AtomicWrite(path, []byte(body), 0o644)
		},
		Revert: func() error {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		},
	}
}

func indentBlock(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}
