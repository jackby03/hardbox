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

package webserver_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/webserver"
)

// writeFile creates dir/name with content and returns the path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// absent returns a path that does not exist, so a family the test is not
// exercising is reported as not installed instead of falling back to the host.
func absent(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent")
}

func find(t *testing.T, findings []modules.Finding, id string) modules.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			return f
		}
	}
	t.Fatalf("finding %s not found", id)
	return modules.Finding{}
}

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = &webserver.Module{}
}

// TestAudit_NoWebServer covers a host with no nginx and no Apache.
func TestAudit_NoWebServer(t *testing.T) {
	m := webserver.NewModuleForTest(absent(t), absent(t), absent(t), absent(t))

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 8 {
		t.Fatalf("want one finding per check, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Status != modules.StatusSkipped {
			t.Errorf("%s: want skipped with no web server installed, got %s", f.Check.ID, f.Status)
		}
	}
}

// TestAudit_NginxHardened covers a correctly configured nginx.
func TestAudit_NginxHardened(t *testing.T) {
	dir := t.TempDir()
	conf := writeFile(t, dir, "nginx.conf", `
http {
    server_tokens off;
    autoindex off;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy no-referrer-when-downgrade always;
}
`)
	m := webserver.NewModuleForTest(conf, absent(t), absent(t), absent(t))

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, id := range []string{"web-001", "web-002", "web-003", "web-004"} {
		if got := find(t, findings, id).Status; got != modules.StatusCompliant {
			t.Errorf("%s: want compliant, got %s", id, got)
		}
	}
	for _, id := range []string{"web-005", "web-006", "web-007", "web-008"} {
		if got := find(t, findings, id).Status; got != modules.StatusSkipped {
			t.Errorf("%s: want skipped without Apache, got %s", id, got)
		}
	}
}

// TestAudit_NginxWeak covers the failures each nginx check is meant to catch.
func TestAudit_NginxWeak(t *testing.T) {
	dir := t.TempDir()
	conf := writeFile(t, dir, "nginx.conf", `
server_tokens on;
autoindex on;
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
`)
	m := webserver.NewModuleForTest(conf, absent(t), absent(t), absent(t))

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if got := find(t, findings, "web-001").Status; got != modules.StatusNonCompliant {
		t.Errorf("web-001: want non-compliant for server_tokens on, got %s", got)
	}
	if got := find(t, findings, "web-002").Status; got != modules.StatusNonCompliant {
		t.Errorf("web-002: want non-compliant for autoindex on, got %s", got)
	}
	if got := find(t, findings, "web-003").Status; got != modules.StatusNonCompliant {
		t.Errorf("web-003: want non-compliant for TLSv1, got %s", got)
	}
	headers := find(t, findings, "web-004")
	if headers.Status != modules.StatusNonCompliant || !strings.Contains(headers.Current, "x-frame-options") {
		t.Errorf("web-004: want the missing headers named, got %s %q", headers.Status, headers.Current)
	}
}

// TestAudit_NginxCommentsAreIgnored guards the comment stripper: a commented-out
// directive must not satisfy a check.
func TestAudit_NginxCommentsAreIgnored(t *testing.T) {
	dir := t.TempDir()
	conf := writeFile(t, dir, "nginx.conf", `
# server_tokens off;
server_tokens on;
`)
	m := webserver.NewModuleForTest(conf, absent(t), absent(t), absent(t))

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if got := find(t, findings, "web-001").Status; got != modules.StatusNonCompliant {
		t.Errorf("a commented directive must not count as configured, got %s", got)
	}
}

func TestAudit_Apache(t *testing.T) {
	dir := t.TempDir()
	conf := writeFile(t, dir, "apache2.conf", `
ServerTokens Full
ServerSignature On
Options Indexes FollowSymLinks
SSLProtocol all -SSLv3
`)
	m := webserver.NewModuleForTest(absent(t), conf, absent(t), absent(t))

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if got := find(t, findings, "web-005").Status; got != modules.StatusNonCompliant {
		t.Errorf("web-005: want non-compliant, got %s", got)
	}
	if got := find(t, findings, "web-006").Status; got != modules.StatusNonCompliant {
		t.Errorf("web-006: want non-compliant for Options Indexes, got %s", got)
	}
	if got := find(t, findings, "web-007").Status; got != modules.StatusNonCompliant {
		t.Errorf("web-007: want non-compliant for 'all -SSLv3', got %s", got)
	}
	if got := find(t, findings, "web-008").Status; got != modules.StatusNonCompliant {
		t.Errorf("web-008: want non-compliant without headers, got %s", got)
	}
}

func TestAudit_ApacheHardened(t *testing.T) {
	dir := t.TempDir()
	conf := writeFile(t, dir, "apache2.conf", `
ServerTokens Prod
ServerSignature Off
Options -Indexes
SSLProtocol -all +TLSv1.2 +TLSv1.3
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Referrer-Policy "no-referrer-when-downgrade"
`)
	m := webserver.NewModuleForTest(absent(t), conf, absent(t), absent(t))

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, id := range []string{"web-005", "web-006", "web-007", "web-008"} {
		if got := find(t, findings, id).Status; got != modules.StatusCompliant {
			t.Errorf("%s: want compliant, got %s", id, got)
		}
	}
}

// TestSSLProtocolAllowsLegacy pins the evaluator, which string matching got
// wrong: "+TLSv1.2" leaves the defaults on, "-all +TLSv1.2 +TLSv1.3" does not.
func TestSSLProtocolAllowsLegacy(t *testing.T) {
	cases := map[string]bool{
		"all -SSLv3":                           true,
		"+TLSv1.2":                             true,
		"all":                                  true,
		"-all +TLSv1.2 +TLSv1.3":               false,
		"-all +TLSv1.3":                        false,
		"-all +TLSv1.1 +TLSv1.2":               true,
		"-all -SSLv3 -TLSv1 -TLSv1.1 +TLSv1.2": false,
	}
	for spec, want := range cases {
		if got := webserver.SSLProtocolAllowsLegacy(spec); got != want {
			t.Errorf("SSLProtocolAllowsLegacy(%q) = %v, want %v", spec, got, want)
		}
	}
}

// TestPlan_WritesBothDropIns covers remediation for both servers.
func TestPlan_WritesBothDropIns(t *testing.T) {
	dir := t.TempDir()
	nginx := writeFile(t, dir, "nginx.conf", "server_tokens on;\n")
	apache := writeFile(t, dir, "apache2.conf", "ServerTokens Full\n")
	nginxDrop := filepath.Join(dir, "99-nginx-hardbox.conf")
	apacheDrop := filepath.Join(dir, "99-apache-hardbox.conf")

	m := webserver.NewModuleForTest(nginx, apache, nginxDrop, apacheDrop)
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 2 {
		t.Fatalf("want one change per installed server, got %d", len(changes))
	}
	for _, c := range changes {
		if len(c.Files) != 1 {
			t.Fatalf("every change must declare its file, got %v", c.Files)
		}
		if err := c.Apply(); err != nil {
			t.Fatalf("Apply %q: %v", c.Description, err)
		}
	}

	nginxBody, err := os.ReadFile(nginxDrop)
	if err != nil {
		t.Fatalf("nginx drop-in: %v", err)
	}
	for _, want := range []string{"server_tokens off;", "X-Frame-Options", "ssl_protocols TLSv1.2 TLSv1.3;"} {
		if !strings.Contains(string(nginxBody), want) {
			t.Errorf("nginx drop-in missing %q:\n%s", want, nginxBody)
		}
	}

	apacheBody, err := os.ReadFile(apacheDrop)
	if err != nil {
		t.Fatalf("apache drop-in: %v", err)
	}
	for _, want := range []string{"ServerTokens Prod", "SSLProtocol -all +TLSv1.2 +TLSv1.3", "Header always set"} {
		if !strings.Contains(string(apacheBody), want) {
			t.Errorf("apache drop-in missing %q:\n%s", want, apacheBody)
		}
	}

	for _, c := range changes {
		if err := c.Revert(); err != nil {
			t.Fatalf("Revert: %v", err)
		}
	}
	for _, path := range []string{nginxDrop, apacheDrop} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("revert should remove %s, stat err = %v", path, err)
		}
	}
}

func TestPlan_NoChangesWhenHardened(t *testing.T) {
	dir := t.TempDir()
	conf := writeFile(t, dir, "nginx.conf", `
server_tokens off;
autoindex off;
ssl_protocols TLSv1.2 TLSv1.3;
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options DENY;
add_header Referrer-Policy no-referrer;
`)
	m := webserver.NewModuleForTest(conf, absent(t), filepath.Join(dir, "drop.conf"), absent(t))

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("want no changes, got %d", len(changes))
	}
}

// TestPlan_ApacheIndexesIsAuditOnly pins the documented exception: Apache accepts
// Options only inside a <Directory> block, and the document root is not knowable
// from the config alone.
func TestPlan_ApacheIndexesIsAuditOnly(t *testing.T) {
	dir := t.TempDir()
	apache := writeFile(t, dir, "apache2.conf", "Options Indexes\n")
	drop := filepath.Join(dir, "99-hardbox.conf")

	m := webserver.NewModuleForTest(absent(t), apache, absent(t), drop)
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, c := range changes {
		// Match the directive, not the bare word: the temp directory name contains
		// this test's name and therefore "Indexes".
		if strings.Contains(c.DryRunOutput, "Options -Indexes") || strings.Contains(c.DryRunOutput, "Options Indexes") {
			t.Errorf("directory listing must not be automated, got %q", c.DryRunOutput)
		}
	}
}

// TestExpandGlobs covers the resolver used to decide whether a server is present.
func TestExpandGlobs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.conf", "")
	writeFile(t, dir, "b.conf", "")

	if got := webserver.ExpandGlobs(filepath.Join(dir, "*.conf"), ""); len(got) != 2 {
		t.Errorf("want 2 matches, got %v", got)
	}
	if got := webserver.ExpandGlobs(absent(t), ""); len(got) != 0 {
		t.Errorf("missing path must resolve to nothing, got %v", got)
	}
}
