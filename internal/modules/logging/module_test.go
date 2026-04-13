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
package logging_test

import (
	"context"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/logging"
)

// ── helpers ───────────────────────────────────────────────────────────────────

type fakeResult struct {
	out string
	err bool
}

func fakeRunner(m map[string]fakeResult) func(ctx context.Context, name string, args ...string) (string, error) {
	return func(ctx context.Context, name string, args ...string) (string, error) {
		key := name + " " + strings.Join(args, " ")
		if r, ok := m[key]; ok {
			var err error
			if r.err {
				err = context.DeadlineExceeded
			}
			return r.out, err
		}
		return "", context.DeadlineExceeded
	}
}

func rsyslogActive() map[string]fakeResult {
	return map[string]fakeResult{
		"systemctl is-enabled rsyslog.service": {out: "enabled"},
		"systemctl is-active rsyslog.service":  {out: "active"},
	}
}

func noSyslogActive() map[string]fakeResult {
	return map[string]fakeResult{
		"systemctl is-enabled rsyslog.service":   {out: "disabled", err: true},
		"systemctl is-active rsyslog.service":    {out: "inactive", err: true},
		"systemctl is-enabled syslog-ng.service": {out: "disabled", err: true},
		"systemctl is-active syslog-ng.service":  {out: "inactive", err: true},
	}
}

func assertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Errorf("check %s: got status %q, want %q (current=%q)", id, f.Status, want, f.Current)
			}
			return
		}
	}
	t.Errorf("check %s: not found in findings", id)
}

// noLogrotate returns a path that doesn't exist.
func noLogrotate() string { return filepath.Join("testdata", "nonexistent_logrotate.conf") }

// ── interface ─────────────────────────────────────────────────────────────────

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = logging.NewModuleForTest(nil, "", "", "", "", "", "")
}

func TestModule_NameAndVersion(t *testing.T) {
	m := logging.NewModuleForTest(nil, "", "", "", "", "", "")
	if m.Name() != "logging" {
		t.Fatalf("Name(): got %q, want logging", m.Name())
	}
	if m.Version() == "" {
		t.Fatal("Version() should not be empty")
	}
}

// ── unit tests: pure helpers ──────────────────────────────────────────────────

func TestSetJournaldKey_ReplaceExisting(t *testing.T) {
	in := "[Journal]\nStorage=auto\nCompress=yes\n"
	got := logging.SetJournaldKey(in, "Storage", "persistent")
	if !strings.Contains(got, "Storage=persistent") {
		t.Errorf("expected Storage=persistent in output, got:\n%s", got)
	}
	if strings.Contains(got, "Storage=auto") {
		t.Errorf("old value should not remain, got:\n%s", got)
	}
}

func TestSetJournaldKey_ReplaceCommented(t *testing.T) {
	in := "[Journal]\n#Storage=auto\n"
	got := logging.SetJournaldKey(in, "Storage", "persistent")
	if !strings.Contains(got, "Storage=persistent") {
		t.Errorf("expected Storage=persistent in output, got:\n%s", got)
	}
}

func TestSetJournaldKey_AppendUnderSection(t *testing.T) {
	in := "[Journal]\nCompress=yes\n"
	got := logging.SetJournaldKey(in, "Storage", "persistent")
	if !strings.Contains(got, "Storage=persistent") {
		t.Errorf("expected Storage=persistent appended, got:\n%s", got)
	}
}

func TestRsyslogHasRemoteForwarding_True(t *testing.T) {
	content := "*.* @@logserver.example.com:514\n"
	if !logging.RsyslogHasRemoteForwarding(content) {
		t.Error("expected true for @@ forwarding")
	}
}

func TestRsyslogHasRemoteForwarding_False(t *testing.T) {
	content := "# @@commented out\nauth,authpriv.* /var/log/auth.log\n"
	if logging.RsyslogHasRemoteForwarding(content) {
		t.Error("expected false when forwarding only in comments")
	}
}

// ── audit: all compliant ──────────────────────────────────────────────────────

func TestAudit_AllCompliant(t *testing.T) {
	varLog := t.TempDir() // empty dir → no world-readable files

	m := logging.NewModuleForTest(
		fakeRunner(rsyslogActive()),
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"), // rsyslog.d not needed (main conf has remote)
		testutil.TestdataPath("journald_persistent.conf"),
		testutil.TestdataPath("rsyslog_remote.conf"), // reuse as logrotate.conf placeholder
		testutil.TestdataPath("nonexistent_dir"),
		varLog,
	)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	if len(findings) != 7 {
		t.Fatalf("expected 7 findings, got %d", len(findings))
	}

	assertStatus(t, findings, "log-001", modules.StatusCompliant)
	assertStatus(t, findings, "log-002", modules.StatusCompliant)
	assertStatus(t, findings, "log-004", modules.StatusCompliant)
	assertStatus(t, findings, "log-005", modules.StatusCompliant)
	assertStatus(t, findings, "log-006", modules.StatusCompliant)
	assertStatus(t, findings, "log-007", modules.StatusCompliant)
}

// ── audit: no syslog service ──────────────────────────────────────────────────

func TestAudit_NoSyslogService_LOG001NonCompliant(t *testing.T) {
	m := logging.NewModuleForTest(
		fakeRunner(noSyslogActive()),
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		testutil.TestdataPath("journald_persistent.conf"),
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		t.TempDir(),
	)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	assertStatus(t, findings, "log-001", modules.StatusNonCompliant)
}

// ── audit: no remote target ───────────────────────────────────────────────────

func TestAudit_LocalOnlyRsyslog_LOG002NonCompliant(t *testing.T) {
	m := logging.NewModuleForTest(
		fakeRunner(rsyslogActive()),
		testutil.TestdataPath("rsyslog_local.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		testutil.TestdataPath("journald_persistent.conf"),
		testutil.TestdataPath("rsyslog_local.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		t.TempDir(),
	)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	assertStatus(t, findings, "log-002", modules.StatusNonCompliant)
}

// ── audit: journald not persistent ───────────────────────────────────────────

func TestAudit_JournaldDefault_LOG004LOG005NonCompliant(t *testing.T) {
	m := logging.NewModuleForTest(
		fakeRunner(rsyslogActive()),
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		testutil.TestdataPath("journald_default.conf"),
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		t.TempDir(),
	)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	assertStatus(t, findings, "log-004", modules.StatusNonCompliant)
	assertStatus(t, findings, "log-005", modules.StatusNonCompliant)
}

// ── audit: no logrotate ───────────────────────────────────────────────────────

func TestAudit_NoLogrotate_LOG006NonCompliant(t *testing.T) {
	m := logging.NewModuleForTest(
		fakeRunner(rsyslogActive()),
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		testutil.TestdataPath("journald_persistent.conf"),
		noLogrotate(),
		testutil.TestdataPath("nonexistent_logrotate_dir"),
		t.TempDir(),
	)

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	assertStatus(t, findings, "log-006", modules.StatusNonCompliant)
}

// ── plan: writes journald keys when non-compliant ─────────────────────────────

func TestPlan_WritesJournaldKeys(t *testing.T) {
	dir := t.TempDir()
	journaldConfPath := filepath.Join(dir, "journald.conf")

	// Write a journald.conf without Storage or ForwardToSyslog
	if err := os.WriteFile(journaldConfPath, []byte("[Journal]\nCompress=yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := logging.NewModuleForTest(
		fakeRunner(rsyslogActive()),
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		journaldConfPath,
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		t.TempDir(),
	)

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}
	if len(changes) == 0 {
		t.Fatal("expected at least one change, got none")
	}

	// Apply all changes
	for i, ch := range changes {
		if err := ch.Apply(); err != nil {
			t.Fatalf("change[%d].Apply() error: %v", i, err)
		}
	}

	data, err := os.ReadFile(journaldConfPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "Storage=persistent") {
		t.Errorf("expected Storage=persistent in journald.conf, got:\n%s", content)
	}
	if !strings.Contains(content, "ForwardToSyslog=yes") {
		t.Errorf("expected ForwardToSyslog=yes in journald.conf, got:\n%s", content)
	}
}

// ── plan: revert restores original content ────────────────────────────────────

func TestPlan_Revert(t *testing.T) {
	dir := t.TempDir()
	journaldConfPath := filepath.Join(dir, "journald.conf")
	original := "[Journal]\nCompress=yes\n"

	if err := os.WriteFile(journaldConfPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	m := logging.NewModuleForTest(
		fakeRunner(rsyslogActive()),
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		journaldConfPath,
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		t.TempDir(),
	)

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}

	for _, ch := range changes {
		if err := ch.Apply(); err != nil {
			t.Fatalf("Apply() error: %v", err)
		}
	}
	for _, ch := range changes {
		if err := ch.Revert(); err != nil {
			t.Fatalf("Revert() error: %v", err)
		}
	}

	data, err := os.ReadFile(journaldConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Errorf("after revert got:\n%q\nwant:\n%q", string(data), original)
	}
}

// ── plan: already compliant returns no changes ────────────────────────────────

func TestPlan_AlreadyCompliant_NoChanges(t *testing.T) {
	m := logging.NewModuleForTest(
		fakeRunner(rsyslogActive()),
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		testutil.TestdataPath("journald_persistent.conf"),
		testutil.TestdataPath("rsyslog_remote.conf"),
		testutil.TestdataPath("nonexistent_dir"),
		t.TempDir(),
	)

	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan() error: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes when already compliant, got %d", len(changes))
	}
}
