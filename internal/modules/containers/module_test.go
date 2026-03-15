package containers_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/containers"
)

// fakeResult holds canned output for a command invocation.
type fakeResult struct {
	out string
	err error
}

// fakeRunner builds a commandRunner returning canned output keyed by "cmd arg1 arg2...".
func fakeRunner(m map[string]fakeResult) func(ctx context.Context, name string, args ...string) (string, error) {
	return func(_ context.Context, name string, args ...string) (string, error) {
		key := name
		if len(args) > 0 {
			key += " " + strings.Join(args, " ")
		}
		if r, ok := m[key]; ok {
			return r.out, r.err
		}
		return "", nil
	}
}

// alwaysHasDocker simulates Docker being present on the system.
func alwaysHasDocker(name string) bool { return name == "docker" }

// neverHasDocker simulates Docker not being installed.
func neverHasDocker(_ string) bool { return false }

// secOptKey returns the full command key for the docker info security-options call.
func secOptKey() string {
	return "docker info --format " + containers.SecurityOptsFmt
}

// assertStatus fails the test when the named check does not match the expected status.
func assertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Errorf("check %s: got status %q, want %q (detail: %s)", id, f.Status, want, f.Detail)
			}
			return
		}
	}
	t.Errorf("check %s: not found in %d findings", id, len(findings))
}

// testdataPath returns the absolute path to a file in testdata/.
func testdataPath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("testdataPath(%q): %v", name, err)
	}
	return p
}

// emptyAuditDir creates a temporary directory with no .rules files.
func emptyAuditDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(t.TempDir(), "audit")
	if err != nil {
		t.Fatalf("emptyAuditDir: %v", err)
	}
	return dir
}

// ----------------------------------------------------------------------------
// Interface and metadata
// ----------------------------------------------------------------------------

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = containers.NewModuleForTest(nil, nil, "", "")
}

func TestModule_NameAndVersion(t *testing.T) {
	m := containers.NewModuleForTest(nil, nil, "", "")
	if m.Name() != "containers" {
		t.Fatalf("Name(): got %q, want %q", m.Name(), "containers")
	}
	if m.Version() == "" {
		t.Fatal("Version() must not be empty")
	}
}

// ----------------------------------------------------------------------------
// Docker not installed
// ----------------------------------------------------------------------------

func TestAudit_DockerNotInstalled(t *testing.T) {
	m := containers.NewModuleForTest(nil, neverHasDocker, "", "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	if len(findings) != 10 {
		t.Fatalf("expected 10 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Status != modules.StatusSkipped {
			t.Errorf("check %s: got %q, want skipped", f.Check.ID, f.Status)
		}
	}
}

// ----------------------------------------------------------------------------
// Plan is always a no-op
// ----------------------------------------------------------------------------

func TestPlan_ReturnsNoChanges(t *testing.T) {
	m := containers.NewModuleForTest(nil, nil, "", "")
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan(): %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("Plan(): expected 0 changes, got %d", len(changes))
	}
}

// ----------------------------------------------------------------------------
// cnt-001: rootless mode
// ----------------------------------------------------------------------------

func TestAudit_RootlessCompliant(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():      {out: "name=rootless\nname=apparmor\nname=seccomp,profile=default\n"},
			"docker ps -q":   {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_hardened.json"),
		testdataPath(t, "audit_rules"),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-001", modules.StatusCompliant)
}

func TestAudit_RootlessNonCompliant(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: "name=apparmor\nname=seccomp,profile=default\n"},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_hardened.json"),
		testdataPath(t, "audit_rules"),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-001", modules.StatusNonCompliant)
}

// ----------------------------------------------------------------------------
// cnt-002: ICC disabled
// ----------------------------------------------------------------------------

func TestAudit_ICCCompliant(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_hardened.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-002", modules.StatusCompliant)
}

func TestAudit_ICCNonCompliant(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-002", modules.StatusNonCompliant)
}

// ----------------------------------------------------------------------------
// cnt-003: userns-remap
// ----------------------------------------------------------------------------

func TestAudit_UsernsRemapCompliant(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_hardened.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-003", modules.StatusCompliant)
}

func TestAudit_UsernsRemapNonCompliant(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-003", modules.StatusNonCompliant)
}

// ----------------------------------------------------------------------------
// cnt-004: TLS for remote API
// ----------------------------------------------------------------------------

func TestAudit_TLSSkippedNoTCPHost(t *testing.T) {
	// daemon_hardened.json has only a unix:// host.
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_hardened.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-004", modules.StatusSkipped)
}

func TestAudit_TLSNonCompliantOnTCPHost(t *testing.T) {
	// daemon_tcp_no_tls.json has a TCP host but no TLS config.
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_tcp_no_tls.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-004", modules.StatusNonCompliant)
}

// ----------------------------------------------------------------------------
// cnt-005: seccomp, cnt-006: MAC profile
// ----------------------------------------------------------------------------

func TestAudit_SeccompAndMACNonCompliant(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: "name=cgroupns\n"}, // no seccomp, no apparmor/selinux
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-005", modules.StatusNonCompliant)
	assertStatus(t, findings, "cnt-006", modules.StatusNonCompliant)
}

func TestAudit_SeccompAndMACCompliant(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: "name=apparmor\nname=seccomp,profile=default\nname=cgroupns\n"},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-005", modules.StatusCompliant)
	assertStatus(t, findings, "cnt-006", modules.StatusCompliant)
}

// ----------------------------------------------------------------------------
// cnt-007: no privileged containers
// ----------------------------------------------------------------------------

func TestAudit_PrivilegedContainerFound(t *testing.T) {
	inspectKey := "docker inspect --format " + containers.PrivilegedFmt + " abc123"
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: "abc123"},
			inspectKey:     {out: "true"},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-007", modules.StatusNonCompliant)
}

func TestAudit_NoPrivilegedContainers(t *testing.T) {
	inspectKey := "docker inspect --format " + containers.PrivilegedFmt + " abc123"
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: "abc123"},
			inspectKey:     {out: "false"},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-007", modules.StatusCompliant)
}

// ----------------------------------------------------------------------------
// cnt-008: docker socket not mounted
// ----------------------------------------------------------------------------

func TestAudit_SocketMountFound(t *testing.T) {
	privKey := "docker inspect --format " + containers.PrivilegedFmt + " abc123"
	mntKey := "docker inspect --format " + containers.MountsFmt + " abc123"
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: "abc123"},
			privKey:        {out: "false"},
			mntKey:         {out: "/var/run/docker.sock /home/user/data "},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-008", modules.StatusNonCompliant)
}

func TestAudit_NoSocketMount(t *testing.T) {
	privKey := "docker inspect --format " + containers.PrivilegedFmt + " abc123"
	mntKey := "docker inspect --format " + containers.MountsFmt + " abc123"
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: "abc123"},
			privKey:        {out: "false"},
			mntKey:         {out: "/home/user/data "},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-008", modules.StatusCompliant)
}

// ----------------------------------------------------------------------------
// cnt-009: image scanning always manual
// ----------------------------------------------------------------------------

func TestAudit_ImageScanningAlwaysManual(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-009", modules.StatusManual)
}

// ----------------------------------------------------------------------------
// cnt-010: audit rules
// ----------------------------------------------------------------------------

func TestAudit_AuditRulePresent(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		testdataPath(t, "audit_rules"),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-010", modules.StatusCompliant)
}

func TestAudit_AuditRuleMissing(t *testing.T) {
	m := containers.NewModuleForTest(
		fakeRunner(map[string]fakeResult{
			secOptKey():    {out: ""},
			"docker ps -q": {out: ""},
		}),
		alwaysHasDocker,
		testdataPath(t, "daemon_default.json"),
		emptyAuditDir(t),
	)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): %v", err)
	}
	assertStatus(t, findings, "cnt-010", modules.StatusNonCompliant)
}
