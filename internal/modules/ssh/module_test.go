package ssh_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/ssh"
)

// writeTempConfig writes content to a temp sshd_config file and returns a cleanup func.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeTempConfig: %v", err)
	}
	return path
}

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = &ssh.Module{}
}

func TestModule_NameAndVersion(t *testing.T) {
	m := &ssh.Module{}
	if m.Name() != "ssh" {
		t.Fatalf("Name(): got %q, want ssh", m.Name())
	}
	if m.Version() == "" {
		t.Fatal("Version() should not be empty")
	}
}

func TestParseSshdConfig(t *testing.T) {
	input := []byte(`
# comment
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
X11Forwarding no
`)
	parsed := ssh.ParseSshdConfigForTest(input)
	cases := map[string]string{
		"permitrootlogin":        "no",
		"passwordauthentication": "no",
		"maxauthtries":           "3",
		"x11forwarding":          "no",
	}
	for k, want := range cases {
		if got := parsed[k]; got != want {
			t.Errorf("parsed[%q] = %q, want %q", k, got, want)
		}
	}
}

// compliantConfig contains all 17 required settings in compliant form.
const compliantConfig = `PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 3
AllowUsers admin
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256
LogLevel VERBOSE
IgnoreRhosts yes
StrictModes yes
PermitEmptyPasswords no
MaxSessions 4
Port 2222
`

func runAuditOnConfig(t *testing.T, configContent string) []modules.Finding {
	t.Helper()
	path := writeTempConfig(t, configContent)
	m := ssh.NewModuleForTest(path)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("Audit(): unexpected error: %v", err)
	}
	return findings
}

func assertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Errorf("check %s: got %s, want %s (current=%q)", id, f.Status, want, f.Current)
			}
			return
		}
	}
	t.Errorf("check %s: not found in findings", id)
}

func TestAudit_AllCompliant(t *testing.T) {
	findings := runAuditOnConfig(t, compliantConfig)
	if len(findings) != 17 {
		t.Fatalf("expected 17 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Status != modules.StatusCompliant {
			t.Errorf("check %s: expected compliant, got %s (current=%q)", f.Check.ID, f.Status, f.Current)
		}
	}
}

func TestAudit_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		config  string
		checkID string
		want    modules.Status
	}{
		{
			name:    "ssh-001 root login enabled",
			config:  "PermitRootLogin yes\n",
			checkID: "ssh-001",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-002 password auth enabled",
			config:  "PasswordAuthentication yes\n",
			checkID: "ssh-002",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-003 MaxAuthTries too high",
			config:  "MaxAuthTries 10\n",
			checkID: "ssh-003",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-003 MaxAuthTries compliant",
			config:  "MaxAuthTries 4\n",
			checkID: "ssh-003",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-004 LoginGraceTime 0 (unlimited - non-compliant)",
			config:  "LoginGraceTime 0\n",
			checkID: "ssh-004",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-004 LoginGraceTime too high",
			config:  "LoginGraceTime 120\n",
			checkID: "ssh-004",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-004 LoginGraceTime compliant",
			config:  "LoginGraceTime 60\n",
			checkID: "ssh-004",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-005 X11 enabled",
			config:  "X11Forwarding yes\n",
			checkID: "ssh-005",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-006 TCP forwarding enabled",
			config:  "AllowTcpForwarding yes\n",
			checkID: "ssh-006",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-006 TCP forwarding disabled",
			config:  "AllowTcpForwarding no\n",
			checkID: "ssh-006",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-007 ClientAlive not set",
			config:  "",
			checkID: "ssh-007",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-007 ClientAlive interval too high",
			config:  "ClientAliveInterval 600\nClientAliveCountMax 3\n",
			checkID: "ssh-007",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-007 ClientAlive compliant",
			config:  "ClientAliveInterval 300\nClientAliveCountMax 3\n",
			checkID: "ssh-007",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-008 no AllowUsers or AllowGroups",
			config:  "",
			checkID: "ssh-008",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-008 AllowGroups set",
			config:  "AllowGroups sshusers\n",
			checkID: "ssh-008",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-008 AllowUsers set",
			config:  "AllowUsers admin\n",
			checkID: "ssh-008",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-009 arcfour exact match (not as substring)",
			config:  "Ciphers chacha20-poly1305@openssh.com,arcfour\n",
			checkID: "ssh-009",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-009 weak cipher present",
			config:  "Ciphers aes256-ctr,aes128-cbc\n",
			checkID: "ssh-009",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-009 strong ciphers only",
			config:  "Ciphers chacha20-poly1305@openssh.com,aes256-ctr\n",
			checkID: "ssh-009",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-009 ciphers not configured",
			config:  "",
			checkID: "ssh-009",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-010 weak MAC present",
			config:  "MACs hmac-sha2-256,hmac-md5\n",
			checkID: "ssh-010",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-010 strong MACs only",
			config:  "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256\n",
			checkID: "ssh-010",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-011 gss prefix kex present (non-compliant)",
			config:  "KexAlgorithms curve25519-sha256,gss-group1-sha1-tohost\n",
			checkID: "ssh-011",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-011 weak kex present",
			config:  "KexAlgorithms curve25519-sha256,diffie-hellman-group1-sha1\n",
			checkID: "ssh-011",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-011 strong kex only",
			config:  "KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256\n",
			checkID: "ssh-011",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-012 LogLevel INFO",
			config:  "LogLevel INFO\n",
			checkID: "ssh-012",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-012 LogLevel VERBOSE",
			config:  "LogLevel VERBOSE\n",
			checkID: "ssh-012",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-013 IgnoreRhosts disabled",
			config:  "IgnoreRhosts no\n",
			checkID: "ssh-013",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-013 IgnoreRhosts enabled",
			config:  "IgnoreRhosts yes\n",
			checkID: "ssh-013",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-014 StrictModes no",
			config:  "StrictModes no\n",
			checkID: "ssh-014",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-014 StrictModes yes",
			config:  "StrictModes yes\n",
			checkID: "ssh-014",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-015 empty passwords allowed",
			config:  "PermitEmptyPasswords yes\n",
			checkID: "ssh-015",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-016 MaxSessions too high",
			config:  "MaxSessions 20\n",
			checkID: "ssh-016",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-016 MaxSessions compliant",
			config:  "MaxSessions 10\n",
			checkID: "ssh-016",
			want:    modules.StatusCompliant,
		},
		{
			name:    "ssh-017 default port 22",
			config:  "Port 22\n",
			checkID: "ssh-017",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-017 no port configured",
			config:  "",
			checkID: "ssh-017",
			want:    modules.StatusNonCompliant,
		},
		{
			name:    "ssh-017 non-default port",
			config:  "Port 2222\n",
			checkID: "ssh-017",
			want:    modules.StatusCompliant,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := runAuditOnConfig(t, tc.config)
			assertStatus(t, findings, tc.checkID, tc.want)
		})
	}
}

// TestPlan_Apply_Revert exercises the full Plan→Apply→Revert cycle using a
// temporary sshd_config, verifying that AtomicWrite integration works correctly.
func TestPlan_Apply_Revert(t *testing.T) {
	cases := []struct {
		name        string
		initial     string // non-compliant config
		checkID     string
		applyWant   string // expected substring after Apply
		revertWant  string // expected substring after Revert
	}{
		{
			name:       "ssh-001 disable PermitRootLogin",
			initial:    "PermitRootLogin yes\n",
			checkID:    "ssh-001",
			applyWant:  "permitrootlogin no",
			revertWant: "permitrootlogin yes",
		},
		{
			name:       "ssh-002 disable PasswordAuthentication",
			initial:    "PasswordAuthentication yes\n",
			checkID:    "ssh-002",
			applyWant:  "passwordauthentication no",
			revertWant: "passwordauthentication yes",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempConfig(t, tc.initial)
			m := ssh.NewModuleForTest(path)

			// Plan: should find at least one non-compliant change for the target check.
			changes, err := m.Plan(context.Background(), nil)
			if err != nil {
				t.Fatalf("Plan(): unexpected error: %v", err)
			}

			var targetChange *modules.Change
			for i := range changes {
				if strings.Contains(changes[i].Description, tc.checkID) {
					targetChange = &changes[i]
					break
				}
			}
			if targetChange == nil {
				t.Fatalf("Plan(): no change found for check %s", tc.checkID)
			}

			// Apply: the config file must be updated atomically.
			if err := targetChange.Apply(); err != nil {
				t.Fatalf("Apply(): unexpected error: %v", err)
			}
			assertConfigContains(t, path, tc.applyWant)

			// File mode must be 0600 after Apply.
			assertFileMode(t, path, 0600)

			// Revert: the config file must be restored to the original value.
			if err := targetChange.Revert(); err != nil {
				t.Fatalf("Revert(): unexpected error: %v", err)
			}
			assertConfigContains(t, path, tc.revertWant)
		})
	}
}

// assertConfigContains reads the file at path and fails if want is not present.
func assertConfigContains(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading config: %v", err)
	}
	if !strings.Contains(string(data), want) {
		t.Errorf("config does not contain %q\ngot:\n%s", want, data)
	}
}

// assertFileMode checks that the file at path has the expected permission bits.
func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("file mode: got %04o, want %04o", got, want)
	}
}
