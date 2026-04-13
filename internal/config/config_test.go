package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConfig_ModuleCfg(t *testing.T) {
	tests := []struct {
		name       string
		config     *Config
		moduleName string
		expected   ModuleConfig
	}{
		{
			name: "Modules is nil",
			config: &Config{
				Modules: nil,
			},
			moduleName: "test-module",
			expected:   ModuleConfig{},
		},
		{
			name: "Module not found",
			config: &Config{
				Modules: map[string]ModuleConfig{
					"other-module": {"key": "value"},
				},
			},
			moduleName: "test-module",
			expected:   ModuleConfig{},
		},
		{
			name: "Module found",
			config: &Config{
				Modules: map[string]ModuleConfig{
					"test-module": {"key": "value"},
				},
			},
			moduleName: "test-module",
			expected:   ModuleConfig{"key": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.ModuleCfg(tt.moduleName)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ModuleCfg() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ── profile integration tests ────────────────────────────────────────────────

// profilePath returns the path to a profile YAML relative to this package.
const profilesDir = "../../configs/profiles/"

func TestLoad_CISLevel1Profile(t *testing.T) {
	cfg, err := Load(profilesDir+"cis-level1.yaml", "")
	if err != nil {
		t.Fatalf("Load cis-level1 profile: %v", err)
	}

	if cfg.Profile != "cis-level1" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "cis-level1")
	}
	if cfg.Environment != "onprem" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "onprem")
	}

	// Every core module must be enabled.
	enabledModules := []string{
		"ssh", "firewall", "kernel", "users", "filesystem",
		"auditd", "services", "network", "mac", "ntp",
		"updates", "crypto", "logging",
	}
	for _, mod := range enabledModules {
		if !cfg.IsModuleEnabled(mod) {
			t.Errorf("module %q should be enabled in cis-level1", mod)
		}
	}
	// containers is optional (off by default at Level 1).
	if cfg.IsModuleEnabled("containers") {
		t.Error("module 'containers' should be disabled in cis-level1")
	}

	// Audit thresholds.
	if !cfg.Audit.FailOnCritical {
		t.Error("audit.fail_on_critical should be true in cis-level1")
	}
	if !cfg.Audit.FailOnHigh {
		t.Error("audit.fail_on_high should be true in cis-level1")
	}

	// SSH hardening booleans must be set.
	sshCfg := cfg.ModuleCfg("ssh")
	for _, key := range []string{"disable_root_login", "disable_empty_passwords", "disable_x11_forwarding"} {
		v, ok := sshCfg[key].(bool)
		if !ok || !v {
			t.Errorf("ssh.%s should be true in cis-level1", key)
		}
	}

	// Crypto module must be present.
	if cfg.ModuleCfg("crypto")["min_tls_version"] == nil {
		t.Error("crypto.min_tls_version should be set in cis-level1")
	}
}

func TestLoad_ProductionProfile(t *testing.T) {
	cfg, err := Load(profilesDir+"production.yaml", "")
	if err != nil {
		t.Fatalf("Load production profile: %v", err)
	}

	if cfg.Profile != "production" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "production")
	}
	if cfg.Environment != "cloud" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "cloud")
	}

	// All hardening modules must be enabled in production.
	enabledModules := []string{
		"ssh", "firewall", "kernel", "users", "filesystem",
		"auditd", "services", "network", "mac", "ntp",
		"updates", "crypto", "logging",
	}
	for _, mod := range enabledModules {
		if !cfg.IsModuleEnabled(mod) {
			t.Errorf("module %q should be enabled in production", mod)
		}
	}

	// Audit thresholds.
	if !cfg.Audit.FailOnCritical {
		t.Error("audit.fail_on_critical should be true in production")
	}
	if cfg.Audit.FailOnHigh {
		t.Error("audit.fail_on_high should be false in production (not a CI gate)")
	}

	// Strict SSH settings.
	sshCfg := cfg.ModuleCfg("ssh")
	for _, key := range []string{"disable_root_login", "disable_empty_passwords", "disable_x11_forwarding"} {
		v, ok := sshCfg[key].(bool)
		if !ok || !v {
			t.Errorf("ssh.%s should be true in production (strict mode)", key)
		}
	}

	// Auditd immutable mode required in production.
	if v, ok := cfg.ModuleCfg("auditd")["immutable"].(bool); !ok || !v {
		t.Error("auditd.immutable should be true in production")
	}

	// Reports include remediation in production.
	if !cfg.Report.IncludeRemediation {
		t.Error("report.include_remediation should be true in production")
	}
}

func TestLoad_DevelopmentProfile(t *testing.T) {
	cfg, err := Load(profilesDir+"development.yaml", "")
	if err != nil {
		t.Fatalf("Load development profile: %v", err)
	}

	if cfg.Profile != "development" {
		t.Errorf("Profile = %q, want %q", cfg.Profile, "development")
	}
	if cfg.Environment != "cloud" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "cloud")
	}

	// Core modules must still be enabled in dev.
	enabledModules := []string{
		"ssh", "firewall", "kernel", "users", "filesystem",
		"auditd", "services", "network", "mac", "ntp",
		"updates", "crypto", "logging",
	}
	for _, mod := range enabledModules {
		if !cfg.IsModuleEnabled(mod) {
			t.Errorf("module %q should be enabled in development", mod)
		}
	}

	// Containers enabled in dev (Docker is common for developers).
	if !cfg.IsModuleEnabled("containers") {
		t.Error("module 'containers' should be enabled in development")
	}

	// Audit thresholds — dev is less strict than cis-level1.
	if !cfg.Audit.FailOnCritical {
		t.Error("audit.fail_on_critical should be true in development")
	}
	if cfg.Audit.FailOnHigh {
		t.Error("audit.fail_on_high should be false in development")
	}

	// Auditd NOT immutable in dev (easier to adjust audit rules).
	if v, ok := cfg.ModuleCfg("auditd")["immutable"].(bool); ok && v {
		t.Error("auditd.immutable should be false in development")
	}

	// Root login must still be disabled even in dev.
	if v, ok := cfg.ModuleCfg("ssh")["disable_root_login"].(bool); !ok || !v {
		t.Error("ssh.disable_root_login should be true even in development")
	}

	// Kernel ip_forward override should be present (Docker networking).
	if cfg.ModuleCfg("kernel")["overrides"] == nil {
		t.Error("kernel.overrides should be set in development (needed for Docker)")
	}
}

// ── inheritance tests ────────────────────────────────────────────────────────

func TestLoad_InheritanceSimple(t *testing.T) {
	// Create a temporary directory for our custom config.
	tmpDir := t.TempDir()
	childYaml := `
profile: my-custom-profile
extends: cis-level1
modules:
  ssh:
    port: 2222
`
	childFile := filepath.Join(tmpDir, "custom.yaml")
	if err := os.WriteFile(childFile, []byte(childYaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(childFile, "")
	if err != nil {
		t.Fatalf("Load with inheritance failed: %v", err)
	}

	// Should inherit cis-level1 settings.
	if !cfg.IsModuleEnabled("ssh") {
		t.Error("Inherited module 'ssh' should be enabled")
	}
	sshCfg := cfg.ModuleCfg("ssh")
	if v, ok := sshCfg["disable_root_login"].(bool); !ok || !v {
		t.Error("Inherited ssh.disable_root_login should be true")
	}

	// Should override the specific setting.
	// Viper reads numbers as float64 or int depending on unmarshal, port is typically parsed as int in map[string]any or float64 in JSON/YAML default decoder.
	// But Viper stores them based on its parser. We can check fmt.Sprint.
	if fmt.Sprintf("%v", sshCfg["port"]) != "2222" {
		t.Errorf("Overridden ssh.port should be 2222, got %v", sshCfg["port"])
	}

	if cfg.Profile != "my-custom-profile" {
		t.Errorf("Profile should be my-custom-profile, got %q", cfg.Profile)
	}
}

func TestLoad_InheritanceChain(t *testing.T) {
	tmpDir := t.TempDir()

	// A -> B -> cis-level1
	bYaml := `
profile: profile-b
extends: cis-level1
modules:
  ssh:
    port: 2020
`
	aYaml := `
profile: profile-a
extends: profile-b
modules:
  ssh:
    max_auth_tries: 2
`
	if err := os.WriteFile(filepath.Join(tmpDir, "profile-b.yaml"), []byte(bYaml), 0o600); err != nil {
		t.Fatal(err)
	}
	aFile := filepath.Join(tmpDir, "profile-a.yaml")
	if err := os.WriteFile(aFile, []byte(aYaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(aFile, "")
	if err != nil {
		t.Fatalf("Load chain failed: %v", err)
	}

	sshCfg := cfg.ModuleCfg("ssh")

	// From A
	if fmt.Sprintf("%v", sshCfg["max_auth_tries"]) != "2" {
		t.Errorf("A's override failed, max_auth_tries = %v", sshCfg["max_auth_tries"])
	}
	// From B
	if fmt.Sprintf("%v", sshCfg["port"]) != "2020" {
		t.Errorf("B's override failed, port = %v", sshCfg["port"])
	}
	// From cis-level1
	if v, ok := sshCfg["disable_root_login"].(bool); !ok || !v {
		t.Error("cis-level1's base config missing")
	}
}

func TestLoad_InheritanceCycle(t *testing.T) {
	tmpDir := t.TempDir()

	// A -> B -> A
	bYaml := `
profile: profile-b
extends: profile-a
`
	aYaml := `
profile: profile-a
extends: profile-b
`
	if err := os.WriteFile(filepath.Join(tmpDir, "profile-b.yaml"), []byte(bYaml), 0o600); err != nil {
		t.Fatal(err)
	}
	aFile := filepath.Join(tmpDir, "profile-a.yaml")
	if err := os.WriteFile(aFile, []byte(aYaml), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(aFile, "")
	if err == nil {
		t.Fatal("Expected error on inheritance cycle, got nil")
	}
	if !strings.Contains(err.Error(), "inheritance cycle detected") {
		t.Errorf("Expected cycle error, got: %v", err)
	}
}

func TestLoad_InheritanceDepthLimit(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a chain of 7 files to exceed the max depth of 5
	for i := 1; i <= 7; i++ {
		content := fmt.Sprintf("profile: profile-%d\n", i)
		if i < 7 {
			content += fmt.Sprintf("extends: profile-%d\n", i+1)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("profile-%d.yaml", i)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	aFile := filepath.Join(tmpDir, "profile-1.yaml")
	_, err := Load(aFile, "")
	if err == nil {
		t.Fatal("Expected error on exceeding inheritance depth, got nil")
	}
	if !strings.Contains(err.Error(), "inheritance depth exceeded") {
		t.Errorf("Expected depth error, got: %v", err)
	}
}
