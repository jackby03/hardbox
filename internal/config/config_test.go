package config

import (
	"reflect"
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

