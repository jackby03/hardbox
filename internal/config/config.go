package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config is the root hardbox configuration, resolved from profile + overrides.
type Config struct {
	Version     string `mapstructure:"version"`
	Profile     string `mapstructure:"profile"`
	Environment string `mapstructure:"environment"` // cloud | onprem | container

	// LogLevel controls zerolog verbosity: debug | info | warn | error.
	// Set via --log-level flag or HARDBOX_LOG_LEVEL env var; defaults to "info".
	LogLevel string `mapstructure:"log_level"`

	DryRun         bool
	NonInteractive bool

	// PluginDir is the directory scanned for .so plugin files at startup.
	// Defaults to /etc/hardbox/plugins. Set to "" to disable plugin loading.
	PluginDir string `mapstructure:"plugin_dir"`

	Modules       map[string]ModuleConfig `mapstructure:"modules"`
	Report        ReportConfig            `mapstructure:"report"`
	Audit         AuditConfig             `mapstructure:"audit"`
	Watch         WatchConfig             `mapstructure:"watch"`
	Notifications NotificationsConfig     `mapstructure:"notifications"`
}

// ModuleConfig holds per-module settings.
type ModuleConfig map[string]any

// ReportConfig controls output format and destination.
type ReportConfig struct {
	Format             string `mapstructure:"format"`
	OutputDir          string `mapstructure:"output_dir"`
	IncludeRemediation bool   `mapstructure:"include_remediation"`
	IncludeEvidence    bool   `mapstructure:"include_evidence"`
}

// AuditConfig controls audit behaviour.
type AuditConfig struct {
	FailOnCritical bool `mapstructure:"fail_on_critical"`
	FailOnHigh     bool `mapstructure:"fail_on_high"`
}

// WatchConfig controls the continuous audit daemon.
type WatchConfig struct {
	// Interval is the duration between audit runs (e.g. "5m", "6h", "24h").
	Interval string `mapstructure:"interval"`
	// MaxRuns is the maximum number of audit iterations. 0 means unlimited.
	MaxRuns int `mapstructure:"max_runs"`
}

// NotificationsConfig controls webhook alerting from the watch daemon.
type NotificationsConfig struct {
	// Webhooks is a list of generic HTTP webhook endpoints.
	Webhooks []WebhookConfig `mapstructure:"webhooks"`
	// Slack is a list of Slack Incoming Webhook integrations.
	Slack []SlackConfig `mapstructure:"slack"`
}

// WebhookConfig defines a generic HTTP webhook destination.
type WebhookConfig struct {
	// URL is the HTTP(S) endpoint to POST the JSON payload to.
	URL string `mapstructure:"url"`
	// Events lists which event types trigger this webhook.
	// Valid values: "regression", "critical_finding", "high_finding".
	// An empty list means all events.
	Events []string `mapstructure:"events"`
	// Modules filters alerts to findings from the named modules only.
	// An empty list means all modules.
	Modules []string `mapstructure:"modules"`
	// Headers are optional extra HTTP headers (e.g. Authorization).
	Headers map[string]string `mapstructure:"headers"`
	// TimeoutSeconds is the per-attempt HTTP timeout. Defaults to 10.
	TimeoutSeconds int `mapstructure:"timeout_seconds"`
}

// SlackConfig defines a Slack Incoming Webhook destination.
type SlackConfig struct {
	// URL is the Slack Incoming Webhook URL.
	URL string `mapstructure:"url"`
	// Events and Modules follow the same semantics as WebhookConfig.
	Events []string `mapstructure:"events"`
	// Modules filters alerts to findings from the named modules only.
	Modules []string `mapstructure:"modules"`
	// Channel overrides the default channel configured on the webhook (optional).
	Channel string `mapstructure:"channel"`
}

// Load reads configuration from the provided file path (or defaults) and
// merges the requested profile on top of base defaultss.
func Load(cfgFile, profile string) (*Config, error) {
	v := viper.New()

	// Set built-in defaults.
	setDefaults(v)

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		// Search standard locations.
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("/etc/hardbox")
		v.AddConfigPath(filepath.Join(os.Getenv("HOME"), ".config", "hardbox"))
		v.AddConfigPath(".")
	}

	// Allow env overrides like HARDBOX_PROFILE=cis-level2.
	v.SetEnvPrefix("HARDBOX")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		// A missing config file is fine — we'll use defaults + profile.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	// Override profile from flag if provided.
	if profile != "" {
		v.Set("profile", profile)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	return &cfg, nil
}

// ModuleCfg returns the ModuleConfig for the given module name,
// returning an empty map if no specific config exists.
func (c *Config) ModuleCfg(name string) ModuleConfig {
	if c.Modules == nil {
		return ModuleConfig{}
	}
	if mc, ok := c.Modules[name]; ok {
		return mc
	}
	return ModuleConfig{}
}

// IsModuleEnabled returns true unless the module is listed in modules_disabled.
func (c *Config) IsModuleEnabled(name string) bool {
	mc := c.ModuleCfg(name)
	if enabled, ok := mc["enabled"]; ok {
		if b, ok := enabled.(bool); ok {
			return b
		}
	}
	return true // enabled by default
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("version", "1")
	v.SetDefault("profile", "production")
	v.SetDefault("environment", "cloud")
	v.SetDefault("log_level", "info")
	v.SetDefault("report.format", "html")
	v.SetDefault("report.output_dir", "/var/lib/hardbox/reports")
	v.SetDefault("report.include_remediation", true)
	v.SetDefault("report.include_evidence", true)
	v.SetDefault("audit.fail_on_critical", true)
	v.SetDefault("audit.fail_on_high", false)
	v.SetDefault("watch.interval", "5m")
	v.SetDefault("watch.max_runs", 0)
	v.SetDefault("plugin_dir", "/etc/hardbox/plugins")
}
