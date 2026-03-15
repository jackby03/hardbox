package main

import (
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestApplyLogLevel_ValidLevels(t *testing.T) {
	cases := []struct {
		input string
		want  zerolog.Level
	}{
		{"debug", zerolog.DebugLevel},
		{"info", zerolog.InfoLevel},
		{"warn", zerolog.WarnLevel},
		{"error", zerolog.ErrorLevel},
		// zerolog also accepts these aliases
		{"DEBUG", zerolog.DebugLevel},
		{"INFO", zerolog.InfoLevel},
		{"WARN", zerolog.WarnLevel},
		{"ERROR", zerolog.ErrorLevel},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if err := applyLogLevel(tc.input); err != nil {
				t.Fatalf("applyLogLevel(%q) returned unexpected error: %v", tc.input, err)
			}
			if got := zerolog.GlobalLevel(); got != tc.want {
				t.Errorf("applyLogLevel(%q): global level = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestApplyLogLevel_InvalidLevel(t *testing.T) {
	err := applyLogLevel("verbose")
	if err == nil {
		t.Fatal("expected error for unknown log level, got nil")
	}
	if !strings.Contains(err.Error(), "unknown log level") {
		t.Errorf("error message should mention 'unknown log level', got: %v", err)
	}
	if !strings.Contains(err.Error(), "verbose") {
		t.Errorf("error message should include the bad value 'verbose', got: %v", err)
	}
}

func TestRootCmd_LogLevelFlagRegistered(t *testing.T) {
	cmd := rootCmd()
	flag := cmd.PersistentFlags().Lookup("log-level")
	if flag == nil {
		t.Fatal("--log-level persistent flag not registered on root command")
	}
	if flag.DefValue != "info" {
		t.Errorf("--log-level default: got %q, want %q", flag.DefValue, "info")
	}
	if !strings.Contains(flag.Usage, "debug") {
		t.Errorf("--log-level usage should mention 'debug', got: %q", flag.Usage)
	}
}

func TestRootCmd_LogLevelInAuditHelp(t *testing.T) {
	cmd := rootCmd()
	// --log-level is a persistent flag, so it should appear in subcommand help too.
	audit, _, err := cmd.Find([]string{"audit"})
	if err != nil || audit == nil {
		t.Fatal("audit subcommand not found")
	}
	// The persistent flag is inherited.
	flag := audit.InheritedFlags().Lookup("log-level")
	if flag == nil {
		t.Fatal("--log-level should be inherited by the audit subcommand")
	}
}
