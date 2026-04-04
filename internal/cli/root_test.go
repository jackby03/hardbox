package cli_test

import (
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hardbox-io/hardbox/internal/cli"
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
		{"DEBUG", zerolog.DebugLevel},
		{"INFO", zerolog.InfoLevel},
		{"WARN", zerolog.WarnLevel},
		{"ERROR", zerolog.ErrorLevel},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if err := cli.ApplyLogLevel(tc.input); err != nil {
				t.Fatalf("ApplyLogLevel(%q) returned unexpected error: %v", tc.input, err)
			}
			if got := zerolog.GlobalLevel(); got != tc.want {
				t.Errorf("ApplyLogLevel(%q): global level = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestApplyLogLevel_InvalidLevel(t *testing.T) {
	err := cli.ApplyLogLevel("verbose")
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
	cmd := cli.NewRootCmdForTest("test")
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
	cmd := cli.NewRootCmdForTest("test")
	audit, _, err := cmd.Find([]string{"audit"})
	if err != nil || audit == nil {
		t.Fatal("audit subcommand not found")
	}
	flag := audit.InheritedFlags().Lookup("log-level")
	if flag == nil {
		t.Fatal("--log-level should be inherited by the audit subcommand")
	}
}

func TestRootCmd_SubcommandsRegistered(t *testing.T) {
	cmd := cli.NewRootCmdForTest("test")
	want := []string{"apply", "audit", "rollback"}
	for _, name := range want {
		sub, _, err := cmd.Find([]string{name})
		if err != nil || sub == nil || sub.Name() != name {
			t.Errorf("subcommand %q not found in root command", name)
		}
	}
}
