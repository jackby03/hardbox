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
package cli_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hardbox-io/hardbox/internal/cli"
)

func TestWatchCmd_Registered(t *testing.T) {
	root := cli.NewRootCmdForTest("test")
	cmd, _, err := root.Find([]string{"watch"})
	if err != nil || cmd == nil || cmd.Name() != "watch" {
		t.Fatalf("watch subcommand not found in root command: %v", err)
	}
}

func TestWatchCmd_FlagsRegistered(t *testing.T) {
	cmd := cli.NewWatchCmdForTest()

	cases := []struct {
		flag     string
		defValue string
	}{
		{"interval", "5m0s"},
		{"max-runs", "0"},
		{"report-dir", ""},
		{"fail-on-regression", "false"},
		{"quiet", "false"},
	}

	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			f := cmd.Flags().Lookup(tc.flag)
			if f == nil {
				t.Fatalf("--%s flag not registered", tc.flag)
			}
			if f.DefValue != tc.defValue {
				t.Errorf("--%s default: got %q, want %q", tc.flag, f.DefValue, tc.defValue)
			}
		})
	}
}

func TestWatchCmd_IntervalFlagParsing(t *testing.T) {
	cmd := cli.NewWatchCmdForTest()
	if err := cmd.Flags().Set("interval", "2h30m"); err != nil {
		t.Fatalf("setting --interval: %v", err)
	}
	f := cmd.Flags().Lookup("interval")
	if f.Value.String() != (2*time.Hour + 30*time.Minute).String() {
		t.Errorf("--interval parsed to %q, want %q", f.Value.String(), (2*time.Hour + 30*time.Minute).String())
	}
}

func TestWatchCmd_ShortDescriptionMentionsContinuous(t *testing.T) {
	cmd := cli.NewWatchCmdForTest()
	if !strings.Contains(strings.ToLower(cmd.Short), "continuous") &&
		!strings.Contains(strings.ToLower(cmd.Long), "continuous") {
		t.Error("watch command description should mention 'continuous'")
	}
}

func TestWatchCmd_ReportDirShorthand(t *testing.T) {
	cmd := cli.NewWatchCmdForTest()
	f := cmd.Flags().ShorthandLookup("d")
	if f == nil {
		t.Fatal("-d shorthand for --report-dir not registered")
	}
	if f.Name != "report-dir" {
		t.Errorf("-d maps to %q, want %q", f.Name, "report-dir")
	}
}

func TestWatchCmd_InheritsLogLevel(t *testing.T) {
	root := cli.NewRootCmdForTest("test")
	watch, _, err := root.Find([]string{"watch"})
	if err != nil || watch == nil {
		t.Fatal("watch subcommand not found")
	}
	if f := watch.InheritedFlags().Lookup("log-level"); f == nil {
		t.Fatal("--log-level should be inherited by the watch subcommand")
	}
	if f := watch.InheritedFlags().Lookup("profile"); f == nil {
		t.Fatal("--profile should be inherited by the watch subcommand")
	}
}

