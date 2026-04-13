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
package cli

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// Execute builds the root command and runs it. Called by cmd/hardbox/main.go.
func Execute(version string) error {
	return newRootCmd(version).Execute()
}

// globalFlags are shared across all subcommands via PersistentFlags.
type globalFlags struct {
	cfgFile  string
	profile  string
	logLevel string
}

func newRootCmd(version string) *cobra.Command {
	gf := &globalFlags{}

	root := &cobra.Command{
		Use:     "hardbox",
		Short:   "Production-grade Linux hardening toolkit",
		Version: version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return applyLogLevel(gf.logLevel)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	root.PersistentFlags().StringVarP(&gf.cfgFile, "config", "c", "", "config file (default: /etc/hardbox/config.yaml)")
	root.PersistentFlags().StringVarP(&gf.profile, "profile", "p", "production", "hardening profile to use")
	root.PersistentFlags().StringVar(&gf.logLevel, "log-level", "info", "log verbosity: debug|info|warn|error")

	root.AddCommand(
		newApplyCmd(gf),
		newAuditCmd(gf),
		newWatchCmd(gf),
		newRollbackCmd(),
		newDiffCmd(),
		newFleetCmd(gf),
		newPluginCmd(gf),
		newServeCmd(),
	)

	return root
}

// applyLogLevel configures the zerolog global logger.
// Accepted values (case-insensitive): debug, info, warn, error.
func applyLogLevel(level string) error {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("unknown log level %q — valid values: debug, info, warn, error", level)
	}
	zerolog.SetGlobalLevel(lvl)
	return nil
}

