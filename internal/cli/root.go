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
