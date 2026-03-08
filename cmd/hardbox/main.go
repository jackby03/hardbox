package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/engine"
	"github.com/hardbox-io/hardbox/internal/tui"
)

var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		cfgFile     string
		profile     string
		dryRun      bool
		nonInteract bool
		reportFmt   string
		reportOut   string
	)

	root := &cobra.Command{
		Use:     "hardbox",
		Short:   "Production-grade Linux hardening toolkit",
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Default: launch TUI
			cfg, err := config.Load(cfgFile, profile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			p := tea.NewProgram(tui.NewApp(cfg), tea.WithAltScreen())
			_, err = p.Run()
			return err
		},
	}

	root.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: /etc/hardbox/config.yaml)")
	root.PersistentFlags().StringVarP(&profile, "profile", "p", "production", "hardening profile to use")

	// apply subcommand
	apply := &cobra.Command{
		Use:   "apply",
		Short: "Apply hardening changes to this system",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile, profile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			cfg.DryRun = dryRun
			cfg.NonInteractive = nonInteract
			e := engine.New(cfg)
			return e.Apply(cmd.Context())
		},
	}
	apply.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "preview changes without applying them")
	apply.Flags().BoolVar(&nonInteract, "non-interactive", false, "run without prompts (CI/CD mode)")
	apply.Flags().StringVar(&reportFmt, "report-format", "text", "report format: json|text|markdown|all")
	apply.Flags().StringVar(&reportOut, "report", "", "write report to this file path")

	// audit subcommand
	audit := &cobra.Command{
		Use:   "audit",
		Short: "Audit system state without making changes",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile, profile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			e := engine.New(cfg)
			return e.Audit(cmd.Context(), reportFmt, reportOut)
		},
	}
	audit.Flags().StringVar(&reportFmt, "format", "text", "output format: json|text|markdown")
	audit.Flags().StringVarP(&reportOut, "output", "o", "", "write report to this file")

	// rollback subcommand
	rollback := &cobra.Command{
		Use:   "rollback",
		Short: "Restore system to state before last hardbox apply",
	}
	rollbackList := &cobra.Command{
		Use:   "list",
		Short: "List available rollback snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			e := engine.New(nil)
			return e.ListSnapshots(cmd.Context())
		},
	}
	var sessionID string
	var rollbackLast bool
	rollbackApply := &cobra.Command{
		Use:   "apply",
		Short: "Restore from a snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			e := engine.New(nil)
			return e.Rollback(cmd.Context(), sessionID, rollbackLast)
		},
	}
	rollbackApply.Flags().StringVar(&sessionID, "session", "", "snapshot session ID to restore")
	rollbackApply.Flags().BoolVar(&rollbackLast, "last", false, "restore the most recent snapshot")
	rollback.AddCommand(rollbackList, rollbackApply)

	root.AddCommand(apply, audit, rollback)
	return root
}
