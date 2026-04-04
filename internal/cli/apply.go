package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/engine"
)

func newApplyCmd(gf *globalFlags) *cobra.Command {
	var (
		dryRun      bool
		nonInteract bool
		reportFmt   string
		reportOut   string
	)

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply hardening changes to this system",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(gf.cfgFile, gf.profile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			cfg.DryRun = dryRun
			cfg.NonInteractive = nonInteract
			cfg.LogLevel = gf.logLevel
			e := engine.New(cfg)
			return e.Apply(cmd.Context())
		},
	}

	cmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "preview changes without applying them")
	cmd.Flags().BoolVar(&nonInteract, "non-interactive", false, "run without prompts (CI/CD mode)")
	cmd.Flags().StringVar(&reportFmt, "report-format", "text", "report format: json|text|markdown|all")
	cmd.Flags().StringVar(&reportOut, "report", "", "write report to this file path")

	return cmd
}
