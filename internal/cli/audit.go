package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/engine"
)

func newAuditCmd(gf *globalFlags) *cobra.Command {
	var (
		reportFmt string
		reportOut string
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit system state without making changes",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(gf.cfgFile, gf.profile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			cfg.LogLevel = gf.logLevel
			e := engine.New(cfg)
			return e.Audit(cmd.Context(), reportFmt, reportOut)
		},
	}

	cmd.Flags().StringVar(&reportFmt, "format", "text", "output format: json|text|markdown|html")
	cmd.Flags().StringVarP(&reportOut, "output", "o", "", "write report to this file")

	return cmd
}
