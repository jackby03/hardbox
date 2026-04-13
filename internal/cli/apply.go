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

