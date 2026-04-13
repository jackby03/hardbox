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

