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

	"github.com/spf13/cobra"

	"github.com/hardbox-io/hardbox/internal/report"
)

func newDiffCmd() *cobra.Command {
	var (
		format     string
		outputFile string
	)

	cmd := &cobra.Command{
		Use:   "diff <before.json> <after.json>",
		Short: "Compare two audit reports and highlight regressions and improvements",
		Long: `diff compares two hardbox JSON audit reports and produces a structured
comparison showing regressions (now failing), improvements (now passing),
and unchanged failures.

Exit code 1 when any regressions are found — safe for CI/CD pipelines.

Examples:
  # Compare two audits and print to terminal
  hardbox diff before.json after.json

  # Generate an HTML diff report
  hardbox diff before.json after.json --format html --output diff.html

  # Use in CI — fails if anything regressed
  hardbox diff baseline.json current.json --format json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			beforePath, afterPath := args[0], args[1]

			d, err := report.DiffFiles(beforePath, afterPath)
			if err != nil {
				return err
			}

			w := cmd.OutOrStdout()
			if outputFile != "" {
				f, err := os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			if err := report.WriteDiff(d, format, w); err != nil {
				return err
			}

			if d.HasRegressions() {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"\n%d regression(s) found — exit 1\n", len(d.Regressions))
				return fmt.Errorf("regressions detected")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "text", "output format: text|html|json")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "write output to file instead of stdout")

	return cmd
}

