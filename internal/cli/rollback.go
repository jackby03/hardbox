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
	"github.com/spf13/cobra"

	"github.com/hardbox-io/hardbox/internal/engine"
)

func newRollbackCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "rollback",
		Short: "Restore system to state before last hardbox apply",
	}

	root.AddCommand(newRollbackListCmd(), newRollbackApplyCmd())
	return root
}

func newRollbackListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available rollback snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			e := engine.New(nil)
			return e.ListSnapshots(cmd.Context())
		},
	}
}

func newRollbackApplyCmd() *cobra.Command {
	var (
		sessionID    string
		rollbackLast bool
		nonInteract  bool
	)

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Restore from a snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			e := engine.New(nil)
			return e.Rollback(cmd.Context(), sessionID, rollbackLast)
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "snapshot session ID to restore")
	cmd.Flags().BoolVar(&rollbackLast, "last", false, "restore the most recent snapshot")
	cmd.Flags().BoolVar(&nonInteract, "non-interactive", false, "run without prompts (CI/CD mode)")

	return cmd
}

