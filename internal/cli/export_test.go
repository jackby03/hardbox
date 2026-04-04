package cli

import "github.com/spf13/cobra"

// Exported shims for white-box testing.

var ApplyLogLevel = applyLogLevel

func NewRootCmdForTest(version string) *cobra.Command {
	return newRootCmd(version)
}

func NewWatchCmdForTest() *cobra.Command {
	return newWatchCmd(&globalFlags{profile: "production", logLevel: "info"})
}
