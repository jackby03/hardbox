package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/engine"
)

func newPluginCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage hardbox plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(
		newPluginListCmd(gf),
		newPluginInstallCmd(gf),
	)
	return cmd
}

func newPluginListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List loaded plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(gf.cfgFile, gf.profile)
			if err != nil {
				return err
			}

			e := engine.New(cfg)
			plugins := e.ListPlugins()

			if len(plugins) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "No plugins loaded (plugin_dir: %s)\n", cfg.PluginDir)
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%-24s %-10s %s\n", "NAME", "VERSION", "PATH")
			for _, p := range plugins {
				fmt.Fprintf(cmd.OutOrStdout(), "%-24s %-10s %s\n", p.Name, p.Version, p.Path)
			}
			return nil
		},
	}
}

func newPluginInstallCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "install <plugin.so>",
		Short: "Install a plugin .so into the plugin directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src := args[0]

			if filepath.Ext(src) != ".so" {
				return fmt.Errorf("plugin file must have a .so extension")
			}

			cfg, err := config.Load(gf.cfgFile, gf.profile)
			if err != nil {
				return err
			}

			if err := os.MkdirAll(cfg.PluginDir, 0o755); err != nil {
				return fmt.Errorf("creating plugin directory %s: %w", cfg.PluginDir, err)
			}

			dst := filepath.Join(cfg.PluginDir, filepath.Base(src))
			if err := copyFile(src, dst); err != nil {
				return fmt.Errorf("installing plugin: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Plugin installed: %s\n", dst)
			return nil
		},
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
