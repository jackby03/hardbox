package cli

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/hardbox-io/hardbox/internal/serve"
)

func newServeCmd() *cobra.Command {
	var (
		port       int
		addr       string
		reportsDir string
		noOpen     bool
		basicAuth  string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start a local web dashboard to browse audit reports",
		Long: `serve starts a read-only HTTP dashboard on localhost that lets you
browse audit reports, inspect findings, and compare any two reports side by side.

The server binds to 127.0.0.1 by default and never exposes to the network
unless --addr is set explicitly.

Examples:
  # Start on default port 8080
  hardbox serve --reports-dir /var/log/hardbox/reports/

  # Custom port
  hardbox serve --port 9000 --reports-dir ./reports/

  # Bind to custom address with basic auth
  hardbox serve --addr 0.0.0.0:8080 --basic-auth admin:secret

  # Don't open browser automatically
  hardbox serve --no-open --reports-dir ./reports/`,
		RunE: func(cmd *cobra.Command, args []string) error {
			listenAddr := resolveAddr(addr, port)

			cfg := serve.Config{
				Addr:       listenAddr,
				ReportsDir: reportsDir,
				BasicAuth:  basicAuth,
			}

			srv, err := serve.New(cfg)
			if err != nil {
				return fmt.Errorf("creating server: %w", err)
			}

			url := "http://" + srv.Addr()
			fmt.Fprintf(cmd.OutOrStdout(), "hardbox dashboard → %s\n", url)
			fmt.Fprintf(cmd.OutOrStdout(), "reports dir      → %s\n", reportsDir)
			fmt.Fprintf(cmd.OutOrStdout(), "press Ctrl+C to stop\n\n")

			if !noOpen {
				go openBrowser(url)
			}

			log.Debug().Str("addr", listenAddr).Str("reports_dir", reportsDir).Msg("serve: starting")
			return srv.Start(cmd.Context())
		},
	}

	cmd.Flags().IntVar(&port, "port", 8080, "port to listen on (ignored when --addr is set)")
	cmd.Flags().StringVar(&addr, "addr", "", "full listen address, e.g. 127.0.0.1:8080 (overrides --port)")
	cmd.Flags().StringVar(&reportsDir, "reports-dir", ".", "directory containing JSON audit reports")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "do not open the browser automatically")
	cmd.Flags().StringVar(&basicAuth, "basic-auth", "", "enable HTTP basic auth, format: user:pass")

	return cmd
}

// resolveAddr returns the listen address, preferring --addr over --port.
func resolveAddr(addr string, port int) string {
	if addr != "" {
		// Ensure it has a host component — default to 127.0.0.1 for safety.
		if !strings.Contains(addr, ":") {
			return net.JoinHostPort("127.0.0.1", addr)
		}
		return addr
	}
	return net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
}

// openBrowser opens url in the user's default browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Debug().Err(err).Msg("serve: could not open browser")
	}
}

// contextKey is unexported to avoid collisions.
type contextKey struct{ name string }

// WithContext attaches a context to the cobra command (used in tests).
func withCancelContext(ctx context.Context, cmd *cobra.Command) {
	cmd.SetContext(ctx)
}
