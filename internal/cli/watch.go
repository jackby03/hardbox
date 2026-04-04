package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/engine"
	"github.com/hardbox-io/hardbox/internal/notify"
	"github.com/hardbox-io/hardbox/internal/report"
)

func newWatchCmd(gf *globalFlags) *cobra.Command {
	var (
		interval         time.Duration
		maxRuns          int
		reportDir        string
		failOnRegression bool
		quiet            bool
	)

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Continuously audit the system and detect regressions",
		Long: `watch runs a full audit on a configurable interval, writes a timestamped
JSON report to disk after each run, and detects regressions by comparing
each audit to the previous one.

On each iteration hardbox watch:
  1. Runs a full audit against the active profile
  2. Writes a timestamped JSON report to --report-dir
  3. Diffs the result against the previous run
  4. Logs a warning (and optionally exits 1) if regressions are found

Send SIGINT or SIGTERM to stop the daemon gracefully.

Examples:
  # Run continuously every 6 hours, write reports to /var/lib/hardbox/reports
  sudo hardbox watch --profile production --interval 6h \
      --report-dir /var/lib/hardbox/reports

  # Run a single baseline audit and exit
  sudo hardbox watch --profile cis-level1 --report-dir ./reports --max-runs 1

  # Two-run regression check for CI (baseline then verify)
  sudo hardbox watch --max-runs 2 --fail-on-regression --report-dir ./reports`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(gf.cfgFile, gf.profile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			cfg.LogLevel = gf.logLevel
			e := engine.New(cfg)
			alerter := notify.New(cfg.Notifications)

			dir := reportDir
			if dir == "" {
				dir = cfg.Report.OutputDir
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return fmt.Errorf("creating report dir %q: %w", dir, err)
			}

			var prev *report.Report
			run := 0

			for {
				// Check for shutdown before each run.
				select {
				case <-cmd.Context().Done():
					log.Info().Msg("watch: shutting down")
					return nil
				default:
				}

				run++
				log.Info().
					Int("run", run).
					Str("profile", cfg.Profile).
					Msg("watch: starting audit")

				r, auditErr := e.RunAudit(cmd.Context())
				if auditErr != nil {
					log.Error().Err(auditErr).Int("run", run).Msg("watch: audit failed")
				} else {
					path := filepath.Join(dir,
						fmt.Sprintf("hardbox-report-%s.json", r.SessionID))
					if writeErr := writeWatchReport(r, path); writeErr != nil {
						log.Error().Err(writeErr).Str("path", path).Msg("watch: could not write report")
					} else {
						log.Info().
							Str("path", path).
							Int("score", r.OverallScore).
							Msg("watch: report written")
					}

					alerter.NotifyNewFindings(cmd.Context(), r)

					if prev != nil {
						d := report.Diff(prev, r)
						if !quiet {
							_ = report.WriteDiff(d, "text", cmd.ErrOrStderr())
						}
						if d.HasRegressions() {
							log.Warn().
								Int("regressions", len(d.Regressions)).
								Int("score_delta", d.ScoreDelta).
								Str("session_before", d.Before.SessionID).
								Str("session_after", d.After.SessionID).
								Msg("watch: regressions detected")
							alerter.NotifyRegression(cmd.Context(), d)
							if failOnRegression {
								return fmt.Errorf("regressions detected: %d check(s) regressed", len(d.Regressions))
							}
						}
					}
					prev = r
				}

				if maxRuns > 0 && run >= maxRuns {
					log.Info().Int("runs", run).Msg("watch: max-runs reached")
					return nil
				}

				// Wait for next tick, but respect context cancellation.
				select {
				case <-cmd.Context().Done():
					log.Info().Msg("watch: shutting down")
					return nil
				case <-time.After(interval):
				}
			}
		},
	}

	cmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "duration between audit runs (e.g. 30m, 6h, 24h)")
	cmd.Flags().IntVar(&maxRuns, "max-runs", 0, "maximum number of runs (0 = run forever)")
	cmd.Flags().StringVarP(&reportDir, "report-dir", "d", "", "directory for timestamped JSON reports (default: report.output_dir from config)")
	cmd.Flags().BoolVar(&failOnRegression, "fail-on-regression", false, "exit 1 when any regressions are detected")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress per-run diff output; only log warnings and errors")

	return cmd
}

// writeWatchReport serialises a Report to a JSON file with 0o600 permissions.
func writeWatchReport(r *report.Report, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling report: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}
