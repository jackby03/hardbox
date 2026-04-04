package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/hardbox-io/hardbox/internal/fleet"
)

// fleetFlags are shared by fleet sub-commands.
type fleetFlags struct {
	hostsFile      string
	concurrency    int
	identityFile   string
	knownHostsFile string
}

func newFleetCmd(gf *globalFlags) *cobra.Command {
	root := &cobra.Command{
		Use:   "fleet",
		Short: "Apply hardening or audit multiple remote hosts over SSH",
		Long: `hardbox fleet dispatches hardening operations to a fleet of Linux hosts
concurrently via SSH. It installs / invokes hardbox on each target, streams
per-host results as they complete, and produces a unified aggregate report.

Host file format (one entry per line):
  user@host
  user@host:port
  # comment lines and blank lines are ignored`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	root.AddCommand(
		newFleetApplyCmd(gf),
		newFleetAuditCmd(gf),
	)

	return root
}

// --------------------------------------------------------------------------
// fleet apply
// --------------------------------------------------------------------------

func newFleetApplyCmd(gf *globalFlags) *cobra.Command {
	ff := &fleetFlags{}
	var (
		dryRun         bool
		failOnCritical bool
	)

	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply hardening profile to all hosts in the fleet",
		Example: `  hardbox fleet apply --hosts hosts.txt --profile production
  hardbox fleet apply --hosts hosts.txt --profile cis-level2 --concurrency 5 --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			hosts, err := fleet.ParseHostsFile(ff.hostsFile)
			if err != nil {
				return fmt.Errorf("loading hosts file: %w", err)
			}

			r := fleet.New(fleet.Config{
				IdentityFile:   ff.identityFile,
				KnownHostsFile: ff.knownHostsFile,
				Concurrency:    ff.concurrency,
				DryRun:         dryRun,
				Profile:        gf.profile,
				FailOnCritical: failOnCritical,
			})

			results := r.Apply(cmd.Context(), hosts)
			printFleetSummary(results)

			if err := writeFleetReport(cmd, results, gf.profile, ""); err != nil {
				return err
			}

			_, failed := countResults(results)
			if failed > 0 {
				return fmt.Errorf("%d host(s) failed", failed)
			}
			return nil
		},
	}

	addFleetFlags(cmd, ff)
	cmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "preview changes without applying them")
	cmd.Flags().BoolVar(&failOnCritical, "fail-on-critical", true, "exit 1 if any host reports critical findings")

	return cmd
}

// --------------------------------------------------------------------------
// fleet audit
// --------------------------------------------------------------------------

func newFleetAuditCmd(gf *globalFlags) *cobra.Command {
	ff := &fleetFlags{}
	var (
		format         string
		output         string
		failOnCritical bool
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit all hosts in the fleet and generate a unified report",
		Example: `  hardbox fleet audit --hosts hosts.txt --profile cis-level2
  hardbox fleet audit --hosts hosts.txt --format html --output fleet-audit.html`,
		RunE: func(cmd *cobra.Command, args []string) error {
			hosts, err := fleet.ParseHostsFile(ff.hostsFile)
			if err != nil {
				return fmt.Errorf("loading hosts file: %w", err)
			}

			r := fleet.New(fleet.Config{
				IdentityFile:   ff.identityFile,
				KnownHostsFile: ff.knownHostsFile,
				Concurrency:    ff.concurrency,
				Profile:        gf.profile,
				FailOnCritical: failOnCritical,
			})

			results := r.Audit(cmd.Context(), hosts)
			printFleetSummary(results)

			if err := writeFleetReport(cmd, results, gf.profile, output); err != nil {
				return err
			}

			_, failed := countResults(results)
			if failed > 0 {
				return fmt.Errorf("%d host(s) failed", failed)
			}
			if failOnCritical && fleet.HasCritical(results) {
				return fmt.Errorf("critical findings detected across fleet")
			}
			return nil
		},
	}

	addFleetFlags(cmd, ff)
	cmd.Flags().StringVar(&format, "format", "text", "report format: text|html")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write aggregate report to this file (default: stdout)")
	cmd.Flags().BoolVar(&failOnCritical, "fail-on-critical", true, "exit 1 if any host reports critical findings")

	return cmd
}

// --------------------------------------------------------------------------
// shared helpers
// --------------------------------------------------------------------------

func addFleetFlags(cmd *cobra.Command, ff *fleetFlags) {
	cmd.Flags().StringVar(&ff.hostsFile, "hosts", "", "path to hosts file (required)")
	cmd.Flags().IntVar(&ff.concurrency, "concurrency", 10, "max parallel SSH sessions")
	cmd.Flags().StringVarP(&ff.identityFile, "identity", "i", "", "SSH private key file (default: agent / ~/.ssh/config)")
	cmd.Flags().StringVar(&ff.knownHostsFile, "host-key-file", "", "known_hosts file for SSH host key verification (default: ~/.ssh/known_hosts)")
	_ = cmd.MarkFlagRequired("hosts")
}

func printFleetSummary(results []fleet.HostResult) {
	passed, failed := countResults(results)
	fmt.Printf("\nfleet: %d hosts processed — %d ok, %d failed\n\n", len(results), passed, failed)
	for _, r := range results {
		if r.OK() {
			fmt.Printf("  ✓  %s  (%s)\n", r.Host, r.Duration.Round(1e6))
		} else {
			fmt.Printf("  ✗  %s  — %v\n", r.Host, r.Err)
		}
	}
	fmt.Println()
}

func writeFleetReport(cmd *cobra.Command, results []fleet.HostResult, profile, outputPath string) error {
	fmtFlag, _ := cmd.Flags().GetString("format")
	format := fleet.FormatText
	if fmtFlag == "html" {
		format = fleet.FormatHTML
	}

	w := os.Stdout
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create report file: %w", err)
		}
		defer f.Close()
		w = f
	}

	return fleet.WriteReport(w, results, profile, format)
}

func countResults(results []fleet.HostResult) (passed, failed int) {
	for _, r := range results {
		if r.OK() {
			passed++
		} else {
			failed++
		}
	}
	return
}
