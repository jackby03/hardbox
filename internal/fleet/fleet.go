package fleet

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Config controls how the fleet runner connects and behaves.
type Config struct {
	// IdentityFile is the path to the SSH private key file.
	// When empty, the SSH agent ($SSH_AUTH_SOCK) or ~/.ssh/config is used.
	IdentityFile string

	// KnownHostsFile is the path to the known_hosts file used for host key
	// verification. When empty, the ssh binary uses ~/.ssh/known_hosts.
	KnownHostsFile string

	// Concurrency is the maximum number of parallel SSH sessions.
	// Defaults to 10.
	Concurrency int

	// DryRun passes --dry-run to hardbox on every host.
	DryRun bool

	// Profile is the hardening profile to apply / audit.
	Profile string

	// FailOnCritical causes Run to exit with code 1 if any host has
	// critical findings (applies to audit runs).
	FailOnCritical bool
}

// Runner executes hardbox commands concurrently across a fleet of hosts.
type Runner struct {
	cfg Config
}

// New creates a Runner with the given Config.
// Concurrency is clamped to 1 if ≤ 0.
func New(cfg Config) *Runner {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	return &Runner{cfg: cfg}
}

// Apply applies the hardening profile to every host concurrently.
// Failures on individual hosts are captured in the HostResult; they do not
// abort the run for other hosts.
func (r *Runner) Apply(ctx context.Context, hosts []Host) []HostResult {
	return r.dispatch(ctx, hosts, func(ctx context.Context, h Host, conn *sshClient) (string, error) {
		cmd := fmt.Sprintf(
			"hardbox apply --profile %s --non-interactive",
			shellQuote(r.cfg.Profile),
		)
		if r.cfg.DryRun {
			cmd += " --dry-run"
		}
		log.Info().Str("host", h.String()).Str("cmd", cmd).Msg("fleet: applying")
		return conn.run(ctx, cmd)
	})
}

// Audit audits every host concurrently, fetching a JSON report per host.
// Failures on individual hosts are captured in the HostResult; they do not
// abort the run for other hosts.
func (r *Runner) Audit(ctx context.Context, hosts []Host) []HostResult {
	return r.dispatch(ctx, hosts, func(ctx context.Context, h Host, conn *sshClient) (string, error) {
		reportPath := fmt.Sprintf("/tmp/hardbox-fleet-%d.json", time.Now().UnixNano())
		auditCmd := fmt.Sprintf(
			"hardbox audit --profile %s --format json --output %s",
			shellQuote(r.cfg.Profile),
			shellQuote(reportPath),
		)
		log.Info().Str("host", h.String()).Msg("fleet: auditing")
		if out, err := conn.run(ctx, auditCmd); err != nil {
			return out, err
		}
		content, err := conn.readFile(ctx, reportPath)
		if err != nil {
			return "", fmt.Errorf("fetch remote report %s: %w", reportPath, err)
		}
		// Clean up temp report file (best-effort).
		_, _ = conn.run(ctx, fmt.Sprintf("rm -f -- %s", shellQuote(reportPath)))
		return content, nil
	})
}

// dispatch runs fn on every host with bounded concurrency.
// Results are returned in the same order as hosts.
func (r *Runner) dispatch(
	ctx context.Context,
	hosts []Host,
	fn func(context.Context, Host, *sshClient) (string, error),
) []HostResult {
	results := make([]HostResult, len(hosts))

	sem := make(chan struct{}, r.cfg.Concurrency)
	var wg sync.WaitGroup

	for i, h := range hosts {
		i, h := i, h
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Acquire semaphore slot.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = HostResult{Host: h, Err: ctx.Err()}
				return
			}
			defer func() { <-sem }()

			start := time.Now()
			conn := newSSHClient(h, r.cfg.IdentityFile, r.cfg.KnownHostsFile)
			out, err := fn(ctx, h, conn)

			if err != nil {
				log.Error().Str("host", h.String()).Err(err).Msg("fleet: host failed")
			} else {
				log.Info().Str("host", h.String()).Dur("duration", time.Since(start)).Msg("fleet: host done")
			}

			results[i] = HostResult{
				Host:     h,
				Output:   out,
				Err:      err,
				Duration: time.Since(start),
			}
		}()
	}

	wg.Wait()
	return results
}

// HasCritical reports whether any host result contains critical findings.
// It performs a simple string search in the JSON output.
func HasCritical(results []HostResult) bool {
	for _, r := range results {
		if r.OK() && strings.Contains(r.Output, `"critical":`) {
			// crude check — a real implementation would unmarshal the JSON
			if !strings.Contains(r.Output, `"critical":0`) &&
				!strings.Contains(r.Output, `"critical": 0`) {
				return true
			}
		}
	}
	return false
}
