package engine

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/modules"
)

// Engine orchestrates the plan → snapshot → execute → verify → report lifecycle.
type Engine struct {
	cfg     *config.Config
	modules []modules.Module
}

// New creates an Engine with all built-in modules registered.
func New(cfg *config.Config) *Engine {
	return &Engine{
		cfg:     cfg,
		modules: registeredModules(),
	}
}

// Audit runs all module checks and returns findings without making changes.
func (e *Engine) Audit(ctx context.Context, format, outputPath string) error {
	log.Info().Str("profile", e.cfg.Profile).Msg("starting audit")

	all, err := e.runAudit(ctx)
	if err != nil {
		return err
	}

	printAuditSummary(all)

	if outputPath != "" {
		if err := writeReport(all, format, outputPath); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}
		log.Info().Str("path", outputPath).Msg("report written")
	}

	if e.cfg.Audit.FailOnCritical && hasCritical(all) {
		return fmt.Errorf("critical findings detected — see report for details")
	}
	return nil
}

// Apply audits, plans, snapshots, and applies all remediation changes.
func (e *Engine) Apply(ctx context.Context) error {
	log.Info().
		Str("profile", e.cfg.Profile).
		Bool("dry_run", e.cfg.DryRun).
		Msg("starting apply")

	all, err := e.runAudit(ctx)
	if err != nil {
		return err
	}

	changes, err := e.buildPlan(ctx, all)
	if err != nil {
		return fmt.Errorf("building plan: %w", err)
	}

	if len(changes) == 0 {
		log.Info().Msg("system is already compliant — nothing to do")
		return nil
	}

	log.Info().Int("changes", len(changes)).Msg("plan built")

	if e.cfg.DryRun {
		printDryRun(changes)
		return nil
	}

	sessionID := time.Now().UTC().Format("2006-01-02T150405Z")
	snap, err := newSnapshot(sessionID, changes)
	if err != nil {
		return fmt.Errorf("creating snapshot: %w", err)
	}
	if err := snap.Save(); err != nil {
		return fmt.Errorf("saving snapshot: %w", err)
	}

	if err := e.execute(ctx, changes, snap); err != nil {
		log.Error().Err(err).Msg("apply failed — attempting rollback")
		if rbErr := snap.Restore(); rbErr != nil {
			log.Error().Err(rbErr).Msg("rollback also failed — manual intervention required")
		} else {
			log.Info().Msg("rollback successful")
		}
		return fmt.Errorf("apply failed: %w", err)
	}

	log.Info().Msg("apply complete")
	return nil
}

// ListSnapshots prints available rollback snapshots.
func (e *Engine) ListSnapshots(_ context.Context) error {
	snaps, err := listSnapshots()
	if err != nil {
		return err
	}
	if len(snaps) == 0 {
		fmt.Println("No snapshots found.")
		return nil
	}
	fmt.Printf("%-30s %-20s %s\n", "SESSION ID", "HOST", "PROFILE")
	for _, s := range snaps {
		fmt.Printf("%-30s %-20s %s\n", s.SessionID, s.Host, s.Profile)
	}
	return nil
}

// Rollback restores the system from a snapshot.
func (e *Engine) Rollback(_ context.Context, sessionID string, last bool) error {
	var snap *snapshot
	var err error
	if last {
		snap, err = latestSnapshot()
	} else {
		snap, err = loadSnapshot(sessionID)
	}
	if err != nil {
		return fmt.Errorf("loading snapshot: %w", err)
	}
	log.Info().Str("session", snap.SessionID).Msg("restoring snapshot")
	return snap.Restore()
}

// ── internal helpers ────────────────────────────────────────────────────────

func (e *Engine) runAudit(ctx context.Context) ([]modules.Finding, error) {
	var all []modules.Finding
	for _, m := range e.modules {
		if !e.cfg.IsModuleEnabled(m.Name()) {
			log.Debug().Str("module", m.Name()).Msg("skipped (disabled)")
			continue
		}
		findings, err := m.Audit(ctx, modules.ModuleConfig(e.cfg.ModuleCfg(m.Name())))
		if err != nil {
			return nil, fmt.Errorf("module %s audit: %w", m.Name(), err)
		}
		all = append(all, findings...)
	}
	return all, nil
}

func (e *Engine) buildPlan(ctx context.Context, findings []modules.Finding) ([]modules.Change, error) {
	var changes []modules.Change
	for _, m := range e.modules {
		if !e.cfg.IsModuleEnabled(m.Name()) {
			continue
		}
		c, err := m.Plan(ctx, modules.ModuleConfig(e.cfg.ModuleCfg(m.Name())))
		if err != nil {
			return nil, fmt.Errorf("module %s plan: %w", m.Name(), err)
		}
		changes = append(changes, c...)
	}
	return changes, nil
}

func (e *Engine) execute(ctx context.Context, changes []modules.Change, snap *snapshot) error {
	for i, ch := range changes {
		log.Info().Int("step", i+1).Int("total", len(changes)).Str("change", ch.Description).Msg("applying")
		if err := ch.Apply(); err != nil {
			return fmt.Errorf("step %d (%s): %w", i+1, ch.Description, err)
		}
	}
	return nil
}

func printAuditSummary(findings []modules.Finding) {
	compliant, nonCompliant := 0, 0
	for _, f := range findings {
		if f.IsCompliant() {
			compliant++
		} else {
			nonCompliant++
		}
	}
	fmt.Fprintf(os.Stdout, "\nAudit Summary: %d compliant / %d non-compliant\n\n",
		compliant, nonCompliant)
}

func printDryRun(changes []modules.Change) {
	fmt.Print("\n[DRY RUN] The following changes would be applied:\n\n")
	for i, ch := range changes {
		fmt.Printf("  %d. %s\n", i+1, ch.Description)
		if ch.DryRunOutput != "" {
			fmt.Printf("     %s\n", ch.DryRunOutput)
		}
	}
	fmt.Printf("\nTotal: %d change(s)\n", len(changes))
}

func hasCritical(findings []modules.Finding) bool {
	for _, f := range findings {
		if !f.IsCompliant() && f.Check.Severity == modules.SeverityCritical {
			return true
		}
	}
	return false
}

// writeReport and snapshot helpers are stubs — implemented in audit/ and snapshot.go.
func writeReport(findings []modules.Finding, format, path string) error {
	// TODO: delegate to internal/audit/renderers
	return nil
}
