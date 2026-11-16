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
package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/distro"
	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
	"github.com/hardbox-io/hardbox/internal/report"
	"github.com/hardbox-io/hardbox/internal/sdk"
)

// Engine orchestrates the plan → snapshot → execute → verify → report lifecycle.
type Engine struct {
	cfg        *config.Config
	modules    []modules.Module
	plugins    []sdk.PluginEntry
	DistroInfo *distro.Info
}

// PluginInfo describes a plugin module loaded from a .so file.
type PluginInfo struct {
	Name    string
	Version string
	Path    string
}

// New creates an Engine with all built-in modules registered.
// It calls distro.Detect() at startup and logs the result; a detection failure
// is non-fatal — the engine continues without distro information.
// Plugins are loaded from cfg.PluginDir; plugin load errors are logged as
// warnings and do not prevent the engine from starting.
func New(cfg *config.Config) *Engine {
	if cfg == nil {
		cfg = &config.Config{}
	}

	e := &Engine{
		cfg:     cfg,
		modules: registeredModules(),
	}

	if info, err := distro.Detect(); err != nil {
		log.Warn().Err(err).Msg("distro detection failed — some module checks may be skipped")
	} else {
		e.DistroInfo = info
		log.Info().
			Str("id", info.ID).
			Str("version", info.VersionID).
			Str("family", string(info.Family)).
			Str("pretty_name", info.PrettyName).
			Msg("distro detected")
	}

	if cfg.PluginDir != "" {
		plugins, err := sdk.LoadPlugins(cfg.PluginDir)
		if err != nil {
			log.Warn().Err(err).Str("plugin_dir", cfg.PluginDir).Msg("plugin load warning")
		}
		for _, p := range plugins {
			e.modules = append(e.modules, p.Module)
			e.plugins = append(e.plugins, p)
			log.Info().
				Str("plugin", p.Module.Name()).
				Str("version", p.Module.Version()).
				Str("path", p.Path).
				Msg("plugin loaded")
		}
	}

	return e
}

// Audit runs all module checks and returns findings without making changes.
func (e *Engine) Audit(ctx context.Context, format, outputPath string) error {
	sessionID := time.Now().UTC().Format("2006-01-02T150405Z")
	log.Info().Str("profile", e.cfg.Profile).Msg("starting audit")

	all, moduleErrors := e.runAudit(ctx)

	printAuditSummary(all, moduleErrors)

	if err := e.writeReportWithErrors(sessionID, all, moduleErrors, format, outputPath); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	if e.cfg.Audit.FailOnCritical && hasCritical(all) {
		return fmt.Errorf("critical findings detected — see report for details")
	}
	return nil
}

// Apply audits, plans, snapshots, and applies all remediation changes.
// If reportFormat is non-empty and this is not a dry run, a post-apply report
// is written to reportOutput (file path or directory).
func (e *Engine) Apply(ctx context.Context, reportFormat, reportOutput string) error {
	log.Info().
		Str("profile", e.cfg.Profile).
		Bool("dry_run", e.cfg.DryRun).
		Msg("starting apply")

	all, moduleErrors := e.runAudit(ctx)
	if len(moduleErrors) > 0 {
		log.Warn().Int("modules", len(moduleErrors)).
			Msg("partial audit: some modules could not be inspected")
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

	if reportFormat != "" && reportOutput != "" {
		if err := e.writePostApplyReport(ctx, sessionID, reportFormat, reportOutput); err != nil {
			log.Error().Err(err).Msg("post-apply report failed")
			return fmt.Errorf("writing post-apply report: %w", err)
		}
	}

	return nil
}

func (e *Engine) writePostApplyReport(ctx context.Context, sessionID, format, path string) error {
	findings, moduleErrors := e.runAudit(ctx)
	return e.writeReportWithErrors(sessionID, findings, moduleErrors, format, path)
}

// RunAudit executes all module checks and returns the structured Report.
// It does not write anything to disk; the caller is responsible for
// persistence and diff comparison. This is the building block for hardbox watch.
func (e *Engine) RunAudit(ctx context.Context) (*report.Report, error) {
	sessionID := time.Now().UTC().Format("2006-01-02T150405Z")
	findings, moduleErrors := e.runAudit(ctx)
	return report.BuildWithErrors(sessionID, e.cfg.Profile, findings, moduleErrors), nil
}

// GetModules returns the list of registered modules (built-in + plugins).
func (e *Engine) GetModules() []modules.Module {
	return e.modules
}

// ListPlugins returns metadata for every plugin loaded from the plugin directory.
func (e *Engine) ListPlugins() []PluginInfo {
	infos := make([]PluginInfo, 0, len(e.plugins))
	for _, p := range e.plugins {
		infos = append(infos, PluginInfo{
			Name:    p.Module.Name(),
			Version: p.Module.Version(),
			Path:    p.Path,
		})
	}
	return infos
}

// AuditModule runs the audit for the named module and returns its findings.
func (e *Engine) AuditModule(ctx context.Context, name string) ([]modules.Finding, error) {
	for _, m := range e.modules {
		if m.Name() == name {
			return m.Audit(ctx, modules.ModuleConfig(e.cfg.ModuleCfg(m.Name())))
		}
	}
	return nil, fmt.Errorf("module %q not found", name)
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

// runAudit executes every enabled module and returns the findings together
// with a per-module error map.
//
// A module that fails does not abort the audit. A hardening tool is expected to
// run on hosts where a given service is simply not installed — no sshd, no
// auditd, no chrony — and returning early meant a single missing config file
// produced no report at all. Modules that fail are recorded and surfaced in the
// report, because a silently partial compliance report is worse than a loud
// failure.
func (e *Engine) runAudit(ctx context.Context) ([]modules.Finding, map[string]string) {
	var all []modules.Finding
	var moduleErrors map[string]string

	for _, m := range e.modules {
		if !e.cfg.IsModuleEnabled(m.Name()) {
			log.Debug().Str("module", m.Name()).Msg("skipped (disabled)")
			continue
		}
		findings, err := m.Audit(ctx, modules.ModuleConfig(e.cfg.ModuleCfg(m.Name())))
		if err != nil {
			log.Warn().Err(err).Str("module", m.Name()).Msg("module audit failed, continuing")
			if moduleErrors == nil {
				moduleErrors = make(map[string]string)
			}
			moduleErrors[m.Name()] = err.Error()
			continue
		}
		all = append(all, findings...)
	}
	return all, moduleErrors
}

func (e *Engine) buildPlan(ctx context.Context, findings []modules.Finding) ([]modules.Change, error) {
	var changes []modules.Change
	for _, m := range e.modules {
		if !e.cfg.IsModuleEnabled(m.Name()) {
			continue
		}
		c, err := m.Plan(ctx, modules.ModuleConfig(e.cfg.ModuleCfg(m.Name())))
		if err != nil {
			// One module that cannot build a plan must not stop remediation of
			// every other module. The audit already reported it.
			log.Warn().Err(err).Str("module", m.Name()).Msg("module plan failed, continuing")
			continue
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

func printAuditSummary(findings []modules.Finding, moduleErrors map[string]string) {
	compliant, nonCompliant := 0, 0
	for _, f := range findings {
		if f.IsCompliant() {
			compliant++
		} else {
			nonCompliant++
		}
	}
	// Write to stderr so structured output on stdout stays pipeable (e.g. | jq .).
	fmt.Fprintf(os.Stderr, "\nAudit Summary: %d compliant / %d non-compliant\n",
		compliant, nonCompliant)

	if len(moduleErrors) > 0 {
		// Make a partial audit loud. A host missing a config file gets a
		// degraded result, not a silent one.
		names := make([]string, 0, len(moduleErrors))
		for name := range moduleErrors {
			names = append(names, name)
		}
		sort.Strings(names)
		fmt.Fprintf(os.Stderr, "Partial audit: %d module(s) could not be audited: %s\n",
			len(names), strings.Join(names, ", "))
	}
	fmt.Fprintln(os.Stderr)
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

// writeReport renders the audit report to stdout (when path is empty) or to a
// file. If path points to a directory, a timestamped file is created inside it.
func (e *Engine) writeReport(sessionID string, findings []modules.Finding, format, path string) error {
	return e.writeReportWithErrors(sessionID, findings, nil, format, path)
}

func (e *Engine) writeReportWithErrors(
	sessionID string,
	findings []modules.Finding,
	moduleErrors map[string]string,
	format, path string,
) error {
	r := report.BuildWithErrors(sessionID, e.cfg.Profile, findings, moduleErrors)

	if path == "" {
		return report.Write(r, format, os.Stdout)
	}

	// If path is an existing directory, generate a filename inside it.
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		ext := formatExtension(format)
		path = filepath.Join(path, fmt.Sprintf("hardbox-report-%s%s", sessionID, ext))
	}

	var buf bytes.Buffer
	if err := report.Write(r, format, &buf); err != nil {
		return err
	}

	if err := util.AtomicWrite(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("writing report file atomically: %w", err)
	}

	log.Info().Str("path", path).Str("format", format).Msg("report written")
	return nil
}

func formatExtension(format string) string {
	switch format {
	case "json":
		return ".json"
	case "markdown", "md":
		return ".md"
	default:
		return ".txt"
	}
}

