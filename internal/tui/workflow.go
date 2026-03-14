package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/engine"
	"github.com/hardbox-io/hardbox/internal/modules"
)

type modulePlan struct {
	name    string
	changes []modules.Change
}

func enabledModules(eng *engine.Engine, cfg *config.Config) []modules.Module {
	var out []modules.Module
	for _, mod := range eng.GetModules() {
		if cfg.IsModuleEnabled(mod.Name()) {
			out = append(out, mod)
		}
	}
	return out
}

func collectPlans(eng *engine.Engine, cfg *config.Config) ([]modulePlan, error) {
	var plans []modulePlan
	for _, mod := range enabledModules(eng, cfg) {
		changes, err := mod.Plan(context.Background(), modules.ModuleConfig(cfg.ModuleCfg(mod.Name())))
		if err != nil {
			return nil, fmt.Errorf("module %s plan: %w", mod.Name(), err)
		}
		plans = append(plans, modulePlan{name: mod.Name(), changes: changes})
	}
	return plans, nil
}

type auditState string

const (
	auditPending auditState = "pending"
	auditRunning auditState = "running"
	auditDone    auditState = "done"
	auditFailed  auditState = "failed"
)

type auditModuleResultMsg struct {
	module   string
	findings []modules.Finding
	err      error
}

type auditTickMsg struct{}

type auditWorkflowModel struct {
	eng      *engine.Engine
	cfg      *config.Config
	modules  []modules.Module
	states   map[string]auditState
	errors   map[string]error
	findings []modules.Finding
	running  int
	done     bool
	frame    int
}

func newAuditWorkflow(eng *engine.Engine, cfg *config.Config) auditWorkflowModel {
	mods := enabledModules(eng, cfg)
	states := make(map[string]auditState, len(mods))
	for _, mod := range mods {
		states[mod.Name()] = auditPending
	}
	return auditWorkflowModel{
		eng:     eng,
		cfg:     cfg,
		modules: mods,
		states:  states,
		errors:  map[string]error{},
		running: -1,
	}
}

func (m auditWorkflowModel) Init() tea.Cmd {
	return tea.Batch(auditTick(), m.nextAuditCmd())
}

func (m auditWorkflowModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case auditTickMsg:
		if m.done {
			return m, nil
		}
		m.frame = (m.frame + 1) % 4
		return m, auditTick()
	case auditModuleResultMsg:
		if msg.err != nil {
			m.states[msg.module] = auditFailed
			m.errors[msg.module] = msg.err
		} else {
			m.states[msg.module] = auditDone
			m.findings = append(m.findings, msg.findings...)
		}
		m.running++
		if m.running+1 >= len(m.modules) {
			m.done = true
			return m, nil
		}
		return m, m.nextAuditCmd()
	}
	return m, nil
}

func (m auditWorkflowModel) View() string {
	s := styles()
	header := s.header.Render(" hardbox - Audit Workflow ")

	spinner := []string{"|", "/", "-", "\\"}
	var rows []string
	for i, mod := range m.modules {
		state := m.states[mod.Name()]
		prefix := "[ ]"
		suffix := ""
		switch state {
		case auditRunning:
			prefix = "[" + spinner[m.frame] + "]"
		case auditDone:
			prefix = "[OK]"
		case auditFailed:
			prefix = "[X]"
			suffix = "  " + m.errors[mod.Name()].Error()
		case auditPending:
			if i == m.running {
				prefix = "[" + spinner[m.frame] + "]"
			} else if i < m.running {
				prefix = "[OK]"
			}
		}
		rows = append(rows, fmt.Sprintf("%s %-20s%s", prefix, mod.Name(), suffix))
	}

	summary := "Running audit..."
	if m.done {
		compliant := 0
		for _, f := range m.findings {
			if f.IsCompliant() {
				compliant++
			}
		}
		total := len(m.findings)
		score := 0
		if total > 0 {
			score = compliant * 100 / total
		}
		summary = fmt.Sprintf("Completed. Score: %d%% (%d/%d compliant)", score, compliant, total)
	}

	actions := "[Q/ESC] Back"
	if !m.done {
		actions = "Audit in progress..."
	}

	body := lipgloss.JoinVertical(lipgloss.Left,
		"Module status:",
		strings.Join(rows, "\n"),
		"",
		summary,
		"",
		s.actions.Render(actions),
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		s.panel.Render(body),
	)
}

func (m auditWorkflowModel) nextAuditCmd() tea.Cmd {
	if m.done {
		return nil
	}
	next := m.running + 1
	if next < 0 || next >= len(m.modules) {
		return nil
	}
	mod := m.modules[next]
	m.states[mod.Name()] = auditRunning
	name := mod.Name()
	return func() tea.Msg {
		findings, err := m.eng.AuditModule(context.Background(), name)
		return auditModuleResultMsg{module: name, findings: findings, err: err}
	}
}

func auditTick() tea.Cmd {
	return tea.Tick(120000000, func(_ time.Time) tea.Msg {
		return auditTickMsg{}
	})
}

type applyPlansMsg struct {
	plans []modulePlan
	err   error
}

type applyConfirmModel struct {
	eng     *engine.Engine
	cfg     *config.Config
	loading bool
	plans   []modulePlan
	err     error
	total   int
	risk    string
	ready   bool
}

func newApplyConfirm(eng *engine.Engine, cfg *config.Config) applyConfirmModel {
	return applyConfirmModel{eng: eng, cfg: cfg, loading: true}
}

func (m applyConfirmModel) Init() tea.Cmd {
	return func() tea.Msg {
		plans, err := collectPlans(m.eng, m.cfg)
		return applyPlansMsg{plans: plans, err: err}
	}
}

func (m applyConfirmModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case applyPlansMsg:
		m.loading = false
		m.err = msg.err
		m.plans = msg.plans
		for _, p := range m.plans {
			m.total += len(p.changes)
		}
		m.risk = estimateRisk(m.total)
		m.ready = m.err == nil
	}
	return m, nil
}

func (m applyConfirmModel) View() string {
	s := styles()
	header := s.header.Render(" hardbox - Apply Confirmation ")

	if m.loading {
		return lipgloss.JoinVertical(lipgloss.Left,
			header,
			s.panel.Render("Building plan..."),
		)
	}

	if m.err != nil {
		return lipgloss.JoinVertical(lipgloss.Left,
			header,
			s.panel.Render("Error: "+m.err.Error()),
		)
	}

	var rows []string
	for _, p := range m.plans {
		rows = append(rows, fmt.Sprintf("- %-20s %3d change(s)", p.name, len(p.changes)))
		for _, ch := range p.changes {
			rows = append(rows, "    * "+ch.Description)
		}
	}
	if len(rows) == 0 {
		rows = append(rows, "No changes required. System is already compliant.")
	}

	body := lipgloss.JoinVertical(lipgloss.Left,
		"Planned changes:",
		strings.Join(rows, "\n"),
		"",
		fmt.Sprintf("Estimated risk level: %s", m.risk),
		fmt.Sprintf("Total changes: %d", m.total),
		"",
		s.actions.Render("[Y] Confirm Apply   [ESC] Cancel"),
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		s.panel.Render(body),
	)
}

func (m applyConfirmModel) Ready() bool {
	return m.ready
}

func (m applyConfirmModel) Plans() []modulePlan {
	return m.plans
}

type applyStepMsg struct {
	module  int
	change  int
	skipped bool
	err     error
}

type rollbackDoneMsg struct {
	err error
}

type applyProgressModel struct {
	plans          []modulePlan
	moduleStates   []string
	moduleIndex    int
	changeIndex    int
	applied        []modules.Change
	totalChanges   int
	completed      int
	done           bool
	err            error
	rollbackStatus string
}

func newApplyProgress(plans []modulePlan) applyProgressModel {
	states := make([]string, len(plans))
	total := 0
	for i, p := range plans {
		states[i] = "pending"
		total += len(p.changes)
	}
	if len(states) > 0 {
		states[0] = "running"
	}
	return applyProgressModel{plans: plans, moduleStates: states, totalChanges: total}
}

func (m applyProgressModel) Init() tea.Cmd {
	return m.nextApplyCmd()
}

func (m applyProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case applyStepMsg:
		if msg.err != nil {
			m.err = msg.err
			if m.moduleIndex < len(m.moduleStates) {
				m.moduleStates[m.moduleIndex] = "failed"
			}
			if len(m.applied) == 0 {
				m.rollbackStatus = "No rollback needed"
				m.done = true
				return m, nil
			}
			return m, m.rollbackCmd()
		}

		current := m.plans[m.moduleIndex]
		if !msg.skipped {
			m.applied = append(m.applied, current.changes[m.changeIndex])
			m.completed++
			m.changeIndex++
		}
		if m.changeIndex >= len(current.changes) {
			m.moduleStates[m.moduleIndex] = "done"
			m.moduleIndex++
			m.changeIndex = 0
			if m.moduleIndex < len(m.moduleStates) {
				m.moduleStates[m.moduleIndex] = "running"
			}
		}

		if m.moduleIndex >= len(m.plans) {
			m.done = true
			m.rollbackStatus = "Not required"
			return m, nil
		}

		return m, m.nextApplyCmd()
	case rollbackDoneMsg:
		if msg.err != nil {
			m.rollbackStatus = "Rollback failed: " + msg.err.Error()
		} else {
			m.rollbackStatus = "Rollback completed"
		}
		m.done = true
		return m, nil
	}
	return m, nil
}

func (m applyProgressModel) View() string {
	s := styles()
	header := s.header.Render(" hardbox - Apply Progress ")

	progress := 0
	if m.totalChanges > 0 {
		progress = m.completed * 100 / m.totalChanges
	}
	bar := renderScoreBar(progress, 40)

	var rows []string
	for i, p := range m.plans {
		state := m.moduleStates[i]
		label := "[ ]"
		switch state {
		case "running":
			label = "[~]"
		case "done":
			label = "[OK]"
		case "failed":
			label = "[X]"
		}
		rows = append(rows, fmt.Sprintf("%s %-20s", label, p.name))
	}

	status := "Applying changes..."
	if m.done {
		if m.err != nil {
			status = "Apply failed: " + m.err.Error()
		} else {
			status = "Apply completed successfully"
		}
	}

	actions := "Applying..."
	if m.done {
		actions = "[Q/ESC] Back"
	}

	body := lipgloss.JoinVertical(lipgloss.Left,
		fmt.Sprintf("Overall progress: %s  %d%%", bar, progress),
		fmt.Sprintf("Completed changes: %d/%d", m.completed, m.totalChanges),
		"",
		"Per-module status:",
		strings.Join(rows, "\n"),
		"",
		status,
		"Rollback: "+m.rollbackStatus,
		"",
		s.actions.Render(actions),
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		s.panel.Render(body),
	)
}

func (m applyProgressModel) nextApplyCmd() tea.Cmd {
	if m.moduleIndex >= len(m.plans) {
		return nil
	}
	plan := m.plans[m.moduleIndex]
	if m.changeIndex >= len(plan.changes) {
		return func() tea.Msg {
			return applyStepMsg{module: m.moduleIndex, change: m.changeIndex, skipped: true}
		}
	}
	change := plan.changes[m.changeIndex]
	moduleIndex := m.moduleIndex
	changeIndex := m.changeIndex
	return func() tea.Msg {
		err := change.Apply()
		return applyStepMsg{module: moduleIndex, change: changeIndex, err: err}
	}
}

func (m applyProgressModel) rollbackCmd() tea.Cmd {
	applied := append([]modules.Change(nil), m.applied...)
	return func() tea.Msg {
		for i := len(applied) - 1; i >= 0; i-- {
			if applied[i].Revert == nil {
				continue
			}
			if err := applied[i].Revert(); err != nil {
				return rollbackDoneMsg{err: err}
			}
		}
		return rollbackDoneMsg{}
	}
}

func (m applyProgressModel) Done() bool {
	return m.done
}

func estimateRisk(totalChanges int) string {
	switch {
	case totalChanges >= 16:
		return "high"
	case totalChanges >= 7:
		return "medium"
	default:
		return "low"
	}
}
