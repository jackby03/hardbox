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
package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/hardbox-io/hardbox/internal/engine"
	"github.com/hardbox-io/hardbox/internal/modules"
)

// auditResultMsg carries findings from an async audit command.
type auditResultMsg struct {
	findings []modules.Finding
	err      error
}

// moduleDetailModel is the per-module audit detail screen.
type moduleDetailModel struct {
	eng      *engine.Engine
	module   modules.Module
	findings []modules.Finding
	loading  bool
	err      error
	offset   int
	height   int
}

func newModuleDetail(eng *engine.Engine, mod modules.Module, height int) moduleDetailModel {
	return moduleDetailModel{
		eng:     eng,
		module:  mod,
		loading: true,
		height:  height,
	}
}

func (m moduleDetailModel) Init() tea.Cmd {
	name := m.module.Name()
	return func() tea.Msg {
		findings, err := m.eng.AuditModule(context.Background(), name)
		return auditResultMsg{findings: findings, err: err}
	}
}

func (m moduleDetailModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case auditResultMsg:
		m.loading = false
		m.err = msg.err
		m.findings = msg.findings
		m.offset = 0
	case tea.KeyMsg:
		visible := m.visibleRows()
		maxOffset := len(m.findings) - visible
		if maxOffset < 0 {
			maxOffset = 0
		}
		switch msg.String() {
		case "up", "k":
			if m.offset > 0 {
				m.offset--
			}
		case "down", "j":
			if m.offset < maxOffset {
				m.offset++
			}
		case "pgup":
			m.offset -= visible
			if m.offset < 0 {
				m.offset = 0
			}
		case "pgdown":
			m.offset += visible
			if m.offset > maxOffset {
				m.offset = maxOffset
			}
		}
	}
	return m, nil
}

func (m moduleDetailModel) View() string {
	s := styles()
	header := s.header.Render(fmt.Sprintf(" hardbox - %s  v%s ", m.module.Name(), m.module.Version()))

	if m.loading {
		return lipgloss.JoinVertical(lipgloss.Left,
			header,
			s.panel.Render("Auditing..."),
		)
	}

	if m.err != nil {
		return lipgloss.JoinVertical(lipgloss.Left,
			header,
			s.panel.Render(fmt.Sprintf("Error: %v", m.err)),
		)
	}

	// Compliance score
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
	scoreBar := renderScoreBar(score, 30)
	summary := lipgloss.JoinHorizontal(lipgloss.Top,
		scoreBar,
		fmt.Sprintf("  %d/%d compliant (%d%%)", compliant, total, score),
	)

	// Table header
	tableHeader := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#94a3b8")).
		Render(fmt.Sprintf("  %-12s %-34s %-14s %-14s %-14s %s",
			"ID", "DESCRIPTION", "STATUS", "CURRENT", "TARGET", "SEV"))

	// Visible rows with scroll
	visible := m.visibleRows()
	end := m.offset + visible
	if end > total {
		end = total
	}

	var rows []string
	for _, f := range m.findings[m.offset:end] {
		label, style := renderStatus(f.Status)
		colored := style.Render(label)
		pad := 14 - len(label)
		if pad < 0 {
			pad = 0
		}
		row := fmt.Sprintf("  %-12s %-34s %s%s%-14s %-14s %s",
			f.Check.ID,
			truncate(f.Check.Title, 34),
			colored,
			strings.Repeat(" ", pad),
			truncate(f.Current, 14),
			truncate(f.Target, 14),
			string(f.Check.Severity),
		)
		rows = append(rows, row)
	}

	scrollNote := ""
	if total > visible {
		scrollNote = fmt.Sprintf("  [%d-%d of %d]", m.offset+1, end, total)
	}

	actions := s.actions.Render("[A] Apply   [↑/↓] Scroll   [PgUp/PgDn]   [Q/ESC] Back" + scrollNote)

	body := lipgloss.JoinVertical(lipgloss.Left,
		summary,
		"",
		tableHeader,
		strings.Join(rows, "\n"),
		"",
		actions,
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		s.panel.Render(body),
	)
}

func (m moduleDetailModel) visibleRows() int {
	rows := m.height - 12
	if rows < 5 {
		return 5
	}
	return rows
}

// renderStatus returns a display label and colour style for a finding status.
func renderStatus(status modules.Status) (string, lipgloss.Style) {
	switch status {
	case modules.StatusCompliant:
		return "compliant", lipgloss.NewStyle().Foreground(lipgloss.Color("#22c55e"))
	case modules.StatusNonCompliant:
		return "non-compliant", lipgloss.NewStyle().Foreground(lipgloss.Color("#ef4444"))
	case modules.StatusManual:
		return "manual", lipgloss.NewStyle().Foreground(lipgloss.Color("#f59e0b"))
	case modules.StatusSkipped:
		return "skipped", lipgloss.NewStyle().Foreground(lipgloss.Color("#64748b"))
	case modules.StatusError:
		return "error", lipgloss.NewStyle().Foreground(lipgloss.Color("#f97316"))
	default:
		return string(status), lipgloss.NewStyle()
	}
}

// truncate shortens s to maxLen runes, adding "…" if cut.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen-1]) + "…"
}

