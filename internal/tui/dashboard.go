package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/hardbox-io/hardbox/internal/config"
)

// dashboardModel is the main hardbox dashboard screen.
type dashboardModel struct {
	cfg      *config.Config
	hostname string
	score    int // 0–100
}

func newDashboard(cfg *config.Config) dashboardModel {
	hostname, _ := os.Hostname()
	return dashboardModel{
		cfg:      cfg,
		hostname: hostname,
		score:    0, // will be populated after first audit
	}
}

func (m dashboardModel) Init() tea.Cmd { return nil }

func (m dashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// All key handling is now done in App.Update()
	return m, nil
}

func (m dashboardModel) View() string {
	s := styles()

	header := s.header.Render(
		fmt.Sprintf(" hardbox  %-30s  [?] Help  [Q]uit", "[ "+m.hostname+" ]"),
	)

	scoreBar := renderScoreBar(m.score, 40)
	info := lipgloss.JoinVertical(lipgloss.Left,
		s.label.Render("Security Score: ")+scoreBar+fmt.Sprintf("  %d / 100", m.score),
		s.label.Render("Profile:        ")+s.value.Render(m.cfg.Profile),
		s.label.Render("Environment:    ")+s.value.Render(m.cfg.Environment),
	)

	actions := s.actions.Render("[ENTER] Modules   [A] Apply All   [D] Audit Workflow   [Q] Quit")

	body := lipgloss.JoinVertical(lipgloss.Left,
		info,
		"",
		actions,
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		s.panel.Render(body),
	)
}

// renderScoreBar draws a filled/empty progress bar for the score.
func renderScoreBar(score, width int) string {
	filled := score * width / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	color := "#22c55e"
	if score < 40 {
		color = "#ef4444"
	} else if score < 70 {
		color = "#f59e0b"
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(bar)
}

// styleSet holds all re-usable Lip Gloss styles for the dashboard.
type styleSet struct {
	header  lipgloss.Style
	panel   lipgloss.Style
	label   lipgloss.Style
	value   lipgloss.Style
	actions lipgloss.Style
}

func styles() styleSet {
	return styleSet{
		header: lipgloss.NewStyle().
			Background(lipgloss.Color("#1e40af")).
			Foreground(lipgloss.Color("#ffffff")).
			Bold(true).
			Padding(0, 1).
			Width(80),
		panel: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#3b82f6")).
			Padding(1, 2).
			Width(78),
		label: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94a3b8")).
			Width(18),
		value: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#e2e8f0")).
			Bold(true),
		actions: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#64748b")).
			MarginTop(1),
	}
}
