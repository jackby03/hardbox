package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/hardbox-io/hardbox/internal/engine"
	"github.com/hardbox-io/hardbox/internal/modules"
)

// modulesModel represents the module list screen.
type modulesModel struct {
	modules  []modules.Module
	selected int
}

func newModules(eng *engine.Engine) modulesModel {
	return modulesModel{
		modules:  eng.GetModules(),
		selected: 0,
	}
}

func (m modulesModel) Init() tea.Cmd {
	return nil
}

func (m modulesModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			if m.selected < len(m.modules)-1 {
				m.selected++
			}
		}
	}
	return m, nil
}

func (m modulesModel) View() string {
	s := styles()

	header := s.header.Render(" hardbox - Modules ")

	// Build module list
	var moduleLines []string
	for i, mod := range m.modules {
		prefix := "  "
		if i == m.selected {
			prefix = "> "
		}
		status := "[ not audited ]"
		moduleLines = append(moduleLines, fmt.Sprintf("%s%-30s %s", prefix, mod.Name(), status))
	}

	moduleList := lipgloss.NewStyle().
		Padding(1, 2).
		Render(lipgloss.JoinVertical(lipgloss.Left, moduleLines...))

	actions := s.actions.Render("[ENTER] Detail   [Q/ESC] Back")

	body := lipgloss.JoinVertical(lipgloss.Left,
		moduleList,
		"",
		actions,
	)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		s.panel.Render(body),
	)
}
