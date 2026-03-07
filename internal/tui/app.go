package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/hardbox-io/hardbox/internal/config"
)

// screen identifies which screen is currently active.
type screen int

const (
	screenDashboard screen = iota
	screenModules
	screenModuleDetail
	screenAudit
	screenApplyConfirm
	screenApplyProgress
)

// App is the root Bubble Tea model that owns the entire TUI.
type App struct {
	cfg    *config.Config
	screen screen
	width  int
	height int

	dashboard    dashboardModel
	moduleList   moduleListModel
}

// NewApp creates the root model, wiring in the config.
func NewApp(cfg *config.Config) App {
	return App{
		cfg:       cfg,
		screen:    screenDashboard,
		dashboard: newDashboard(cfg),
	}
}

// Init runs any startup commands.
func (a App) Init() tea.Cmd {
	return a.dashboard.Init()
}

// Update handles messages and routes them to the active screen.
func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return a, tea.Quit
		}
	}

	// Route to active screen.
	switch a.screen {
	case screenDashboard:
		m, cmd := a.dashboard.Update(msg)
		a.dashboard = m.(dashboardModel)
		return a, cmd
	}

	return a, nil
}

// View renders the current screen.
func (a App) View() string {
	switch a.screen {
	case screenDashboard:
		return a.dashboard.View()
	default:
		return lipgloss.NewStyle().Padding(1, 2).Render("Loading...")
	}
}
