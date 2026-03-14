package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/engine"
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
	eng    *engine.Engine
	screen screen
	width  int
	height int

	dashboard    dashboardModel
	modules      modulesModel
	moduleDetail moduleDetailModel
}

// NewApp creates the root model, wiring in the config.
func NewApp(cfg *config.Config) App {
	eng := engine.New(cfg)
	return App{
		cfg:       cfg,
		eng:       eng,
		screen:    screenDashboard,
		dashboard: newDashboard(cfg),
		modules:   newModules(eng),
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
		a.moduleDetail.height = msg.Height

	case tea.KeyMsg:
		// ctrl+c always quits regardless of screen
		if msg.String() == "ctrl+c" {
			return a, tea.Quit
		}

		// Screen-specific keybinds take precedence over global ones
		switch a.screen {
		case screenDashboard:
			switch msg.String() {
			case "q":
				return a, tea.Quit
			case "enter":
				a.screen = screenModules
				return a, nil
			}
		case screenModules:
			switch msg.String() {
			case "q", "esc":
				a.screen = screenDashboard
				return a, nil
			case "enter":
				mod := a.modules.modules[a.modules.selected]
				a.moduleDetail = newModuleDetail(a.eng, mod, a.height)
				a.screen = screenModuleDetail
				return a, a.moduleDetail.Init()
			}
		case screenModuleDetail:
			switch msg.String() {
			case "q", "esc":
				a.screen = screenModules
				return a, nil
			case "a":
				a.screen = screenApplyConfirm
				return a, nil
			}
		}
	}

	// Route to active screen.
	switch a.screen {
	case screenDashboard:
		m, cmd := a.dashboard.Update(msg)
		a.dashboard = m.(dashboardModel)
		return a, cmd
	case screenModules:
		m, cmd := a.modules.Update(msg)
		a.modules = m.(modulesModel)
		return a, cmd
	case screenModuleDetail:
		m, cmd := a.moduleDetail.Update(msg)
		a.moduleDetail = m.(moduleDetailModel)
		return a, cmd
	}

	return a, nil
}

// View renders the current screen.
func (a App) View() string {
	switch a.screen {
	case screenDashboard:
		return a.dashboard.View()
	case screenModules:
		return a.modules.View()
	case screenModuleDetail:
		return a.moduleDetail.View()
	default:
		return lipgloss.NewStyle().Padding(1, 2).Render("Loading...")
	}
}
