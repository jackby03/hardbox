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
	audit        auditWorkflowModel
	applyConfirm applyConfirmModel
	applyFlow    applyProgressModel
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
		audit:     newAuditWorkflow(eng, cfg),
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
			case "d":
				a.audit = newAuditWorkflow(a.eng, a.cfg)
				a.screen = screenAudit
				return a, a.audit.Init()
			case "a":
				a.applyConfirm = newApplyConfirm(a.eng, a.cfg)
				a.screen = screenApplyConfirm
				return a, a.applyConfirm.Init()
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
				a.applyConfirm = newApplyConfirm(a.eng, a.cfg)
				a.screen = screenApplyConfirm
				return a, a.applyConfirm.Init()
			}
		case screenAudit:
			switch msg.String() {
			case "q", "esc":
				a.screen = screenDashboard
				return a, nil
			}
		case screenApplyConfirm:
			switch msg.String() {
			case "q", "esc":
				a.screen = screenDashboard
				return a, nil
			case "y":
				if a.applyConfirm.Ready() {
					a.applyFlow = newApplyProgress(a.applyConfirm.Plans())
					a.screen = screenApplyProgress
					return a, a.applyFlow.Init()
				}
			}
		case screenApplyProgress:
			switch msg.String() {
			case "q", "esc":
				if a.applyFlow.Done() {
					a.screen = screenDashboard
					return a, nil
				}
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
	case screenAudit:
		m, cmd := a.audit.Update(msg)
		a.audit = m.(auditWorkflowModel)
		return a, cmd
	case screenApplyConfirm:
		m, cmd := a.applyConfirm.Update(msg)
		a.applyConfirm = m.(applyConfirmModel)
		return a, cmd
	case screenApplyProgress:
		m, cmd := a.applyFlow.Update(msg)
		a.applyFlow = m.(applyProgressModel)
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
	case screenAudit:
		return a.audit.View()
	case screenApplyConfirm:
		return a.applyConfirm.View()
	case screenApplyProgress:
		return a.applyFlow.View()
	default:
		return lipgloss.NewStyle().Padding(1, 2).Render("Loading...")
	}
}

