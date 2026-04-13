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
package mac

import "context"

// TestOptions customizes module internals for tests.
type TestOptions struct {
	Backend         string
	SELinuxConfig   string
	AppArmorEnabled string
	Runner          func(ctx context.Context, name string, args ...string) (string, error)
}

// NewModuleForTest returns a Module with injected test hooks.
func NewModuleForTest(o TestOptions) *Module {
	return &Module{
		run:             o.Runner,
		backendOverride: o.Backend,
		selinuxConfig:   o.SELinuxConfig,
		apparmorEnabled: o.AppArmorEnabled,
	}
}

