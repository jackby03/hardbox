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
	"testing"
)

// TestRegisteredModules_ContainsSSH verifies that the SSH module is present in
// the built-in registry so that audit and apply flows include SSH checks.
func TestRegisteredModules_ContainsSSH(t *testing.T) {
	mods := registeredModules()
	for _, m := range mods {
		if m.Name() == "ssh" {
			return
		}
	}
	t.Fatal("ssh module is not registered in registeredModules(); add &ssh.Module{} to registry.go")
}

// TestRegisteredModules_NoDuplicates ensures no module name appears more than once.
func TestRegisteredModules_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, m := range registeredModules() {
		if seen[m.Name()] {
			t.Errorf("duplicate module name %q in registeredModules()", m.Name())
		}
		seen[m.Name()] = true
	}
}

