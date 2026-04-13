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
package users

// NewModuleForTest returns a Module with injected paths for white-box testing.
func NewModuleForTest(
	run commandRunner,
	loginDefs, pamDir, passwdFile, sudoers, sudoersDir, useraddConf string,
) *Module {
	return &Module{
		run:         run,
		loginDefs:   loginDefs,
		pamDir:      pamDir,
		passwdFile:  passwdFile,
		sudoers:     sudoers,
		sudoersDir:  sudoersDir,
		useraddConf: useraddConf,
	}
}

// ParseLoginDefsKey exposes the pure helper for unit tests.
var ParseLoginDefsKey = parseLoginDefsKey

// SetLoginDefsKey exposes the pure helper for unit tests.
var SetLoginDefsKey = setLoginDefsKey

// SetSimpleKey exposes the pure helper for unit tests.
var SetSimpleKey = setSimpleKey

