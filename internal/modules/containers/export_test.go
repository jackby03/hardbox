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
package containers

// NewModuleForTest builds a containers module with injectable dependencies.
func NewModuleForTest(
	run commandRunner,
	hasBinary binaryChecker,
	daemonJSONPath string,
	auditRulesDir string,
) *Module {
	return &Module{
		run:            run,
		hasBinary:      hasBinary,
		daemonJSONPath: daemonJSONPath,
		auditRulesDir:  auditRulesDir,
	}
}

// Exported format strings so tests can build matching command keys.
var (
	SecurityOptsFmt = securityOptsFmt
	PrivilegedFmt   = privilegedFmt
	MountsFmt       = mountsFmt
)

