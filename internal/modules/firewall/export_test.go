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
package firewall

import "github.com/hardbox-io/hardbox/internal/distro"

// NewModuleForTest builds a firewall module with injectable dependencies.
func NewModuleForTest(
	run commandRunner,
	detect distroDetector,
	hasBinary binaryChecker,
	backendOverride string,
	ipv6DisablePath string,
) *Module {
	return &Module{
		run:             run,
		detectDistro:    detect,
		hasBinary:       hasBinary,
		backendOverride: backend(backendOverride),
		ipv6DisablePath: ipv6DisablePath,
	}
}

var (
	ParseUFWDefaults = parseUFWDefaults
	NftHasIPv6Rules  = nftHasIPv6Rules
)

func FakeDistroDebian() (*distro.Info, error) {
	return &distro.Info{ID: "ubuntu", Family: distro.FamilyDebian}, nil
}

func FakeDistroRHEL() (*distro.Info, error) {
	return &distro.Info{ID: "rocky", Family: distro.FamilyRHEL}, nil
}

