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
package crypto

import "github.com/hardbox-io/hardbox/internal/distro"

// NewModuleForTest creates a module instance with injectable file paths and distro detector.
func NewModuleForTest(
	detect distroDetector,
	cryptoPolicyPath, opensslConfPath, fipsEnabledPath, systemGPGConf, userGPGConf, homeDir string,
) *Module {
	return &Module{
		detectDistro:     detect,
		cryptoPolicyPath: cryptoPolicyPath,
		opensslConfPath:  opensslConfPath,
		fipsEnabledPath:  fipsEnabledPath,
		systemGPGConf:    systemGPGConf,
		userGPGConf:      userGPGConf,
		homeDir:          homeDir,
	}
}

var (
	PolicyIsDefaultOrStronger = policyIsDefaultOrStronger
	ParseOpenSSLMinProtocol   = parseOpenSSLMinProtocol
	ParseOpenSSLCipherString  = parseOpenSSLCipherString
	GPGUsesLongKeyID          = gpgUsesLongKeyID
)

func FakeDistroDebian() (*distro.Info, error) {
	return &distro.Info{ID: "debian", Family: distro.FamilyDebian}, nil
}

func FakeDistroRHEL() (*distro.Info, error) {
	return &distro.Info{ID: "rhel", Family: distro.FamilyRHEL}, nil
}

