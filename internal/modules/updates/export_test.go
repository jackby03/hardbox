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
package updates

// TestOptions configures file paths and family override for tests.
type TestOptions struct {
	Family             string
	APTSourcesList     string
	APTSourcesListDir  string
	APTAutoUpgrades    string
	APTUnattended      string
	APTTrustedGPG      string
	APTTrustedGPGDir   string
	USRShareKeyrings   string
	DNFAutomaticConfig string
}

// NewModuleForTest creates a Module with test-specific paths.
func NewModuleForTest(o TestOptions) *Module {
	return &Module{
		familyOverride:         o.Family,
		aptSourcesListPath:     o.APTSourcesList,
		aptSourcesListDir:      o.APTSourcesListDir,
		aptAutoUpgradesPath:    o.APTAutoUpgrades,
		aptUnattendedPath:      o.APTUnattended,
		aptTrustedGPGPath:      o.APTTrustedGPG,
		aptTrustedGPGDir:       o.APTTrustedGPGDir,
		usrShareKeyringsDir:    o.USRShareKeyrings,
		dnfAutomaticConfigPath: o.DNFAutomaticConfig,
	}
}

