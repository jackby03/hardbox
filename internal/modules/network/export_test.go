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
package network

// TestOptions configures module file paths for tests.
type TestOptions struct {
	IPv6DisablePath string
	ModprobeDir     string
	HostsAllowPath  string
	HostsDenyPath   string
	WirelessPath    string
	PasswdPath      string
}

// NewModuleForTest returns a module with test path overrides.
func NewModuleForTest(o TestOptions) *Module {
	return &Module{
		ipv6DisablePath: o.IPv6DisablePath,
		modprobeDir:     o.ModprobeDir,
		hostsAllowPath:  o.HostsAllowPath,
		hostsDenyPath:   o.HostsDenyPath,
		wirelessPath:    o.WirelessPath,
		passwdPath:      o.PasswdPath,
	}
}

