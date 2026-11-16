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

package nameservices

// NewModuleForTest returns a Module with every path injected.
//
// Tests must pass explicit paths for all six files: reading the host's real
// /etc/hosts or /etc/resolv.conf would make the result depend on the machine.
func NewModuleForTest(hostsPath, nsswitchPath, resolvPath, resolvedConf, unboundConf, dnsmasqConf string) *Module {
	return &Module{
		hostsPath:    hostsPath,
		nsswitchPath: nsswitchPath,
		resolvPath:   resolvPath,
		resolvedConf: resolvedConf,
		unboundConf:  unboundConf,
		dnsmasqConf:  dnsmasqConf,
	}
}

var (
	// HostsLine exposes the nsswitch hosts-line reader.
	HostsLine = hostsLine
	// FilesBeforeDNS exposes the ordering analysis.
	FilesBeforeDNS = filesBeforeDNS
	// NormalizeHostsLine exposes the rewriter.
	NormalizeHostsLine = normalizeHostsLine
	// ResolvNameservers exposes the resolv.conf reader.
	ResolvNameservers = resolvNameservers
	// IsLoopbackNS exposes the local-resolver predicate.
	IsLoopbackNS = isLoopbackNS
)
