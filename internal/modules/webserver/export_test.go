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

package webserver

// NewModuleForTest returns a Module with injected globs and drop-in paths.
//
// Every argument must be an explicit path: an empty string falls back to the
// host's real configuration, which makes a test depend on the machine it runs on.
func NewModuleForTest(nginxGlobs, apacheGlobs, nginxDropIn, apacheDropIn string) *Module {
	return &Module{
		nginxGlobs:   nginxGlobs,
		apacheGlobs:  apacheGlobs,
		nginxDropIn:  nginxDropIn,
		apacheDropIn: apacheDropIn,
	}
}

var (
	// ExpandGlobs exposes the glob resolver.
	ExpandGlobs = expandGlobs
	// NginxStatements exposes the statement scanner.
	NginxStatements = nginxStatements
	// ApacheDirectives exposes the directive scanner.
	ApacheDirectives = apacheDirectives
	// SSLProtocolAllowsLegacy exposes the SSLProtocol evaluator.
	SSLProtocolAllowsLegacy = sslProtocolAllowsLegacy
)
