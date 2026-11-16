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

package databases

import "context"

// NewModuleForTest returns a Module with injected paths and a fake query
// function, so the audit can be exercised without a database server.
//
//   - mysqlConfs, pgHba, pgConf are comma-separated globs or literal paths
//   - dropIn overrides the path remediation would write
//   - query replaces the mysql client call
func NewModuleForTest(mysqlConfs, pgHba, pgConf, dropIn string, query func(ctx context.Context, q string) (string, error)) *Module {
	return &Module{
		mysqlConfGlobs: mysqlConfs,
		pgHbaGlobs:     pgHba,
		pgConfGlobs:    pgConf,
		mysqlDropIn:    dropIn,
		mysqlQuery:     query,
	}
}

var (
	// ParseMySQLOptions exposes the option parser.
	ParseMySQLOptions = parseMySQLOptions
	// HbaTrustRules exposes the pg_hba.conf parser.
	HbaTrustRules = hbaTrustRules
	// ParsePGConf exposes the postgresql.conf parser.
	ParsePGConf = parsePGConf
)
