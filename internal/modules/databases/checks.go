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

import "github.com/hardbox-io/hardbox/internal/modules"

// Compliance mapping note: this module deliberately carries no CIS control
// numbers. The CIS MySQL and PostgreSQL benchmarks use their own numbering that
// does not line up with the OS-level CIS controls the rest of hardbox quotes, and
// inventing plausible-looking identifiers in a compliance reference is worse than
// leaving the column empty. NIST and PCI-DSS controls below are defensible as-is.

func checkDB001() modules.Check {
	return modules.Check{
		ID:          "db-001",
		Title:       "MySQL/MariaDB does not listen on all interfaces",
		Description: "bind-address should be a loopback address unless the server must accept remote connections.",
		Remediation: "Set 'bind-address = 127.0.0.1' under [mysqld] in /etc/mysql/conf.d/99-hardbox.cnf.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-7"},
			{Framework: "PCI", Control: "1.3"},
		},
	}
}

func checkDB002() modules.Check {
	return modules.Check{
		ID:          "db-002",
		Title:       "MySQL/MariaDB LOCAL INFILE is disabled",
		Description: "LOCAL INFILE lets a client make the server read arbitrary local files into a table.",
		Remediation: "Set 'local_infile = 0' under [mysqld] in /etc/mysql/conf.d/99-hardbox.cnf.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-7"},
			{Framework: "PCI", Control: "6.3"},
		},
	}
}

func checkDB003() modules.Check {
	return modules.Check{
		ID:          "db-003",
		Title:       "PostgreSQL pg_hba.conf has no 'trust' authentication",
		Description: "'trust' accepts any connection without a password, so any reachable client is authenticated as the named role.",
		Remediation: "Replace 'trust' with 'scram-sha-256' (or 'peer' for local sockets) in every pg_hba.conf rule.",
		Severity:    modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "IA-2"},
			{Framework: "PCI", Control: "8.3"},
		},
	}
}

func checkDB004() modules.Check {
	return modules.Check{
		ID:          "db-004",
		Title:       "PostgreSQL password_encryption uses scram-sha-256",
		Description: "md5 password hashes are crackable offline and are deprecated by PostgreSQL.",
		Remediation: "Run: ALTER SYSTEM SET password_encryption = 'scram-sha-256'; SELECT pg_reload_conf();",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "IA-5"},
			{Framework: "PCI", Control: "8.3"},
		},
	}
}

func checkDB005() modules.Check {
	return modules.Check{
		ID:          "db-005",
		Title:       "PostgreSQL listen_addresses is restricted",
		Description: "listen_addresses should not be '*' unless the server must accept connections on every interface.",
		Remediation: "Run: ALTER SYSTEM SET listen_addresses = 'localhost'; SELECT pg_reload_conf();",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-7"},
			{Framework: "PCI", Control: "1.3"},
		},
	}
}

func checkDB006() modules.Check {
	return modules.Check{
		ID:          "db-006",
		Title:       "MySQL/MariaDB has no anonymous accounts",
		Description: "An account with an empty user name matches any user that has no explicit account.",
		Remediation: "SELECT user, host FROM mysql.user WHERE user = ''; then DROP USER ''@'<host>' for each row.",
		Severity:    modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "IA-2"},
			{Framework: "PCI", Control: "8.3"},
		},
	}
}

func checkDB007() modules.Check {
	return modules.Check{
		ID:          "db-007",
		Title:       "MySQL/MariaDB root is not reachable from any host",
		Description: "A root account with host '%' allows administrative login from anywhere the server is reachable.",
		Remediation: "SELECT user, host FROM mysql.user WHERE user = 'root' AND host NOT IN ('localhost', '127.0.0.1', '::1');",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "AC-6"},
			{Framework: "PCI", Control: "2.2"},
		},
	}
}

func checkDB008() modules.Check {
	return modules.Check{
		ID:          "db-008",
		Title:       "No leftover 'test' database",
		Description: "The 'test' database shipped with legacy MySQL installs is world-accessible and should be removed.",
		Remediation: "SHOW DATABASES LIKE 'test'; then DROP DATABASE test;",
		Severity:    modules.SeverityLow,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "CM-7"},
			{Framework: "PCI", Control: "2.2"},
		},
	}
}
