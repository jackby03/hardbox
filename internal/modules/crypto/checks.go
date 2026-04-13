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

import "github.com/hardbox-io/hardbox/internal/modules"

func checkCRY001() modules.Check {
	return modules.Check{
		ID:          "cry-001",
		Title:       "System crypto policy set to DEFAULT or stronger",
		Description: "Validate system-wide cryptographic baseline is not legacy.",
		Remediation: "Set crypto policy to DEFAULT/FUTURE/FIPS or harden OpenSSL minimum protocol.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "NIST", Control: "SC-17"}, {Framework: "PCI", Control: "4.2.1"}},
	}
}

func checkCRY002() modules.Check {
	return modules.Check{
		ID:          "cry-002",
		Title:       "TLS 1.0 and 1.1 disabled system-wide",
		Description: "Ensure minimum protocol enforces TLSv1.2 or stronger.",
		Remediation: "Set MinProtocol to TLSv1.2+ and apply policy.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "NIST", Control: "SC-8"}, {Framework: "PCI", Control: "4.2.1"}},
	}
}

func checkCRY003() modules.Check {
	return modules.Check{
		ID:          "cry-003",
		Title:       "SSLv2 and SSLv3 disabled",
		Description: "Ensure obsolete SSL protocol versions are disabled.",
		Remediation: "Disable SSLv2/SSLv3 via policy or OpenSSL options.",
		Severity:    modules.SeverityCritical,
		Compliance:  []modules.ComplianceRef{{Framework: "NIST", Control: "SC-8"}, {Framework: "PCI", Control: "4.2.1"}},
	}
}

func checkCRY004() modules.Check {
	return modules.Check{
		ID:          "cry-004",
		Title:       "Weak ciphers removed",
		Description: "Ensure RC4, DES, 3DES, and export ciphers are removed.",
		Remediation: "Harden CipherString/crypto policy to exclude weak ciphers.",
		Severity:    modules.SeverityCritical,
		Compliance:  []modules.ComplianceRef{{Framework: "NIST", Control: "SC-8"}, {Framework: "PCI", Control: "4.2.1"}},
	}
}

func checkCRY005() modules.Check {
	return modules.Check{
		ID:          "cry-005",
		Title:       "FIPS 140-2 mode available",
		Description: "Check if kernel FIPS mode is enabled when required by policy.",
		Remediation: "Enable FIPS mode for regulated environments where mandated.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "NIST", Control: "SC-13"}},
	}
}

func checkCRY006() modules.Check {
	return modules.Check{
		ID:          "cry-006",
		Title:       "GnuPG keyid format is long",
		Description: "Avoid short key IDs by enforcing long keyid display format.",
		Remediation: "Set 'keyid-format 0xlong' in gpg.conf.",
		Severity:    modules.SeverityLow,
	}
}

