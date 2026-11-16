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

import "github.com/hardbox-io/hardbox/internal/modules"

// Compliance mapping note: like the databases module, this one carries no CIS
// control numbers. The CIS nginx and Apache benchmarks use their own numbering
// that does not line up with the OS-level CIS controls the rest of hardbox
// quotes, and a plausible-looking identifier in a compliance reference is worse
// than an empty column.

func checkWEB001() modules.Check {
	return modules.Check{
		ID:          "web-001",
		Title:       "nginx does not advertise its version",
		Description: "server_tokens off stops nginx from adding its version and OS to error pages and the Server header.",
		Remediation: "Set 'server_tokens off;' in the http context, for example in /etc/nginx/conf.d/99-hardbox.conf.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "CM-7"},
			{Framework: "PCI", Control: "2.2"},
		},
	}
}

func checkWEB002() modules.Check {
	return modules.Check{
		ID:          "web-002",
		Title:       "nginx directory listing is disabled",
		Description: "autoindex on exposes the contents of directories that have no index file.",
		Remediation: "Set 'autoindex off;' in the http context, or remove every 'autoindex on;' from the server blocks.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "AC-3"},
			{Framework: "PCI", Control: "6.5"},
		},
	}
}

func checkWEB003() modules.Check {
	return modules.Check{
		ID:          "web-003",
		Title:       "nginx disables TLS 1.0 and 1.1",
		Description: "Both protocol versions are deprecated and fail modern compliance baselines.",
		Remediation: "Set 'ssl_protocols TLSv1.2 TLSv1.3;' in the http context.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-8"},
			{Framework: "PCI", Control: "4.1"},
		},
	}
}

func checkWEB004() modules.Check {
	return modules.Check{
		ID:          "web-004",
		Title:       "nginx sets baseline security headers",
		Description: "X-Content-Type-Options, X-Frame-Options and Referrer-Policy mitigate MIME sniffing, clickjacking and referrer leakage.",
		Remediation: "Add the three add_header directives in the http context.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-18"},
			{Framework: "PCI", Control: "6.5"},
		},
	}
}

func checkWEB005() modules.Check {
	return modules.Check{
		ID:          "web-005",
		Title:       "Apache does not advertise its version",
		Description: "ServerTokens Prod and ServerSignature Off keep the version and the server banner out of responses and error pages.",
		Remediation: "Set 'ServerTokens Prod' and 'ServerSignature Off' in the server config.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "CM-7"},
			{Framework: "PCI", Control: "2.2"},
		},
	}
}

func checkWEB006() modules.Check {
	return modules.Check{
		ID:          "web-006",
		Title:       "Apache directory listing is disabled",
		Description: "The Indexes option makes Apache generate a directory listing when no index file exists.",
		Remediation: "Ensure no configuration enables 'Options Indexes'; use 'Options -Indexes' for the document root.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "AC-3"},
			{Framework: "PCI", Control: "6.5"},
		},
	}
}

func checkWEB007() modules.Check {
	return modules.Check{
		ID:          "web-007",
		Title:       "Apache disables TLS 1.0 and 1.1",
		Description: "SSLProtocol must not leave the deprecated protocol versions enabled.",
		Remediation: "Set 'SSLProtocol -all +TLSv1.2 +TLSv1.3' in the server config.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-8"},
			{Framework: "PCI", Control: "4.1"},
		},
	}
}

func checkWEB008() modules.Check {
	return modules.Check{
		ID:          "web-008",
		Title:       "Apache sets baseline security headers",
		Description: "The same three headers as the nginx check, via mod_headers.",
		Remediation: "Add 'Header always set' directives for X-Content-Type-Options, X-Frame-Options and Referrer-Policy.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-18"},
			{Framework: "PCI", Control: "6.5"},
		},
	}
}
