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

import "github.com/hardbox-io/hardbox/internal/modules"

// Compliance mapping note: this module carries no CIS control numbers. The CIS
// benchmark sections covering name resolution are organised differently from the
// OS-level controls quoted elsewhere in hardbox, and a plausible-looking
// identifier in a compliance reference is worse than an empty column.

func checkDNS001() modules.Check {
	return modules.Check{
		ID:          "dns-001",
		Title:       "/etc/hosts maps localhost on both loopback addresses",
		Description: "A host with only one of the two loopback mappings resolves localhost inconsistently between IPv4 and IPv6, which some daemons rely on.",
		Remediation: "Ensure /etc/hosts contains '127.0.0.1 localhost' and '::1 localhost ip6-localhost ip6-loopback'.",
		Severity:    modules.SeverityLow,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-20"},
		},
	}
}

func checkDNS002() modules.Check {
	return modules.Check{
		ID:          "dns-002",
		Title:       "/etc/hosts is not writable by group or other",
		Description: "A writable /etc/hosts lets any local user redirect name resolution for every process on the host.",
		Remediation: "chown root:root /etc/hosts && chmod 0644 /etc/hosts",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "AC-6"},
		},
	}
}

func checkDNS003() modules.Check {
	return modules.Check{
		ID:          "dns-003",
		Title:       "nsswitch.conf resolves hosts from files before DNS",
		Description: "If dns precedes files, a resolver answer overrides /etc/hosts and local overrides stop being authoritative.",
		Remediation: "Set the hosts line in /etc/nsswitch.conf to 'hosts: files dns ...'.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-20"},
		},
	}
}

func checkDNS004() modules.Check {
	return modules.Check{
		ID:          "dns-004",
		Title:       "The local resolver validates DNSSEC",
		Description: "Without validation, a spoofed DNS answer is indistinguishable from a real one.",
		Remediation: "Enable DNSSEC in the resolver: 'DNSSEC=yes' for systemd-resolved, 'auto-trust-anchor-file' for unbound, 'dnssec' for dnsmasq.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-8"},
			{Framework: "NIST", Control: "SC-20"},
		},
	}
}

func checkDNS005() modules.Check {
	return modules.Check{
		ID:          "dns-005",
		Title:       "Name resolution does not use plaintext DNS to external servers",
		Description: "resolv.conf pointing at a remote nameserver sends every query unencrypted and unauthenticated over the network.",
		Remediation: "Point resolv.conf at a local resolver (127.0.0.1 or 127.0.0.53) and configure that resolver to use DNS-over-TLS upstream.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "NIST", Control: "SC-8"},
		},
	}
}
