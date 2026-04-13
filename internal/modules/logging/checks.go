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
package logging

import "github.com/hardbox-io/hardbox/internal/modules"

func checkLOG001() modules.Check {
	return modules.Check{
		ID:          "log-001",
		Title:       "Syslog service installed and active",
		Description: "rsyslog or syslog-ng must be installed and actively running.",
		Remediation: "Install and enable rsyslog: apt install rsyslog && systemctl enable --now rsyslog",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.2.1.1"},
			{Framework: "NIST", Control: "AU-9"},
			{Framework: "PCI", Control: "10.5.3"},
		},
	}
}

func checkLOG002() modules.Check {
	return modules.Check{
		ID:          "log-002",
		Title:       "Rsyslog configured to send logs to remote server",
		Description: "Logs should be forwarded to a centralised log server for tamper-evident storage.",
		Remediation: "Add @@loghost:514 or equivalent omfwd action to /etc/rsyslog.conf",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.2.1.5"},
			{Framework: "NIST", Control: "AU-4"},
			{Framework: "PCI", Control: "10.5.3"},
			{Framework: "HIPAA", Control: "164.312(b)"},
		},
	}
}

func checkLOG003() modules.Check {
	return modules.Check{
		ID:          "log-003",
		Title:       "Rsyslog config file permissions restricted",
		Description: "/etc/rsyslog.conf must not be world-readable or world-writable.",
		Remediation: "chmod 640 /etc/rsyslog.conf && chown root:adm /etc/rsyslog.conf",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.2.1.4"},
			{Framework: "NIST", Control: "AU-9"},
		},
	}
}

func checkLOG004() modules.Check {
	return modules.Check{
		ID:          "log-004",
		Title:       "Journald persistent storage enabled",
		Description: "journald Storage must be set to 'persistent' so logs survive reboots.",
		Remediation: "Set Storage=persistent in /etc/systemd/journald.conf and restart systemd-journald",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.2.2.1"},
			{Framework: "NIST", Control: "AU-11"},
		},
	}
}

func checkLOG005() modules.Check {
	return modules.Check{
		ID:          "log-005",
		Title:       "Journald forwarding to syslog enabled",
		Description: "journald should forward messages to rsyslog/syslog-ng for centralised handling.",
		Remediation: "Set ForwardToSyslog=yes in /etc/systemd/journald.conf",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.2.2.2"},
			{Framework: "NIST", Control: "AU-12"},
		},
	}
}

func checkLOG006() modules.Check {
	return modules.Check{
		ID:          "log-006",
		Title:       "Logrotate configured for all logs",
		Description: "/etc/logrotate.conf or /etc/logrotate.d/ must be present to manage log retention.",
		Remediation: "Install logrotate: apt install logrotate",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.2.3"},
			{Framework: "NIST", Control: "AU-11"},
			{Framework: "PCI", Control: "10.7.1"},
		},
	}
}

func checkLOG007() modules.Check {
	return modules.Check{
		ID:          "log-007",
		Title:       "Log files not world-readable",
		Description: "Files under /var/log must not have the world-read bit set.",
		Remediation: "fix -R o-r /var/log; consider restricting with chmod 640 or 600",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.2.1.3"},
			{Framework: "NIST", Control: "AU-9"},
			{Framework: "STIG", Control: "V-238302"},
			{Framework: "HIPAA", Control: "164.312(b)"},
		},
	}
}

