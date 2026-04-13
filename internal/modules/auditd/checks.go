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
package auditd

import "github.com/hardbox-io/hardbox/internal/modules"

func checkAUD001() modules.Check {
	return modules.Check{
		ID:          "aud-001",
		Title:       "execve syscall auditing by non-root",
		Description: "Audit all execve syscalls made by non-privileged users.",
		Remediation: "Add -a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k exec",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.3"},
			{Framework: "NIST", Control: "AU-12"},
			{Framework: "PCI", Control: "10.2.7"},
		},
	}
}

func checkAUD002() modules.Check {
	return modules.Check{
		ID:          "aud-002",
		Title:       "Unauthorized file access attempts audited",
		Description: "Audit failed open/openat calls with EACCES or EPERM by non-privileged users.",
		Remediation: "Add -a always,exit -F arch=b64 -S open,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.5"},
			{Framework: "NIST", Control: "AU-12"},
			{Framework: "STIG", Control: "V-238285"},
		},
	}
}

func checkAUD003() modules.Check {
	return modules.Check{
		ID:          "aud-003",
		Title:       "User/group identity file modifications audited",
		Description: "Audit changes to /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow.",
		Remediation: "Add -w /etc/passwd -p wa -k identity (and shadow, group, gshadow).",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.6"},
			{Framework: "NIST", Control: "AU-12"},
			{Framework: "STIG", Control: "V-238286"},
		},
	}
}

func checkAUD004() modules.Check {
	return modules.Check{
		ID:          "aud-004",
		Title:       "sudo usage logging",
		Description: "Audit writes and attribute changes on /etc/sudoers and /etc/sudoers.d/.",
		Remediation: "Add -w /etc/sudoers -p wa -k sudo",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.11"},
			{Framework: "NIST", Control: "AU-12"},
			{Framework: "PCI", Control: "10.2.5"},
		},
	}
}

func checkAUD005() modules.Check {
	return modules.Check{
		ID:          "aud-005",
		Title:       "Login/logout/SSH events audited",
		Description: "Audit faillog, lastlog, and faillock paths for login events.",
		Remediation: "Add -w /var/log/faillog -p wa -k logins",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.8"},
			{Framework: "NIST", Control: "AC-17"},
			{Framework: "PCI", Control: "10.2.4"},
		},
	}
}

func checkAUD006() modules.Check {
	return modules.Check{
		ID:          "aud-006",
		Title:       "Kernel module loading audited",
		Description: "Audit init_module, finit_module, delete_module syscalls and modprobe.",
		Remediation: "Add -a always,exit -F arch=b64 -S init_module,finit_module -k modules",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.17"},
			{Framework: "NIST", Control: "CM-7"},
			{Framework: "STIG", Control: "V-238289"},
		},
	}
}

func checkAUD007() modules.Check {
	return modules.Check{
		ID:          "aud-007",
		Title:       "chown/chmod/setuid operations audited",
		Description: "Audit discretionary permissions changes by non-privileged users.",
		Remediation: "Add -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.7"},
			{Framework: "NIST", Control: "AU-12"},
			{Framework: "STIG", Control: "V-238287"},
		},
	}
}

func checkAUD008() modules.Check {
	return modules.Check{
		ID:          "aud-008",
		Title:       "Network config changes audited",
		Description: "Audit writes to /etc/hosts, /etc/sysconfig/network, and sethostname.",
		Remediation: "Add -w /etc/hosts -p wa -k network",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.16"},
			{Framework: "NIST", Control: "AU-12"},
		},
	}
}

func checkAUD009() modules.Check {
	return modules.Check{
		ID:          "aud-009",
		Title:       "Audit log immutability enabled",
		Description: "The -e 2 flag makes audit rules immutable until reboot.",
		Remediation: "Add -e 2 as the last line of your rules.",
		Severity:    modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.18"},
			{Framework: "NIST", Control: "AU-9"},
			{Framework: "STIG", Control: "V-238291"},
			{Framework: "PCI", Control: "10.5.2"},
		},
	}
}

func checkAUD010() modules.Check {
	return modules.Check{
		ID:          "aud-010",
		Title:       "Audit log file size configured",
		Description: "max_log_file in auditd.conf should be >= 8 MB.",
		Remediation: "Set max_log_file = 8 in /etc/audit/auditd.conf",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.1.1"},
			{Framework: "NIST", Control: "AU-11"},
			{Framework: "PCI", Control: "10.7.1"},
		},
	}
}

func checkAUD011() modules.Check {
	return modules.Check{
		ID:          "aud-011",
		Title:       "Audit log full action configured",
		Description: "max_log_file_action should be keep_logs or rotate to prevent log loss.",
		Remediation: "Set max_log_file_action = keep_logs in /etc/audit/auditd.conf",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.1.2"},
			{Framework: "NIST", Control: "AU-5"},
			{Framework: "PCI", Control: "10.7.1"},
		},
	}
}

func checkAUD012() modules.Check {
	return modules.Check{
		ID:          "aud-012",
		Title:       "Audit space_left_action configured",
		Description: "space_left_action should be email, syslog, or exec to alert on low disk.",
		Remediation: "Set space_left_action = email in /etc/audit/auditd.conf",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.1.3"},
			{Framework: "NIST", Control: "AU-5"},
		},
	}
}

func checkAUD013() modules.Check {
	return modules.Check{
		ID:          "aud-013",
		Title:       "auditd service enabled and active",
		Description: "The auditd service must be enabled at boot and currently running.",
		Remediation: "Run: systemctl enable --now auditd",
		Severity:    modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "4.1.1"},
			{Framework: "NIST", Control: "AU-12"},
			{Framework: "STIG", Control: "V-238283"},
			{Framework: "PCI", Control: "10.6.3"},
		},
	}
}

