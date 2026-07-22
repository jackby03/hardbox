package integrity

import "github.com/hardbox-io/hardbox/internal/modules"

func checkINT001() modules.Check {
	return modules.Check{
		ID:          "int-001",
		Title:       "File integrity tool (AIDE or Tripwire) installed",
		Description: "Verify AIDE or Tripwire binary is available on the system.",
		Remediation: "apt-get install aide or yum install aide.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.3.1"}, {Framework: "NIST", Control: "SI-7"}, {Framework: "STIG", Control: "V-238283"}},
	}
}

func checkINT002() modules.Check {
	return modules.Check{
		ID:          "int-002",
		Title:       "Integrity database initialized",
		Description: "Check if AIDE/Tripwire integrity database exists.",
		Remediation: "Run aideinit or tripwire --init after installing.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.3.1"}, {Framework: "NIST", Control: "SI-7"}},
	}
}

func checkINT003() modules.Check {
	return modules.Check{
		ID:          "int-003",
		Title:       "Integrity check scheduled via cron or systemd timer",
		Description: "Verify AIDE/Tripwire runs on a schedule.",
		Remediation: "Create cron job or systemd timer for daily aide --check.",
		Severity:    modules.SeverityMedium,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.3.2"}, {Framework: "NIST", Control: "SI-7"}},
	}
}

func checkINT004() modules.Check {
	return modules.Check{
		ID:          "int-004",
		Title:       "Integrity check results exist from last 7 days",
		Description: "Check for recent AIDE/Tripwire run output.",
		Remediation: "Ensure daily runs are producing output to /var/log/aide/ or /var/lib/tripwire/report/.",
		Severity:    modules.SeverityMedium,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.3.2"}, {Framework: "NIST", Control: "SI-7"}},
	}
}

func checkINT005() modules.Check {
	return modules.Check{
		ID:          "int-005",
		Title:       "/etc/aide/aide.conf or /etc/tripwire/tw.cfg has restricted permissions",
		Description: "Verify integrity tool config is not world-readable.",
		Remediation: "chmod 0600 /etc/aide/aide.conf.",
		Severity:    modules.SeverityMedium,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.3.1"}},
	}
}
