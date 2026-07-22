package processes

import "github.com/hardbox-io/hardbox/internal/modules"

func checkPRC001() modules.Check {
	return modules.Check{ID: "prc-001", Title: "Process accounting installed and enabled", Description: "Verify acct or psacct is installed and active.", Remediation: "apt-get install acct && systemctl enable --now acct.", Severity: modules.SeverityMedium, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "1.5.1"}, {Framework: "NIST", Control: "AU-12"}}}
}
func checkPRC002() modules.Check {
	return modules.Check{ID: "prc-002", Title: "Core dumps disabled via limits.conf", Description: "Verify * hard core 0 is set in /etc/security/limits.conf.", Remediation: "Add '* hard core 0' to /etc/security/limits.conf.", Severity: modules.SeverityHigh, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "1.5.2"}, {Framework: "NIST", Control: "SI-16"}}}
}
func checkPRC003() modules.Check {
	return modules.Check{ID: "prc-003", Title: "Core dumps disabled via sysctl", Description: "Verify fs.suid_dumpable=0 in sysctl.", Remediation: "sysctl -w fs.suid_dumpable=0.", Severity: modules.SeverityHigh, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "1.5.2"}, {Framework: "STIG", Control: "V-238200"}}}
}
func checkPRC004() modules.Check {
	return modules.Check{ID: "prc-004", Title: "Default ulimit -c set to 0", Description: "Verify core file size limit is 0 in /etc/security/limits.conf.", Remediation: "Add '* soft core 0' to limits.conf.", Severity: modules.SeverityMedium, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "1.5.2"}}}
}
func checkPRC005() modules.Check {
	return modules.Check{ID: "prc-005", Title: "Process accounting log rotation configured", Description: "Verify /var/log/account has logrotate config.", Remediation: "Create /etc/logrotate.d/psacct.", Severity: modules.SeverityLow, Compliance: []modules.ComplianceRef{{Framework: "NIST", Control: "AU-12"}}}
}
