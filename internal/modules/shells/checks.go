package shells

import "github.com/hardbox-io/hardbox/internal/modules"

func checkSHL001() modules.Check {
	return modules.Check{ID: "shl-001", Title: "TMOUT is set in /etc/profile.d/", Description: "Verify shell timeout is configured.", Remediation: "Add TMOUT=900 to /etc/profile.d/timeout.sh.", Severity: modules.SeverityMedium, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "5.4.4"}, {Framework: "STIG", Control: "V-238220"}}}
}
func checkSHL002() modules.Check {
	return modules.Check{ID: "shl-002", Title: "HISTSIZE limited to <= 2000", Description: "Limit command history size.", Remediation: "Set HISTSIZE=2000 in /etc/profile.", Severity: modules.SeverityLow, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "5.4.4"}}}
}
func checkSHL003() modules.Check {
	return modules.Check{ID: "shl-003", Title: "Shell timeout configured in /etc/bash.bashrc", Description: "Verify TMOUT or readonly TMOUT is set.", Remediation: "Add readonly TMOUT=900 to /etc/bash.bashrc.", Severity: modules.SeverityMedium, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "5.4.4"}, {Framework: "STIG", Control: "V-238220"}}}
}
func checkSHL004() modules.Check {
	return modules.Check{ID: "shl-004", Title: ".bashrc and .profile have restricted permissions", Description: "User shell config files should not be world-writable.", Remediation: "chmod 0640 ~/.bashrc ~/.profile.", Severity: modules.SeverityMedium, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "5.4.4"}}}
}
func checkSHL005() modules.Check {
	return modules.Check{ID: "shl-005", Title: "HISTFILESIZE limited to <= 2000", Description: "Limit history file size.", Remediation: "Set HISTFILESIZE=2000.", Severity: modules.SeverityLow, Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "5.4.4"}}}
}
