package firewall

import "github.com/hardbox-io/hardbox/internal/modules"

func checkFW001() modules.Check {
	return modules.Check{
		ID:          "fw-001",
		Title:       "Firewall service enabled and active",
		Description: "Verify a supported firewall backend is installed and active.",
		Remediation: "Enable and start ufw, firewalld, or nftables.",
		Severity:    modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "3.5.1"}, {Framework: "NIST", Control: "SC-7"}, {Framework: "STIG", Control: "V-238270"}, {Framework: "PCI", Control: "1.3.1"}},
	}
}

func checkFW002() modules.Check {
	return modules.Check{
		ID:          "fw-002",
		Title:       "Default inbound policy is DROP",
		Description: "Validate the default inbound traffic policy is deny/drop.",
		Remediation: "Set default inbound policy to DROP.",
		Severity:    modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "3.5.1.1"}, {Framework: "NIST", Control: "SC-7"}, {Framework: "PCI", Control: "1.3.2"}},
	}
}

func checkFW003() modules.Check {
	return modules.Check{
		ID:          "fw-003",
		Title:       "Default outbound policy is DROP or ACCEPT",
		Description: "Validate outbound policy is explicitly set to DROP or ACCEPT.",
		Remediation: "Set explicit outbound default policy.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "3.5.1.2"}, {Framework: "NIST", Control: "SC-7"}},
	}
}

func checkFW004() modules.Check {
	return modules.Check{
		ID:          "fw-004",
		Title:       "Loopback traffic explicitly allowed",
		Description: "Ensure localhost traffic is explicitly allowed by firewall rules.",
		Remediation: "Allow loopback input/output traffic.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "3.5.1.3"}, {Framework: "NIST", Control: "SC-7"}},
	}
}

func checkFW005() modules.Check {
	return modules.Check{
		ID:          "fw-005",
		Title:       "No overly permissive sensitive port rules",
		Description: "Detect globally exposed sensitive ports from untrusted sources.",
		Remediation: "Restrict sensitive ports by source CIDR or disable unnecessary services.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "3.5.1.4"}, {Framework: "NIST", Control: "SC-7"}, {Framework: "PCI", Control: "1.3.4"}},
	}
}

func checkFW006() modules.Check {
	return modules.Check{
		ID:          "fw-006",
		Title:       "IPv6 rules present when IPv6 enabled",
		Description: "Ensure firewall coverage also exists for IPv6 traffic when enabled.",
		Remediation: "Enable IPv6 filtering in the selected firewall backend.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{{Framework: "CIS", Control: "3.5.2"}, {Framework: "NIST", Control: "SC-7"}},
	}
}
