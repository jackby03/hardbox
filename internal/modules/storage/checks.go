package storage

import "github.com/hardbox-io/hardbox/internal/modules"

func checkSTG001() modules.Check {
	return modules.Check{
		ID:          "stg-001",
		Title:       "LUKS/dm-crypt enabled on sensitive partitions",
		Description: "Verify /home, /var, /tmp have LUKS encryption configured via /etc/crypttab or lsblk.",
		Remediation: "Set up LUKS on partition and add entry to /etc/crypttab.",
		Severity:    modules.SeverityCritical,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.1.20"}, {Framework: "NIST", Control: "SC-28"}},
	}
}

func checkSTG002() modules.Check {
	return modules.Check{
		ID:          "stg-002",
		Title:       "Encrypted swap partition or no swap",
		Description: "Ensure swap is either encrypted (via crypttab) or disabled entirely.",
		Remediation: "Configure /etc/crypttab for encrypted swap or disable swap via swapoff and /etc/fstab.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "NIST", Control: "SC-28"}},
	}
}

func checkSTG003() modules.Check {
	return modules.Check{
		ID:          "stg-003",
		Title:       "/etc/crypttab entries have correct permissions",
		Description: "Verify /etc/crypttab has 0600 permissions and root:root ownership.",
		Remediation: "chmod 0600 /etc/crypttab; chown root:root /etc/crypttab.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.1.21"}},
	}
}

func checkSTG004() modules.Check {
	return modules.Check{
		ID:          "stg-004",
		Title:       "No plain-text swap detected in /etc/fstab",
		Description: "Scan /etc/fstab for swap entries pointing to unencrypted devices.",
		Remediation: "Remove unprotected swap entries or configure crypttab with LUKS-encrypted swap.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "NIST", Control: "SC-28"}},
	}
}

func checkSTG005() modules.Check {
	return modules.Check{
		ID:          "stg-005",
		Title:       "dm-crypt kernel module loaded",
		Description: "Verify the dm_crypt kernel module is available.",
		Remediation: "modprobe dm_crypt and ensure it is loaded at boot.",
		Severity:    modules.SeverityMedium,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.1.20"}},
	}
}
