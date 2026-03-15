package users

import "github.com/hardbox-io/hardbox/internal/modules"

func checkUSR001() modules.Check {
	return modules.Check{
		ID:          "usr-001",
		Title:       "Password maximum age ≤ 90 days",
		Description: "PASS_MAX_DAYS in /etc/login.defs must be set to 90 or fewer.",
		Remediation: "Set PASS_MAX_DAYS 90 in /etc/login.defs",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.1.1"},
			{Framework: "NIST", Control: "IA-5"},
			{Framework: "STIG", Control: "V-238218"},
			{Framework: "PCI", Control: "8.3.9"},
			{Framework: "HIPAA", Control: "164.312(d)"},
			{Framework: "ISO", Control: "A.9.4.3"},
		},
	}
}

func checkUSR002() modules.Check {
	return modules.Check{
		ID:          "usr-002",
		Title:       "Password minimum age ≥ 1 day",
		Description: "PASS_MIN_DAYS in /etc/login.defs must be at least 1 to prevent rapid password cycling.",
		Remediation: "Set PASS_MIN_DAYS 1 in /etc/login.defs",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.1.2"},
			{Framework: "NIST", Control: "IA-5"},
			{Framework: "PCI", Control: "8.3.6"},
		},
	}
}

func checkUSR003() modules.Check {
	return modules.Check{
		ID:          "usr-003",
		Title:       "Password expiry warning ≥ 7 days",
		Description: "PASS_WARN_AGE in /etc/login.defs must give at least 7 days notice before expiry.",
		Remediation: "Set PASS_WARN_AGE 14 in /etc/login.defs",
		Severity:    modules.SeverityLow,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.1.3"},
			{Framework: "NIST", Control: "IA-5"},
		},
	}
}

func checkUSR004() modules.Check {
	return modules.Check{
		ID:          "usr-004",
		Title:       "Password minimum length ≥ 14",
		Description: "PASS_MIN_LEN in /etc/login.defs or minlen in pam_pwquality must be at least 14.",
		Remediation: "Set PASS_MIN_LEN 14 in /etc/login.defs",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.1.4"},
			{Framework: "NIST", Control: "IA-5"},
			{Framework: "STIG", Control: "V-238349"},
			{Framework: "PCI", Control: "8.3.6"},
			{Framework: "HIPAA", Control: "164.312(d)"},
		},
	}
}

func checkUSR005() modules.Check {
	return modules.Check{
		ID:          "usr-005",
		Title:       "PAM complexity module configured",
		Description: "pam_pwquality.so or pam_cracklib.so must be present in the PAM password stack.",
		Remediation: "Install and configure libpam-pwquality; add it to /etc/pam.d/common-password",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.1"},
			{Framework: "NIST", Control: "IA-5"},
			{Framework: "STIG", Control: "V-238349"},
			{Framework: "PCI", Control: "8.3.6"},
			{Framework: "HIPAA", Control: "164.312(d)"},
		},
	}
}

func checkUSR006() modules.Check {
	return modules.Check{
		ID:          "usr-006",
		Title:       "PAM password history ≥ 5 remembered",
		Description: "pam_pwhistory.so (or pam_unix remember=) must prevent reuse of at least the last 5 passwords.",
		Remediation: "Add 'password required pam_pwhistory.so remember=24 use_authtok' to /etc/pam.d/common-password",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.3"},
			{Framework: "NIST", Control: "IA-5"},
			{Framework: "STIG", Control: "V-238348"},
			{Framework: "PCI", Control: "8.3.7"},
		},
	}
}

func checkUSR007() modules.Check {
	return modules.Check{
		ID:          "usr-007",
		Title:       "PAM lockout threshold ≤ 5 attempts",
		Description: "pam_faillock.so (or pam_tally2.so) must lock accounts after at most 5 failed attempts.",
		Remediation: "Configure 'deny=5' in pam_faillock.so in /etc/pam.d/common-auth",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.3.2"},
			{Framework: "NIST", Control: "AC-7"},
			{Framework: "STIG", Control: "V-238351"},
			{Framework: "PCI", Control: "8.3.4"},
			{Framework: "HIPAA", Control: "164.312(a)(2)(iii)"},
		},
	}
}

func checkUSR008() modules.Check {
	return modules.Check{
		ID:          "usr-008",
		Title:       "PAM lockout unlock time ≥ 900 seconds",
		Description: "pam_faillock.so unlock_time must be set to at least 900 seconds (15 minutes).",
		Remediation: "Set 'unlock_time=900' in the pam_faillock.so line in /etc/pam.d/common-auth",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.3.3"},
			{Framework: "NIST", Control: "AC-7"},
			{Framework: "PCI", Control: "8.3.4"},
		},
	}
}

func checkUSR009() modules.Check {
	return modules.Check{
		ID:          "usr-009",
		Title:       "PAM root account lockout enabled",
		Description: "pam_faillock.so must include 'even_deny_root' to lock the root account on repeated failures.",
		Remediation: "Add 'even_deny_root' to the pam_faillock.so line in /etc/pam.d/common-auth",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.6.6"},
			{Framework: "NIST", Control: "AC-7"},
		},
	}
}

func checkUSR010() modules.Check {
	return modules.Check{
		ID:          "usr-010",
		Title:       "Only root has UID 0",
		Description: "No account other than root should have UID 0.",
		Remediation: "Remove or reassign UIDs for any non-root accounts with UID 0",
		Severity:    modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.2.1"},
			{Framework: "NIST", Control: "AC-6"},
			{Framework: "STIG", Control: "V-238218"},
			{Framework: "PCI", Control: "7.2.1"},
			{Framework: "HIPAA", Control: "164.312(a)(1)"},
		},
	}
}

func checkUSR011() modules.Check {
	return modules.Check{
		ID:          "usr-011",
		Title:       "No system accounts with interactive login shells",
		Description: "System accounts (UID 1–999) must use /usr/sbin/nologin or /bin/false as their shell.",
		Remediation: "Run: usermod -s /usr/sbin/nologin <account> for each offending system account",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.2.2"},
			{Framework: "NIST", Control: "AC-6"},
			{Framework: "STIG", Control: "V-238220"},
		},
	}
}

func checkUSR012() modules.Check {
	return modules.Check{
		ID:          "usr-012",
		Title:       "Sudoers includes /etc/sudoers.d/",
		Description: "/etc/sudoers must include '#includedir /etc/sudoers.d' for modular sudo rules.",
		Remediation: "Add '#includedir /etc/sudoers.d' at the end of /etc/sudoers",
		Severity:    modules.SeverityLow,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.3.1"},
			{Framework: "NIST", Control: "AC-6"},
		},
	}
}

func checkUSR013() modules.Check {
	return modules.Check{
		ID:          "usr-013",
		Title:       "No NOPASSWD in sudoers",
		Description: "No sudo rule should grant password-free privilege escalation.",
		Remediation: "Remove NOPASSWD from all rules in /etc/sudoers and /etc/sudoers.d/",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.3.5"},
			{Framework: "NIST", Control: "AC-6"},
			{Framework: "STIG", Control: "V-238352"},
			{Framework: "PCI", Control: "7.2.1"},
			{Framework: "HIPAA", Control: "164.312(a)(1)"},
		},
	}
}

func checkUSR014() modules.Check {
	return modules.Check{
		ID:          "usr-014",
		Title:       "No sudo authenticate bypass",
		Description: "No sudo rule should use '!authenticate' to bypass password prompts.",
		Remediation: "Remove '!authenticate' from all rules in /etc/sudoers and /etc/sudoers.d/",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.3.6"},
			{Framework: "NIST", Control: "AC-6"},
		},
	}
}

func checkUSR015() modules.Check {
	return modules.Check{
		ID:          "usr-015",
		Title:       "Default umask ≤ 027",
		Description: "UMASK in /etc/login.defs must be 027 or more restrictive.",
		Remediation: "Set UMASK 027 in /etc/login.defs",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.4"},
			{Framework: "NIST", Control: "AC-6"},
			{Framework: "STIG", Control: "V-238327"},
		},
	}
}

func checkUSR016() modules.Check {
	return modules.Check{
		ID:          "usr-016",
		Title:       "Root PATH does not include '.'",
		Description: "ENV_PATH / ENV_SUPATH in /etc/login.defs must not contain '.' or empty components.",
		Remediation: "Remove '.' from ENV_PATH and ENV_SUPATH in /etc/login.defs",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.5"},
			{Framework: "NIST", Control: "CM-6"},
		},
	}
}

func checkUSR017() modules.Check {
	return modules.Check{
		ID:          "usr-017",
		Title:       "Inactive account lock ≤ 30 days",
		Description: "INACTIVE in /etc/default/useradd must be set to 30 or fewer days.",
		Remediation: "Set INACTIVE=30 in /etc/default/useradd and run: useradd -D -f 30",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4.1.5"},
			{Framework: "NIST", Control: "AC-2"},
			{Framework: "STIG", Control: "V-238229"},
			{Framework: "PCI", Control: "8.1.4"},
		},
	}
}
