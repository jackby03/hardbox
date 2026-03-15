package containers

import "github.com/hardbox-io/hardbox/internal/modules"

func checkCNT001() modules.Check {
	return modules.Check{
		ID:          "cnt-001",
		Title:       "Docker daemon runs in rootless mode",
		Description: "Running Docker in rootless mode limits container breakout impact.",
		Remediation: "Set up rootless Docker using 'dockerd-rootless-setuptool.sh install'.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "2.1"},
			{Framework: "NIST", Control: "CM-6"},
		},
	}
}

func checkCNT002() modules.Check {
	return modules.Check{
		ID:          "cnt-002",
		Title:       "Inter-container communication disabled (icc=false)",
		Description: "Disabling ICC prevents containers from communicating directly over the bridge network.",
		Remediation: "Set '\"icc\": false' in /etc/docker/daemon.json and restart Docker.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "2.1"},
			{Framework: "NIST", Control: "SC-7"},
			{Framework: "PCI", Control: "1.3.2"},
		},
	}
}

func checkCNT003() modules.Check {
	return modules.Check{
		ID:          "cnt-003",
		Title:       "User namespace remapping enabled",
		Description: "User namespace remapping isolates container UIDs from host UIDs.",
		Remediation: "Set '\"userns-remap\": \"default\"' in /etc/docker/daemon.json and restart Docker.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "2.8"},
			{Framework: "NIST", Control: "AC-6"},
		},
	}
}

func checkCNT004() modules.Check {
	return modules.Check{
		ID:          "cnt-004",
		Title:       "Docker remote API protected by TLS",
		Description: "If Docker daemon exposes a TCP endpoint, TLS must be enforced.",
		Remediation: "Set 'tls', 'tlsverify', 'tlscert', and 'tlskey' in /etc/docker/daemon.json.",
		Severity:    modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "2.6"},
			{Framework: "NIST", Control: "SC-8"},
			{Framework: "PCI", Control: "4.2.1"},
		},
	}
}

func checkCNT005() modules.Check {
	return modules.Check{
		ID:          "cnt-005",
		Title:       "Default seccomp profile applied to containers",
		Description: "The default seccomp profile limits risky syscalls inside containers.",
		Remediation: "Ensure the Docker daemon has not disabled seccomp via --security-opt seccomp=unconfined.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.21"},
			{Framework: "NIST", Control: "SI-3"},
		},
	}
}

func checkCNT006() modules.Check {
	return modules.Check{
		ID:          "cnt-006",
		Title:       "AppArmor or SELinux profile active for containers",
		Description: "MAC profiles provide mandatory access controls for container processes.",
		Remediation: "Enable AppArmor (Debian/Ubuntu) or SELinux (RHEL/CentOS) on the host.",
		Severity:    modules.SeverityHigh,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.25"},
			{Framework: "NIST", Control: "AC-3"},
			{Framework: "STIG", Control: "V-235805"},
		},
	}
}

func checkCNT007() modules.Check {
	return modules.Check{
		ID:          "cnt-007",
		Title:       "No running containers with --privileged flag",
		Description: "Privileged containers have full host capabilities and break containment.",
		Remediation: "Remove the --privileged flag from all container definitions.",
		Severity:    modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.4"},
			{Framework: "NIST", Control: "AC-6"},
			{Framework: "PCI", Control: "2.2.1"},
		},
	}
}

func checkCNT008() modules.Check {
	return modules.Check{
		ID:          "cnt-008",
		Title:       "Docker socket not mounted inside containers",
		Description: "Mounting /var/run/docker.sock grants root-equivalent control over the host.",
		Remediation: "Remove the Docker socket bind-mount from container configurations.",
		Severity:    modules.SeverityCritical,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.31"},
			{Framework: "NIST", Control: "AC-3"},
		},
	}
}

func checkCNT009() modules.Check {
	return modules.Check{
		ID:          "cnt-009",
		Title:       "Container images scanned for vulnerabilities",
		Description: "Regularly scan container images for known CVEs before deployment.",
		Remediation: "Integrate image scanning (e.g., Trivy, Grype) into your CI/CD pipeline.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "5.1"},
			{Framework: "NIST", Control: "RA-5"},
			{Framework: "PCI", Control: "6.3.3"},
		},
	}
}

func checkCNT010() modules.Check {
	return modules.Check{
		ID:          "cnt-010",
		Title:       "Audit rules configured for Docker daemon socket",
		Description: "Audit logging on /var/run/docker.sock tracks container daemon access.",
		Remediation: "Add '-w /var/run/docker.sock -p rwxa -k docker' to /etc/audit/rules.d/docker.rules.",
		Severity:    modules.SeverityMedium,
		Compliance: []modules.ComplianceRef{
			{Framework: "CIS", Control: "1.1.18"},
			{Framework: "NIST", Control: "AU-12"},
			{Framework: "PCI", Control: "10.2.5"},
		},
	}
}
