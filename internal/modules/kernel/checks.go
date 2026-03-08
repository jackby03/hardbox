package kernel

import "github.com/hardbox-io/hardbox/internal/modules"

// sysctlCheck pairs a modules.Check with its sysctl parameter path and
// the expected value + validator function.
type sysctlCheck struct {
	check    modules.Check
	param    string // dot-notation sysctl key, e.g. "net.ipv4.ip_forward"
	expected string
	validate func(current string) bool
}

// eq returns a validator that passes when current equals expected (trimmed).
func eq(expected string) func(string) bool {
	return func(current string) bool {
		return current == expected
	}
}

// allChecks returns the complete ordered list of kernel hardening checks.
// Network checks (kn-*) come first, then memory/process checks (km-*).
func allChecks() []sysctlCheck {
	return []sysctlCheck{
		// ── Network hardening (kn-001 … kn-011) ──────────────────────────────
		{
			param: "net.ipv4.ip_forward", expected: "0",
			validate: eq("0"),
			check: modules.Check{
				ID: "kn-001", Title: "Disable IPv4 forwarding",
				Description: "Prevents the host from acting as a router.",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.1.1"},
					{Framework: "NIST", Control: "SC-5"},
				},
			},
		},
		{
			param: "net.ipv4.conf.all.send_redirects", expected: "0",
			validate: eq("0"),
			check: modules.Check{
				ID: "kn-002", Title: "Disable sending ICMP redirects",
				Description: "Stops the host from sending ICMP redirect messages.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.1.2"},
					{Framework: "NIST", Control: "SC-5"},
				},
			},
		},
		{
			param: "net.ipv4.conf.all.accept_source_route", expected: "0",
			validate: eq("0"),
			check: modules.Check{
				ID: "kn-003", Title: "Disable source-routed packets",
				Description: "Rejects packets with the source route IP option set.",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.2.1"},
					{Framework: "NIST", Control: "SC-5"},
				},
			},
		},
		{
			param: "net.ipv4.conf.all.accept_redirects", expected: "0",
			validate: eq("0"),
			check: modules.Check{
				ID: "kn-004", Title: "Disable ICMP redirect acceptance",
				Description: "Prevents routing table modification via ICMP redirects.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.2.2"},
					{Framework: "NIST", Control: "SC-5"},
				},
			},
		},
		{
			param: "net.ipv4.conf.all.secure_redirects", expected: "0",
			validate: eq("0"),
			check: modules.Check{
				ID: "kn-005", Title: "Disable secure ICMP redirect acceptance",
				Description: "Rejects ICMP redirects even from gateway-listed hosts.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.2.3"},
				},
			},
		},
		{
			param: "net.ipv4.conf.all.log_martians", expected: "1",
			validate: eq("1"),
			check: modules.Check{
				ID: "kn-006", Title: "Log martian packets",
				Description: "Logs packets with impossible source addresses for anomaly detection.",
				Severity:    modules.SeverityLow,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.2.4"},
					{Framework: "NIST", Control: "AU-12"},
				},
			},
		},
		{
			param: "net.ipv4.icmp_echo_ignore_broadcasts", expected: "1",
			validate: eq("1"),
			check: modules.Check{
				ID: "kn-007", Title: "Ignore broadcast ICMP echo requests",
				Description: "Mitigates Smurf amplification attacks.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.2.5"},
					{Framework: "NIST", Control: "SC-5"},
				},
			},
		},
		{
			param: "net.ipv4.icmp_ignore_bogus_error_responses", expected: "1",
			validate: eq("1"),
			check: modules.Check{
				ID: "kn-008", Title: "Ignore bogus ICMP error responses",
				Description: "Suppresses kernel log spam from RFC-violating routers.",
				Severity:    modules.SeverityLow,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.2.6"},
				},
			},
		},
		{
			param: "net.ipv4.conf.all.rp_filter", expected: "1",
			validate: eq("1"),
			check: modules.Check{
				ID: "kn-009", Title: "Enable reverse path filtering",
				Description: "Validates that reply packets egress the same interface as ingress.",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.2.7"},
					{Framework: "NIST", Control: "SC-5"},
				},
			},
		},
		{
			param: "net.ipv4.tcp_syncookies", expected: "1",
			validate: eq("1"),
			check: modules.Check{
				ID: "kn-010", Title: "Enable TCP SYN cookies",
				Description: "Protects against SYN flood DoS attacks.",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.2.8"},
					{Framework: "NIST", Control: "SC-5"},
				},
			},
		},
		{
			param: "net.ipv6.conf.all.accept_ra", expected: "0",
			validate: eq("0"),
			check: modules.Check{
				ID: "kn-011", Title: "Disable IPv6 router advertisement acceptance",
				Description: "Prevents rogue router advertisement attacks.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "3.2.9"},
					{Framework: "NIST", Control: "SC-5"},
				},
			},
		},

		// ── Memory / process hardening (km-001 … km-008) ─────────────────────
		{
			param: "kernel.randomize_va_space", expected: "2",
			validate: eq("2"),
			check: modules.Check{
				ID: "km-001", Title: "Enable full ASLR",
				Description: "Randomises virtual address space to mitigate memory-corruption exploits.",
				Severity:    modules.SeverityCritical,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.5.2"},
					{Framework: "NIST", Control: "SI-16"},
					{Framework: "STIG", Control: "V-238221"},
				},
			},
		},
		{
			param: "kernel.dmesg_restrict", expected: "1",
			validate: eq("1"),
			check: modules.Check{
				ID: "km-002", Title: "Restrict dmesg to privileged users",
				Description: "Hides kernel ring buffer from unprivileged users.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.5.3"},
					{Framework: "NIST", Control: "AC-6"},
				},
			},
		},
		{
			param: "kernel.kptr_restrict", expected: "2",
			validate: eq("2"),
			check: modules.Check{
				ID: "km-003", Title: "Hide kernel symbol addresses",
				Description: "Prevents /proc/kallsyms from exposing kernel pointer values.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.5.4"},
					{Framework: "NIST", Control: "AC-6"},
				},
			},
		},
		{
			param: "kernel.yama.ptrace_scope", expected: "1",
			validate: eq("1"),
			check: modules.Check{
				ID: "km-004", Title: "Restrict ptrace to child processes",
				Description: "Limits ptrace to parent-child relationships, blocking cross-process debugging.",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.5.5"},
					{Framework: "NIST", Control: "AC-6"},
				},
			},
		},
		{
			param: "fs.protected_hardlinks", expected: "1",
			validate: eq("1"),
			check: modules.Check{
				ID: "km-005", Title: "Enable hardlink protection",
				Description: "Prevents unprivileged users from creating hard links to files they don't own.",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.5.6"},
					{Framework: "NIST", Control: "AC-6"},
				},
			},
		},
		{
			param: "fs.protected_symlinks", expected: "1",
			validate: eq("1"),
			check: modules.Check{
				ID: "km-006", Title: "Enable symlink protection",
				Description: "Blocks following symlinks in sticky world-writable directories.",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.5.7"},
					{Framework: "NIST", Control: "AC-6"},
				},
			},
		},
		{
			param: "fs.suid_dumpable", expected: "0",
			validate: eq("0"),
			check: modules.Check{
				ID: "km-007", Title: "Disable core dumps for setuid programs",
				Description: "Prevents core dumps from privileged processes leaking sensitive data.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.5.1"},
					{Framework: "NIST", Control: "SI-12"},
				},
			},
		},
		{
			param: "kernel.core_uses_pid", expected: "1",
			validate: eq("1"),
			check: modules.Check{
				ID: "km-008", Title: "Append PID to core dump filenames",
				Description: "Ensures core files from concurrent crashes do not overwrite each other.",
				Severity:    modules.SeverityInfo,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.5.1"},
				},
			},
		},
	}
}
