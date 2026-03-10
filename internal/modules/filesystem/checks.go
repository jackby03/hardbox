package filesystem

import (
	"os"

	"github.com/hardbox-io/hardbox/internal/modules"
)

// mountCheckSpec describes required mount options for a filesystem mountpoint.
type mountCheckSpec struct {
	check      modules.Check
	mountPoint string
	required   []string // options that must all be present
}

// filePermSpec describes required permissions and ownership for a file.
type filePermSpec struct {
	check    modules.Check
	path     string      // absolute path on the target system
	mode     os.FileMode // required permission bits
	modeAlt  os.FileMode // alternative acceptable mode (0 = none)
	wantUID  uint32      // expected owner UID
	wantGID  uint32      // expected group GID
	skipGID  bool        // skip GID check (e.g. shadow group varies by distro)
	gidLabel string      // human-readable GID label for output
}

func mountChecks() []mountCheckSpec {
	return []mountCheckSpec{
		{
			mountPoint: "/tmp",
			required:   []string{"nodev", "nosuid", "noexec"},
			check: modules.Check{
				ID:          "fs-001",
				Title:       "Mount /tmp with nodev,nosuid,noexec",
				Description: "/tmp should be mounted with nodev, nosuid, and noexec to prevent execution of malicious files.",
				Remediation: "Add nodev,nosuid,noexec to the /tmp entry in /etc/fstab and run: mount -o remount /tmp",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.2"},
					{Framework: "NIST", Control: "CM-7"},
				},
			},
		},
		{
			mountPoint: "/dev/shm",
			required:   []string{"nodev", "nosuid", "noexec"},
			check: modules.Check{
				ID:          "fs-002",
				Title:       "Mount /dev/shm with nodev,nosuid,noexec",
				Description: "Shared memory should be mounted with nodev, nosuid, and noexec.",
				Remediation: "Add nodev,nosuid,noexec to the /dev/shm entry in /etc/fstab and remount.",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.7"},
					{Framework: "NIST", Control: "CM-7"},
				},
			},
		},
		{
			mountPoint: "/home",
			required:   []string{"nodev"},
			check: modules.Check{
				ID:          "fs-003",
				Title:       "Mount /home with nodev",
				Description: "Home directories should be mounted nodev to prevent device file creation.",
				Remediation: "Add nodev to the /home entry in /etc/fstab and remount.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.13"},
					{Framework: "NIST", Control: "CM-7"},
				},
			},
		},
		{
			mountPoint: "/var",
			required:   []string{"nodev", "nosuid"},
			check: modules.Check{
				ID:          "fs-004",
				Title:       "Mount /var with nodev,nosuid",
				Description: "/var should be mounted with nodev and nosuid to limit attack surface.",
				Remediation: "Add nodev,nosuid to the /var entry in /etc/fstab and remount.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.14"},
					{Framework: "NIST", Control: "CM-7"},
				},
			},
		},
		{
			mountPoint: "/var/log",
			required:   []string{"nodev", "nosuid", "noexec"},
			check: modules.Check{
				ID:          "fs-005",
				Title:       "Mount /var/log with nodev,nosuid,noexec",
				Description: "Log directory should not allow execution, device files, or setuid binaries.",
				Remediation: "Add nodev,nosuid,noexec to the /var/log entry in /etc/fstab and remount.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.15"},
					{Framework: "NIST", Control: "AU-9"},
				},
			},
		},
		{
			mountPoint: "/var/log/audit",
			required:   []string{"nodev", "nosuid", "noexec"},
			check: modules.Check{
				ID:          "fs-006",
				Title:       "Mount /var/log/audit with nodev,nosuid,noexec",
				Description: "Audit log directory should not allow execution or special files.",
				Remediation: "Add nodev,nosuid,noexec to the /var/log/audit entry in /etc/fstab and remount.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.16"},
					{Framework: "NIST", Control: "AU-9"},
				},
			},
		},
		{
			mountPoint: "/boot",
			required:   []string{"nodev", "nosuid"},
			check: modules.Check{
				ID:          "fs-007",
				Title:       "Mount /boot with nodev,nosuid",
				Description: "Boot partition should be mounted with restrictive options.",
				Remediation: "Add nodev,nosuid to the /boot entry in /etc/fstab and remount.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.17"},
					{Framework: "NIST", Control: "CM-7"},
				},
			},
		},
	}
}

func filePermChecks() []filePermSpec {
	return []filePermSpec{
		{
			path: "/etc/passwd", mode: 0o644,
			wantUID: 0, wantGID: 0, gidLabel: "root",
			check: modules.Check{
				ID:          "fs-010",
				Title:       "/etc/passwd permissions: 644 root:root",
				Severity:    modules.SeverityHigh,
				Remediation: "chmod 644 /etc/passwd && chown root:root /etc/passwd",
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "6.1.2"},
					{Framework: "NIST", Control: "AC-6"},
				},
			},
		},
		{
			path: "/etc/shadow", mode: 0o640, modeAlt: 0o000,
			wantUID: 0, skipGID: true, gidLabel: "shadow/root",
			check: modules.Check{
				ID:          "fs-011",
				Title:       "/etc/shadow permissions: 640 or 000 root:shadow",
				Severity:    modules.SeverityCritical,
				Remediation: "chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "6.1.3"},
					{Framework: "NIST", Control: "IA-5"},
				},
			},
		},
		{
			path: "/etc/group", mode: 0o644,
			wantUID: 0, wantGID: 0, gidLabel: "root",
			check: modules.Check{
				ID:          "fs-012",
				Title:       "/etc/group permissions: 644 root:root",
				Severity:    modules.SeverityMedium,
				Remediation: "chmod 644 /etc/group && chown root:root /etc/group",
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "6.1.4"},
					{Framework: "NIST", Control: "AC-6"},
				},
			},
		},
		{
			path: "/etc/gshadow", mode: 0o640, modeAlt: 0o000,
			wantUID: 0, skipGID: true, gidLabel: "shadow/root",
			check: modules.Check{
				ID:          "fs-013",
				Title:       "/etc/gshadow permissions: 640 or 000 root:shadow",
				Severity:    modules.SeverityCritical,
				Remediation: "chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow",
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "6.1.5"},
					{Framework: "NIST", Control: "IA-5"},
				},
			},
		},
		{
			path: "/etc/passwd-", mode: 0o644,
			wantUID: 0, wantGID: 0, gidLabel: "root",
			check: modules.Check{
				ID:          "fs-014a",
				Title:       "/etc/passwd- backup: 644 root:root",
				Severity:    modules.SeverityMedium,
				Remediation: "chmod 644 /etc/passwd- && chown root:root /etc/passwd-",
				Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "6.1.6"}},
			},
		},
		{
			path: "/etc/shadow-", mode: 0o640, modeAlt: 0o000,
			wantUID: 0, skipGID: true, gidLabel: "shadow/root",
			check: modules.Check{
				ID:          "fs-014b",
				Title:       "/etc/shadow- backup: 640 or 000",
				Severity:    modules.SeverityCritical,
				Remediation: "chmod 640 /etc/shadow- && chown root:shadow /etc/shadow-",
				Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "6.1.7"}},
			},
		},
		{
			path: "/etc/group-", mode: 0o644,
			wantUID: 0, wantGID: 0, gidLabel: "root",
			check: modules.Check{
				ID:          "fs-014c",
				Title:       "/etc/group- backup: 644 root:root",
				Severity:    modules.SeverityMedium,
				Remediation: "chmod 644 /etc/group- && chown root:root /etc/group-",
				Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "6.1.8"}},
			},
		},
		{
			path: "/etc/gshadow-", mode: 0o640, modeAlt: 0o000,
			wantUID: 0, skipGID: true, gidLabel: "shadow/root",
			check: modules.Check{
				ID:          "fs-014d",
				Title:       "/etc/gshadow- backup: 640 or 000",
				Severity:    modules.SeverityCritical,
				Remediation: "chmod 640 /etc/gshadow- && chown root:shadow /etc/gshadow-",
				Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "6.1.9"}},
			},
		},
	}
}
