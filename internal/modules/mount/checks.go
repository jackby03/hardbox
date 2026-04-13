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
package mount

import "github.com/hardbox-io/hardbox/internal/modules"

// partitionCheckSpec describes a mountpoint that should be on its own partition.
type partitionCheckSpec struct {
	check      modules.Check
	mountPoint string
}

// kernelModuleCheckSpec describes a kernel module that must be disabled.
type kernelModuleCheckSpec struct {
	check      modules.Check
	moduleName string
}

func partitionChecks() []partitionCheckSpec {
	return []partitionCheckSpec{
		{
			mountPoint: "/tmp",
			check: modules.Check{
				ID:          "mnt-001",
				Title:       "/tmp is on a dedicated partition",
				Description: "Having /tmp on a dedicated partition prevents runaway processes from filling the root filesystem and limits attack surface.",
				Remediation: "Mount /tmp on a dedicated partition or use 'systemd-mount --type=tmpfs tmpfs /tmp' and add the entry to /etc/fstab.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.2"},
					{Framework: "NIST", Control: "CM-7"},
					{Framework: "STIG", Control: "V-238149"},
				},
			},
		},
		{
			mountPoint: "/var",
			check: modules.Check{
				ID:          "mnt-003",
				Title:       "/var is on a dedicated partition",
				Description: "A dedicated /var partition prevents log growth or package operations from exhausting the root filesystem.",
				Remediation: "Mount /var on a dedicated partition and add the entry to /etc/fstab.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.6"},
					{Framework: "NIST", Control: "CM-6"},
					{Framework: "STIG", Control: "V-238151"},
				},
			},
		},
		{
			mountPoint: "/var/tmp",
			check: modules.Check{
				ID:          "mnt-004",
				Title:       "/var/tmp is on a dedicated partition",
				Description: "/var/tmp persists across reboots and is world-writable; a dedicated partition limits spillover risk.",
				Remediation: "Mount /var/tmp on a dedicated partition and add the entry to /etc/fstab.",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.8"},
					{Framework: "NIST", Control: "CM-7"},
				},
			},
		},
		{
			mountPoint: "/var/log",
			check: modules.Check{
				ID:          "mnt-005",
				Title:       "/var/log is on a dedicated partition",
				Description: "Logs on a dedicated partition prevent a log flood from exhausting the root filesystem.",
				Remediation: "Mount /var/log on a dedicated partition and add the entry to /etc/fstab.",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.11"},
					{Framework: "NIST", Control: "AU-9"},
					{Framework: "STIG", Control: "V-238152"},
				},
			},
		},
		{
			mountPoint: "/var/log/audit",
			check: modules.Check{
				ID:          "mnt-006",
				Title:       "/var/log/audit is on a dedicated partition",
				Description: "Audit logs on a dedicated partition prevent denial-of-service via log flooding and protect audit integrity.",
				Remediation: "Mount /var/log/audit on a dedicated partition and add the entry to /etc/fstab.",
				Severity:    modules.SeverityHigh,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.12"},
					{Framework: "NIST", Control: "AU-9"},
					{Framework: "STIG", Control: "V-238153"},
				},
			},
		},
		{
			mountPoint: "/home",
			check: modules.Check{
				ID:          "mnt-007",
				Title:       "/home is on a dedicated partition",
				Description: "A dedicated /home partition limits user data from affecting system stability.",
				Remediation: "Mount /home on a dedicated partition and add the entry to /etc/fstab.",
				Severity:    modules.SeverityLow,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.13"},
					{Framework: "NIST", Control: "CM-6"},
				},
			},
		},
	}
}

func kernelModuleChecks() []kernelModuleCheckSpec {
	return []kernelModuleCheckSpec{
		{
			moduleName: "cramfs",
			check: modules.Check{
				ID:          "mnt-011",
				Title:       "cramfs kernel module disabled",
				Description: "cramfs is a legacy compressed read-only filesystem rarely used in production. Disabling it reduces kernel attack surface.",
				Remediation: "Add 'install cramfs /bin/false' and 'blacklist cramfs' to /etc/modprobe.d/hardbox.conf",
				Severity:    modules.SeverityLow,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.1.1"},
					{Framework: "NIST", Control: "CM-7"},
				},
			},
		},
		{
			moduleName: "squashfs",
			check: modules.Check{
				ID:          "mnt-012",
				Title:       "squashfs kernel module disabled",
				Description: "squashfs is used by snap packages; if snap is not in use, disabling it reduces attack surface.",
				Remediation: "Add 'install squashfs /bin/false' and 'blacklist squashfs' to /etc/modprobe.d/hardbox.conf",
				Severity:    modules.SeverityLow,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.1.2"},
					{Framework: "NIST", Control: "CM-7"},
				},
			},
		},
		{
			moduleName: "udf",
			check: modules.Check{
				ID:          "mnt-013",
				Title:       "udf kernel module disabled",
				Description: "UDF (Universal Disk Format) is used for optical media. Disabling it on servers without optical drives reduces attack surface.",
				Remediation: "Add 'install udf /bin/false' and 'blacklist udf' to /etc/modprobe.d/hardbox.conf",
				Severity:    modules.SeverityLow,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.1.3"},
					{Framework: "NIST", Control: "CM-7"},
				},
			},
		},
		{
			moduleName: "usb-storage",
			check: modules.Check{
				ID:          "mnt-015",
				Title:       "usb-storage kernel module disabled",
				Description: "USB storage devices can be used for data exfiltration or malware introduction. Disable on servers where removable storage is not required.",
				Remediation: "Add 'install usb-storage /bin/false' and 'blacklist usb-storage' to /etc/modprobe.d/hardbox.conf",
				Severity:    modules.SeverityMedium,
				Compliance: []modules.ComplianceRef{
					{Framework: "CIS", Control: "1.1.24"},
					{Framework: "NIST", Control: "CM-7"},
					{Framework: "STIG", Control: "V-238322"},
				},
			},
		},
	}
}

