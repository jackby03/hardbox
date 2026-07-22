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
package boot

import "github.com/hardbox-io/hardbox/internal/modules"

func checkBOOT001() modules.Check {
	return modules.Check{
		ID:          "boot-001",
		Title:       "GRUB2 password is set",
		Description: "Verify GRUB2 bootloader is protected with a password.",
		Remediation: "Run grub2-setpassword or manually set superusers and password_pbkdf2 in /etc/grub.d/40_custom.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.4.1"}, {Framework: "NIST", Control: "AC-3"}, {Framework: "STIG", Control: "V-238200"}},
	}
}

func checkBOOT002() modules.Check {
	return modules.Check{
		ID:          "boot-002",
		Title:       "Secure Boot is enabled",
		Description: "Verify UEFI Secure Boot is active.",
		Remediation: "Enable Secure Boot in UEFI firmware settings.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.4.2"}, {Framework: "NIST", Control: "SI-7"}},
	}
}

func checkBOOT003() modules.Check {
	return modules.Check{
		ID:          "boot-003",
		Title:       "/boot permissions are restricted",
		Description: "Check /boot directory and files have correct ownership and permissions.",
		Remediation: "chown root:root /boot; chmod 0755 /boot; chmod 0600 /boot/grub/grub.cfg.",
		Severity:    modules.SeverityMedium,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.4.3"}, {Framework: "STIG", Control: "V-238204"}},
	}
}

func checkBOOT004() modules.Check {
	return modules.Check{
		ID:          "boot-004",
		Title:       "Bootloader configuration is not world-readable",
		Description: "Verify /boot/grub/grub.cfg is not readable by unauthorized users.",
		Remediation: "chmod 0600 /boot/grub/grub.cfg.",
		Severity:    modules.SeverityHigh,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.4.3"}, {Framework: "STIG", Control: "V-238203"}},
	}
}

func checkBOOT005() modules.Check {
	return modules.Check{
		ID:          "boot-005",
		Title:       "Kernel cmdline has security parameters",
		Description: "Check /proc/cmdline for audit=1 and other hardening parameters.",
		Remediation: "Add audit=1, module.sig_enforce=1 to GRUB_CMDLINE_LINUX in /etc/default/grub and run update-grub.",
		Severity:    modules.SeverityMedium,
		Compliance:  []modules.ComplianceRef{{Framework: "CIS", Control: "1.4.4"}, {Framework: "NIST", Control: "AU-12"}},
	}
}
