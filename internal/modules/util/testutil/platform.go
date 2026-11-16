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

package testutil

import (
	"os"
	"runtime"
	"testing"
)

// UnixPermsSupported reports whether the host enforces POSIX permission bits.
//
// It is false on Windows, where chmod only toggles the read-only flag, so a
// file created with mode 0000 is still readable. Assertions about mode bits or
// about access being denied by permissions are meaningless there.
func UnixPermsSupported() bool {
	return runtime.GOOS != "windows"
}

// Unprivileged reports whether the test runs without superuser privileges.
//
// On Windows os.Geteuid returns -1, so callers must check UnixPermsSupported
// first; this helper treats Windows as unprivileged to stay composable.
func Unprivileged() bool {
	if !UnixPermsSupported() {
		return true
	}
	return os.Geteuid() != 0
}

// RequireUnixPerms skips the test on hosts without POSIX permission semantics.
//
// Use it for tests that assert mode bits or that access is denied because of
// file permissions. Do not use it for tests that merely run on Linux: use
// RequireLinux for those.
func RequireUnixPerms(t *testing.T) {
	t.Helper()
	if !UnixPermsSupported() {
		t.Skipf("Unix permission semantics unavailable on %s", runtime.GOOS)
	}
}

// RequireLinux skips the test unless the host is Linux.
//
// Use it for tests that depend on Linux-only paths or behaviour (/proc, sysctl,
// systemd units) rather than on Unix permissions.
func RequireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("Linux-only test (host is %s)", runtime.GOOS)
	}
}

// RequireRoot skips the test unless the process runs as root.
//
// Use it for behaviour that can only be exercised with CAP_CHOWN or CAP_DAC_OVERRIDE,
// such as asserting that a remediation actually reapplies ownership.
func RequireRoot(t *testing.T) {
	t.Helper()
	if !UnixPermsSupported() {
		t.Skipf("Unix privilege model unavailable on %s", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root: chown and similar operations need CAP_CHOWN")
	}
}

// RequireUnprivileged skips the test when running as root, or on hosts without
// POSIX permission semantics.
//
// Root bypasses permission checks, so a file with mode 0000 is still readable
// and any assertion that access is denied would fail. Pair it with
// RequireUnixPerms when both conditions matter.
func RequireUnprivileged(t *testing.T) {
	t.Helper()
	if !UnixPermsSupported() {
		t.Skipf("Unix permission semantics unavailable on %s", runtime.GOOS)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission checks are bypassed")
	}
}
