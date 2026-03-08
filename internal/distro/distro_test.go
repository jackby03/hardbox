package distro_test

import (
	"testing"

	"github.com/hardbox-io/hardbox/internal/distro"
)

// helper wraps detectFromPaths which is exported via the internal test hook below.
// We use the package-level testDetect function to avoid exposing detectFromPaths
// in the public API.

func TestDetect_Ubuntu_OsRelease(t *testing.T) {
	info := mustDetect(t,
		"testdata/ubuntu_os_release",
		"testdata/nonexistent",
		"testdata/nonexistent",
	)

	assertEqual(t, "id", "ubuntu", info.ID)
	assertEqual(t, "version_id", "22.04", info.VersionID)
	assertEqual(t, "family", string(distro.FamilyDebian), string(info.Family))
	if info.PrettyName == "" {
		t.Error("PrettyName should not be empty")
	}
}

func TestDetect_Debian_OsRelease(t *testing.T) {
	info := mustDetect(t,
		"testdata/debian_os_release",
		"testdata/nonexistent",
		"testdata/nonexistent",
	)

	assertEqual(t, "id", "debian", info.ID)
	assertEqual(t, "version_id", "12", info.VersionID)
	assertEqual(t, "family", string(distro.FamilyDebian), string(info.Family))
}

func TestDetect_Rocky_OsRelease(t *testing.T) {
	info := mustDetect(t,
		"testdata/rocky_os_release",
		"testdata/nonexistent",
		"testdata/nonexistent",
	)

	assertEqual(t, "id", "rocky", info.ID)
	assertEqual(t, "version_id", "9.3", info.VersionID)
	assertEqual(t, "family", string(distro.FamilyRHEL), string(info.Family))
}

func TestDetect_AmazonLinux_OsRelease(t *testing.T) {
	info := mustDetect(t,
		"testdata/amzn_os_release",
		"testdata/nonexistent",
		"testdata/nonexistent",
	)

	assertEqual(t, "id", "amzn", info.ID)
	assertEqual(t, "version_id", "2023", info.VersionID)
	assertEqual(t, "family", string(distro.FamilyRHEL), string(info.Family))
}

func TestDetect_Ubuntu_LsbRelease_Fallback(t *testing.T) {
	info := mustDetect(t,
		"testdata/nonexistent",
		"testdata/ubuntu_lsb_release",
		"testdata/nonexistent",
	)

	assertEqual(t, "id", "ubuntu", info.ID)
	assertEqual(t, "version_id", "20.04", info.VersionID)
	assertEqual(t, "family", string(distro.FamilyDebian), string(info.Family))
}

func TestDetect_RHEL6_RedhatRelease_Fallback(t *testing.T) {
	info := mustDetect(t,
		"testdata/nonexistent",
		"testdata/nonexistent",
		"testdata/rhel6_redhat_release",
	)

	assertEqual(t, "id", "rhel", info.ID)
	assertEqual(t, "version_id", "6.10", info.VersionID)
	assertEqual(t, "family", string(distro.FamilyRHEL), string(info.Family))
}

func TestDetect_NoFiles_ReturnsError(t *testing.T) {
	_, err := distro.TestDetectFromPaths(
		"testdata/nonexistent",
		"testdata/nonexistent",
		"testdata/nonexistent",
	)
	if err == nil {
		t.Fatal("expected error when no release files exist, got nil")
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func mustDetect(t *testing.T, osRelease, lsbRelease, redhatRelease string) *distro.Info {
	t.Helper()
	info, err := distro.TestDetectFromPaths(osRelease, lsbRelease, redhatRelease)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return info
}

func assertEqual(t *testing.T, field, want, got string) {
	t.Helper()
	if want != got {
		t.Errorf("%s: want %q, got %q", field, want, got)
	}
}
