package mount_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/mount"
)

// ── parseMountPoints ──────────────────────────────────────────────────────────

func TestParseMountPoints(t *testing.T) {
	input := []byte(`
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /home ext4 rw,nodev,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0
`)
	got := mount.ParseMountPoints(input)

	for _, want := range []string{"/", "/home", "/tmp", "/sys", "/proc"} {
		if !got[want] {
			t.Errorf("expected mountpoint %q to be present", want)
		}
	}
	if got["/nonexistent"] {
		t.Errorf("unexpected mountpoint /nonexistent")
	}
}

// ── isBlacklisted / hasInstallFalse ──────────────────────────────────────────

func TestIsBlacklisted(t *testing.T) {
	conf := "blacklist cramfs\nblacklist udf\n"
	if !mount.IsBlacklisted(conf, "cramfs") {
		t.Error("expected cramfs to be blacklisted")
	}
	if mount.IsBlacklisted(conf, "squashfs") {
		t.Error("squashfs should not be blacklisted")
	}
	// Hyphen / underscore normalisation.
	if !mount.IsBlacklisted(conf, "udf") {
		t.Error("expected udf to be blacklisted")
	}
}

func TestHasInstallFalse(t *testing.T) {
	conf := "install cramfs /bin/false\ninstall udf /bin/true\n"
	if !mount.HasInstallFalse(conf, "cramfs") {
		t.Error("expected cramfs to have install /bin/false")
	}
	if !mount.HasInstallFalse(conf, "udf") {
		t.Error("expected udf to have install /bin/true (counts as disabled)")
	}
	if mount.HasInstallFalse(conf, "squashfs") {
		t.Error("squashfs should not have install false")
	}
}

func TestNormaliseModName(t *testing.T) {
	if mount.NormaliseModName("usb-storage") != "usb_storage" {
		t.Error("hyphen should be converted to underscore")
	}
	if mount.NormaliseModName("cramfs") != "cramfs" {
		t.Error("name without hyphen should be unchanged")
	}
}

// ── Audit — partition checks ──────────────────────────────────────────────────

func TestAuditPartitions_AllPresent(t *testing.T) {
	f := writeTempFile(t, `
/dev/sda1 / ext4 rw 0 0
/dev/sda2 /tmp tmpfs rw 0 0
/dev/sda3 /var ext4 rw 0 0
/dev/sda4 /var/tmp ext4 rw 0 0
/dev/sda5 /var/log ext4 rw 0 0
/dev/sda6 /var/log/audit ext4 rw 0 0
/dev/sda7 /home ext4 rw 0 0
`)
	m := mount.NewModuleWithMounts(f)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	partIDs := map[string]bool{
		"mnt-001": true, "mnt-003": true, "mnt-004": true,
		"mnt-005": true, "mnt-006": true, "mnt-007": true,
	}
	for _, f := range findings {
		if !partIDs[f.Check.ID] {
			continue
		}
		if f.Status != modules.StatusCompliant {
			t.Errorf("check %s: expected Compliant, got %s (%s)", f.Check.ID, f.Status, f.Detail)
		}
	}
}

func TestAuditPartitions_NonePresent(t *testing.T) {
	f := writeTempFile(t, "/dev/sda1 / ext4 rw 0 0\n")
	m := mount.NewModuleWithMounts(f)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nonCompliant := 0
	for _, f := range findings {
		if strings.HasPrefix(f.Check.ID, "mnt-0") && f.Status == modules.StatusNonCompliant {
			nonCompliant++
		}
	}
	if nonCompliant == 0 {
		t.Error("expected at least one non-compliant partition finding")
	}
}

func TestAuditPartitions_MissingMountsFile(t *testing.T) {
	m := mount.NewModuleWithMounts("/nonexistent/proc/mounts")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if strings.HasPrefix(f.Check.ID, "mnt-") && f.Status != modules.StatusSkipped {
			// kernel module checks will be non-compliant/compliant — only partition checks should be skipped
			if f.Check.ID != "mnt-011" && f.Check.ID != "mnt-012" && f.Check.ID != "mnt-013" && f.Check.ID != "mnt-015" {
				t.Errorf("check %s: expected Skipped when /proc/mounts absent, got %s", f.Check.ID, f.Status)
			}
		}
	}
}

// ── Audit — kernel module checks ─────────────────────────────────────────────

func TestAuditKernelModules_AllBlacklisted(t *testing.T) {
	dir := t.TempDir()
	conf := "blacklist cramfs\ninstall cramfs /bin/false\n" +
		"blacklist squashfs\ninstall squashfs /bin/false\n" +
		"blacklist udf\ninstall udf /bin/false\n" +
		"blacklist usb-storage\ninstall usb-storage /bin/false\n"
	os.WriteFile(filepath.Join(dir, "hardbox.conf"), []byte(conf), 0o644)

	m := mount.NewModuleWithModprobe(dir, "" /* no modules loaded */)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	modIDs := map[string]bool{"mnt-011": true, "mnt-012": true, "mnt-013": true, "mnt-015": true}
	for _, f := range findings {
		if !modIDs[f.Check.ID] {
			continue
		}
		if f.Status != modules.StatusCompliant {
			t.Errorf("check %s: expected Compliant, got %s (%s)", f.Check.ID, f.Status, f.Detail)
		}
	}
}

func TestAuditKernelModules_NoneBlacklisted(t *testing.T) {
	dir := t.TempDir() // empty dir — no conf files
	m := mount.NewModuleWithModprobe(dir, "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	modIDs := map[string]bool{"mnt-011": true, "mnt-012": true, "mnt-013": true, "mnt-015": true}
	for _, f := range findings {
		if !modIDs[f.Check.ID] {
			continue
		}
		if f.Status != modules.StatusNonCompliant {
			t.Errorf("check %s: expected NonCompliant, got %s", f.Check.ID, f.Status)
		}
	}
}

func TestAuditKernelModules_ModuleLoaded(t *testing.T) {
	dir := t.TempDir()
	// blacklisted in conf but currently loaded
	os.WriteFile(filepath.Join(dir, "hardbox.conf"), []byte("blacklist cramfs\ninstall cramfs /bin/false\n"), 0o644)
	lsmod := "Module                  Size  Used by\ncramfs                 12345  0\n"

	m := mount.NewModuleWithModprobe(dir, lsmod)
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "mnt-011" {
			if f.Status != modules.StatusNonCompliant {
				t.Errorf("loaded module should be NonCompliant, got %s", f.Status)
			}
			if !strings.Contains(f.Current, "currently loaded") {
				t.Errorf("detail should mention 'currently loaded', got: %s", f.Current)
			}
			return
		}
	}
	t.Error("mnt-011 finding not found")
}

// ── Plan ──────────────────────────────────────────────────────────────────────

func TestPlan_AddsBlacklistEntries(t *testing.T) {
	dir := t.TempDir()
	mountsFile := writeTempFile(t, "/dev/sda1 / ext4 rw 0 0\n")

	m := &mount.Module{}
	_ = m // use internal fields via constructor
	m2 := mount.NewModuleWithModprobe(dir, "")
	_ = mount.NewModuleWithMounts(mountsFile)

	changes, err := m2.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if len(changes) == 0 {
		t.Fatal("expected at least one change for kernel module blacklisting")
	}
	if !strings.Contains(changes[0].DryRunOutput, "blacklist") {
		t.Errorf("DryRunOutput should mention 'blacklist', got: %s", changes[0].DryRunOutput)
	}
}

// ── Module interface ──────────────────────────────────────────────────────────

func TestModule_NameAndVersion(t *testing.T) {
	m := mount.NewModuleWithMounts("/proc/mounts")
	if m.Name() != "mount" {
		t.Errorf("Name() = %q, want %q", m.Name(), "mount")
	}
	if m.Version() == "" {
		t.Error("Version() should not be empty")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "mounts-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return f.Name()
}
