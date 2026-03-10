package filesystem_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/filesystem"
)

const (
	mountsHardened = "testdata/proc_mounts_hardened"
	mountsDefault  = "testdata/proc_mounts_default"
)

// ── interface compliance ──────────────────────────────────────────────────────

func TestModule_ImplementsInterface(t *testing.T) {
	var _ modules.Module = filesystem.NewModuleForTest("", "", "")
}

func TestModule_NameAndVersion(t *testing.T) {
	m := filesystem.NewModuleForTest("", "", "")
	if m.Name() != "filesystem" {
		t.Errorf("Name(): got %q, want 'filesystem'", m.Name())
	}
	if m.Version() == "" {
		t.Error("Version() should not be empty")
	}
}

// ── Mount option auditing ─────────────────────────────────────────────────────

func TestAudit_MountOptions_AllCompliant(t *testing.T) {
	m := filesystem.NewModuleForTest(mountsHardened, t.TempDir(), "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mountIDs := map[string]bool{
		"fs-001": true, "fs-002": true, "fs-003": true, "fs-004": true,
		"fs-005": true, "fs-006": true, "fs-007": true,
	}
	for _, f := range findings {
		if !mountIDs[f.Check.ID] {
			continue
		}
		if f.Status != modules.StatusCompliant {
			t.Errorf("check %s: expected compliant, got %s (detail: %s)",
				f.Check.ID, f.Status, f.Detail)
		}
	}
}

func TestAudit_MountOptions_MissingOptions(t *testing.T) {
	m := filesystem.NewModuleForTest(mountsDefault, t.TempDir(), "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nonCompliant := 0
	for _, f := range findings {
		if strings.HasPrefix(f.Check.ID, "fs-00") && f.Status == modules.StatusNonCompliant {
			nonCompliant++
		}
	}
	if nonCompliant < 7 {
		t.Errorf("expected 7 non-compliant mount findings, got %d", nonCompliant)
	}
}

func TestAudit_MountOptions_MissingDetail(t *testing.T) {
	m := filesystem.NewModuleForTest(mountsDefault, t.TempDir(), "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "fs-001" {
			if f.Status != modules.StatusNonCompliant {
				t.Fatalf("fs-001: expected non-compliant, got %s", f.Status)
			}
			if !strings.Contains(f.Detail, "noexec") {
				t.Errorf("fs-001 detail should mention missing option 'noexec', got: %s", f.Detail)
			}
		}
	}
}

func TestAudit_MountOptions_NotMounted_Skipped(t *testing.T) {
	tmpDir := t.TempDir()
	mountsPath := filepath.Join(tmpDir, "proc_mounts")
	// Write a mounts file that only has /tmp — other entries are absent.
	content := "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"
	if err := os.WriteFile(mountsPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	m := filesystem.NewModuleForTest(mountsPath, tmpDir, "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "fs-002" && f.Status != modules.StatusSkipped {
			t.Errorf("fs-002 (/dev/shm absent): expected skipped, got %s", f.Status)
		}
	}
}

func TestAudit_MountOptions_NoMountsFile_Skipped(t *testing.T) {
	m := filesystem.NewModuleForTest("/nonexistent/proc/mounts", t.TempDir(), "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if strings.HasPrefix(f.Check.ID, "fs-00") {
			if f.Status != modules.StatusSkipped {
				t.Errorf("check %s: expected skipped when /proc/mounts absent, got %s",
					f.Check.ID, f.Status)
			}
		}
	}
}

// ── File permission auditing ──────────────────────────────────────────────────

func TestAudit_FilePerms_SkippedWhenMissing(t *testing.T) {
	// fsRoot is an empty temp dir — all /etc/* files are absent.
	m := filesystem.NewModuleForTest(mountsHardened, t.TempDir(), "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	permIDs := map[string]bool{
		"fs-010": true, "fs-011": true, "fs-012": true, "fs-013": true,
	}
	for _, f := range findings {
		if permIDs[f.Check.ID] && f.Status != modules.StatusSkipped {
			t.Errorf("check %s: expected skipped (file absent), got %s", f.Check.ID, f.Status)
		}
	}
}

func TestAudit_FilePerms_WrongMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission model not available on Windows")
	}

	fsRoot := t.TempDir()
	etcDir := filepath.Join(fsRoot, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Write /etc/passwd with 0777 (too permissive).
	passwdPath := filepath.Join(etcDir, "passwd")
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o777); err != nil {
		t.Fatal(err)
	}

	m := filesystem.NewModuleForTest(mountsHardened, fsRoot, "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "fs-010" {
			if f.Status != modules.StatusNonCompliant {
				t.Errorf("fs-010: expected non-compliant for 0777, got %s", f.Status)
			}
			return
		}
	}
	t.Error("fs-010 finding not found")
}

func TestAudit_FilePerms_CorrectMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission model not available on Windows")
	}

	fsRoot := t.TempDir()
	etcDir := filepath.Join(fsRoot, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}

	passwdPath := filepath.Join(etcDir, "passwd")
	if err := os.WriteFile(passwdPath, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := filesystem.NewModuleForTest(mountsHardened, fsRoot, "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "fs-010" {
			// Mode is correct; ownership check depends on platform — accept compliant or non-compliant.
			if f.Status == modules.StatusError {
				t.Errorf("fs-010: unexpected error status: %s", f.Detail)
			}
			return
		}
	}
	t.Error("fs-010 finding not found")
}

// ── Sticky bit on /tmp (fs-019) ───────────────────────────────────────────────

func TestAudit_StickyTmp_Compliant(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sticky bit not supported on Windows")
	}

	fsRoot := t.TempDir()
	tmpPath := filepath.Join(fsRoot, "tmp")
	if err := os.MkdirAll(tmpPath, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpPath, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}

	m := filesystem.NewModuleForTest(mountsHardened, fsRoot, "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "fs-019" {
			if f.Status != modules.StatusCompliant {
				t.Errorf("fs-019: expected compliant, got %s", f.Status)
			}
			return
		}
	}
	t.Error("fs-019 finding not found")
}

func TestAudit_StickyTmp_Missing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sticky bit not supported on Windows")
	}

	fsRoot := t.TempDir()
	tmpPath := filepath.Join(fsRoot, "tmp")
	if err := os.MkdirAll(tmpPath, 0o777); err != nil {
		t.Fatal(err)
	}
	// Explicitly remove sticky bit.
	if err := os.Chmod(tmpPath, 0o777); err != nil {
		t.Fatal(err)
	}

	m := filesystem.NewModuleForTest(mountsHardened, fsRoot, "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "fs-019" {
			if f.Status != modules.StatusNonCompliant {
				t.Errorf("fs-019: expected non-compliant without sticky bit, got %s", f.Status)
			}
			return
		}
	}
	t.Error("fs-019 finding not found")
}

func TestAudit_StickyTmp_Skipped_WhenAbsent(t *testing.T) {
	// fsRoot has no /tmp directory.
	m := filesystem.NewModuleForTest(mountsHardened, t.TempDir(), "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "fs-019" {
			if f.Status != modules.StatusSkipped {
				t.Errorf("fs-019: expected skipped when /tmp absent, got %s", f.Status)
			}
			return
		}
	}
	t.Error("fs-019 finding not found")
}

// ── World-writable scan (fs-015) ─────────────────────────────────────────────

func TestAudit_WorldWritable_Clean(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission model not available on Windows")
	}

	fsRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(fsRoot, "normal.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := filesystem.NewModuleForTest(mountsHardened, fsRoot, "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "fs-015" {
			if f.Status != modules.StatusCompliant {
				t.Errorf("fs-015: expected compliant, got %s (detail: %s)", f.Status, f.Detail)
			}
			return
		}
	}
	t.Error("fs-015 finding not found")
}

func TestAudit_WorldWritable_Found(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission model not available on Windows")
	}

	fsRoot := t.TempDir()
	wwFile := filepath.Join(fsRoot, "world_writable.txt")
	if err := os.WriteFile(wwFile, []byte("bad"), 0o666); err != nil {
		t.Fatal(err)
	}
	// Explicitly set world-write bit.
	if err := os.Chmod(wwFile, 0o666); err != nil {
		t.Fatal(err)
	}

	m := filesystem.NewModuleForTest(mountsHardened, fsRoot, "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "fs-015" {
			if f.Status != modules.StatusNonCompliant {
				t.Errorf("fs-015: expected non-compliant, got %s", f.Status)
			}
			if !strings.Contains(f.Detail, "world_writable.txt") {
				t.Errorf("fs-015: detail should mention the world-writable file, got: %s", f.Detail)
			}
			return
		}
	}
	t.Error("fs-015 finding not found")
}

// ── SUID/SGID scan (fs-017) ───────────────────────────────────────────────────

func TestAudit_SUIDSGID_AlwaysManual(t *testing.T) {
	m := filesystem.NewModuleForTest(mountsHardened, t.TempDir(), "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Check.ID == "fs-017" {
			if f.Status != modules.StatusManual {
				t.Errorf("fs-017: expected manual (requires human review), got %s", f.Status)
			}
			return
		}
	}
	t.Error("fs-017 finding not found")
}

// ── Check ID format ───────────────────────────────────────────────────────────

func TestAudit_CheckIDs_HaveCorrectPrefix(t *testing.T) {
	m := filesystem.NewModuleForTest(mountsHardened, t.TempDir(), "")
	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if !strings.HasPrefix(f.Check.ID, "fs-") {
			t.Errorf("check ID %q does not start with 'fs-'", f.Check.ID)
		}
		if f.Check.Title == "" {
			t.Errorf("check %s has empty Title", f.Check.ID)
		}
		if f.Check.Severity == "" {
			t.Errorf("check %s has empty Severity", f.Check.ID)
		}
	}
}

// ── Plan ─────────────────────────────────────────────────────────────────────

func TestPlan_NoChanges_WhenCompliant(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sticky bit not supported on Windows")
	}

	fsRoot := t.TempDir()
	// Create /tmp with sticky bit set (fs-019 compliant).
	tmpPath := filepath.Join(fsRoot, "tmp")
	if err := os.MkdirAll(tmpPath, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpPath, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}

	// No fstab file → all mount checks are skipped.
	m := filesystem.NewModuleForTest(mountsHardened, fsRoot, filepath.Join(fsRoot, "fstab"))
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// File permission checks are skipped (files absent), sticky bit compliant, mounts compliant.
	if len(changes) != 0 {
		t.Errorf("expected 0 changes, got %d", len(changes))
	}
}

func TestPlan_ReturnsChanges_ForMissingMountOptions(t *testing.T) {
	tmpDir := t.TempDir()
	fstabPath := filepath.Join(tmpDir, "fstab")
	if err := os.WriteFile(fstabPath, []byte("tmpfs /tmp tmpfs rw 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := filesystem.NewModuleForTest(mountsDefault, tmpDir, fstabPath)
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(changes) == 0 {
		t.Fatal("expected at least 1 change for non-compliant mount options, got 0")
	}

	// There should be exactly one batched fstab change.
	hasFstabChange := false
	for _, c := range changes {
		if strings.Contains(c.Description, "fstab") {
			hasFstabChange = true
			if c.Description == "" {
				t.Error("Change.Description should not be empty")
			}
			if c.DryRunOutput == "" {
				t.Error("Change.DryRunOutput should not be empty")
			}
			if c.Apply == nil {
				t.Error("Change.Apply should not be nil")
			}
			if c.Revert == nil {
				t.Error("Change.Revert should not be nil")
			}
		}
	}
	if !hasFstabChange {
		t.Error("expected a fstab change in plan")
	}
}

func TestPlan_FstabChange_ApplyRevert(t *testing.T) {
	tmpDir := t.TempDir()
	fstabPath := filepath.Join(tmpDir, "fstab")
	original := "tmpfs /tmp tmpfs rw 0 0\n"
	if err := os.WriteFile(fstabPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	m := filesystem.NewModuleForTest(mountsDefault, tmpDir, fstabPath)
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var fstabChange *modules.Change
	for i := range changes {
		if strings.Contains(changes[i].Description, "fstab") {
			fstabChange = &changes[i]
			break
		}
	}
	if fstabChange == nil {
		t.Fatal("fstab change not found in plan")
	}

	// Apply should update the file.
	if err := fstabChange.Apply(); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	afterApply, _ := os.ReadFile(fstabPath)
	if string(afterApply) == original {
		t.Error("fstab content should have changed after Apply()")
	}
	// Applied content should contain some of the required options.
	if !strings.Contains(string(afterApply), "noexec") && !strings.Contains(string(afterApply), "nosuid") {
		t.Errorf("applied fstab should contain hardened options, got:\n%s", afterApply)
	}

	// Revert should restore the original.
	if err := fstabChange.Revert(); err != nil {
		t.Fatalf("Revert() error: %v", err)
	}
	afterRevert, _ := os.ReadFile(fstabPath)
	if string(afterRevert) != original {
		t.Errorf("Revert() should restore original fstab\nwant: %q\ngot:  %q", original, afterRevert)
	}
}

func TestPlan_StickyBit_ApplyRevert(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sticky bit not supported on Windows")
	}

	fsRoot := t.TempDir()
	tmpPath := filepath.Join(fsRoot, "tmp")
	if err := os.MkdirAll(tmpPath, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpPath, 0o777); err != nil {
		t.Fatal(err)
	}

	m := filesystem.NewModuleForTest(mountsHardened, fsRoot, filepath.Join(fsRoot, "fstab"))
	changes, err := m.Plan(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var stickyChange *modules.Change
	for i := range changes {
		if strings.Contains(changes[i].Description, "sticky") {
			stickyChange = &changes[i]
			break
		}
	}
	if stickyChange == nil {
		t.Fatal("sticky bit change not found in plan")
	}

	if err := stickyChange.Apply(); err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	info, _ := os.Stat(tmpPath)
	if info.Mode()&os.ModeSticky == 0 {
		t.Error("sticky bit should be set after Apply()")
	}

	if err := stickyChange.Revert(); err != nil {
		t.Fatalf("Revert() error: %v", err)
	}
	info, _ = os.Stat(tmpPath)
	if info.Mode()&os.ModeSticky != 0 {
		t.Error("sticky bit should be cleared after Revert()")
	}
}
