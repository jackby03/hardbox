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

package filesystem_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/filesystem"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
)

// writeMounts writes a fake /proc/mounts file and returns its path.
func writeMounts(t *testing.T, root string, entries ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proc_mounts")
	lines := []string{
		// The scan root itself must look like ordinary local storage.
		"/dev/sda1 " + root + " ext4 rw,relatime 0 0",
	}
	lines = append(lines, entries...)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write mounts: %v", err)
	}
	return path
}

// TestAudit_WorldWritable_SkipsRemoteMountTree is the regression test for the
// hang where the scan walked every mount under /, including 9p/NFS shares that
// block on a stale handle.
func TestAudit_WorldWritable_SkipsRemoteMountTree(t *testing.T) {
	testutil.RequireUnixPerms(t)

	root := t.TempDir()

	// A world-writable file on local storage: must be reported.
	localDir := filepath.Join(root, "srv")
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		t.Fatal(err)
	}
	localFile := filepath.Join(localDir, "local-ww")
	if err := os.WriteFile(localFile, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(localFile, 0o666); err != nil {
		t.Fatal(err)
	}

	// The same thing behind an NFS mount: must be ignored.
	remoteDir := filepath.Join(root, "remote")
	if err := os.MkdirAll(remoteDir, 0o755); err != nil {
		t.Fatal(err)
	}
	remoteFile := filepath.Join(remoteDir, "remote-ww")
	if err := os.WriteFile(remoteFile, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(remoteFile, 0o666); err != nil {
		t.Fatal(err)
	}

	mounts := writeMounts(t, root, "nas:/export "+remoteDir+" nfs4 rw,relatime 0 0")
	m := filesystem.NewModuleForTest(mounts, root, "")

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fs015 := findFinding(t, findings, "fs-015")
	if !strings.Contains(fs015.Detail, "local-ww") {
		t.Errorf("fs-015 should report the local world-writable file, detail=%q", fs015.Detail)
	}
	if strings.Contains(fs015.Detail, "remote-ww") {
		t.Errorf("fs-015 walked into the nfs mount and reported the remote file, detail=%q", fs015.Detail)
	}
}

// TestAudit_SUIDSGID_SkipsRemoteMountTree covers the second and third scans,
// which had their own copy of the same defect.
func TestAudit_SUIDSGID_SkipsRemoteMountTree(t *testing.T) {
	testutil.RequireUnixPerms(t)

	root := t.TempDir()

	localFile := filepath.Join(root, "local-suid")
	if err := os.WriteFile(localFile, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// In Go the setuid bit is os.ModeSetuid, not the 04000 component of a
	// numeric literal; os.Chmod masks anything outside 0777.
	if err := os.Chmod(localFile, os.FileMode(0o755)|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}

	remoteDir := filepath.Join(root, "remote")
	if err := os.MkdirAll(remoteDir, 0o755); err != nil {
		t.Fatal(err)
	}
	remoteFile := filepath.Join(remoteDir, "remote-suid")
	if err := os.WriteFile(remoteFile, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(remoteFile, os.FileMode(0o755)|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}

	mounts := writeMounts(t, root, "C:\\134 "+remoteDir+" 9p rw,noatime 0 0")
	m := filesystem.NewModuleForTest(mounts, root, "")

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fs017 := findFinding(t, findings, "fs-017")
	if !strings.Contains(fs017.Detail, "local-suid") {
		t.Errorf("fs-017 should report the local SUID file, detail=%q", fs017.Detail)
	}
	if strings.Contains(fs017.Detail, "remote-suid") {
		t.Errorf("fs-017 walked into the 9p mount, detail=%q", fs017.Detail)
	}
}

// TestAudit_DoesNotSkipLocalMounts guards against over-exclusion: a plain ext4
// mount below the root must still be scanned.
func TestAudit_DoesNotSkipLocalMounts(t *testing.T) {
	testutil.RequireUnixPerms(t)

	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ww := filepath.Join(dataDir, "ww")
	if err := os.WriteFile(ww, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ww, 0o666); err != nil {
		t.Fatal(err)
	}

	mounts := writeMounts(t, root, "/dev/sdb1 "+dataDir+" xfs rw,relatime 0 0")
	m := filesystem.NewModuleForTest(mounts, root, "")

	findings, err := m.Audit(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fs015 := findFinding(t, findings, "fs-015")
	if !strings.Contains(fs015.Detail, "ww") {
		t.Errorf("fs-015 must still scan a local ext4/xfs mount, detail=%q", fs015.Detail)
	}
}

func findFinding(t *testing.T, findings []modules.Finding, id string) modules.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			return f
		}
	}
	t.Fatalf("finding %s not found", id)
	return modules.Finding{}
}
