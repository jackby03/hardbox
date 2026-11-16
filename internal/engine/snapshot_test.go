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

package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
)

// TestNewSnapshot_BacksUpDeclaredFiles is the regression test for the defect
// where newSnapshot ignored the changes it was given, so rollback iterated an
// empty file list and reported success without restoring anything.
func TestNewSnapshot_BacksUpDeclaredFiles(t *testing.T) {
	base := t.TempDir()
	work := t.TempDir()

	existing := filepath.Join(work, "existing.conf")
	if err := os.WriteFile(existing, []byte("original\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(work, "created.conf")

	changes := []modules.Change{
		{Description: "modifies", Files: []string{existing}},
		{Description: "creates", Files: []string{created}},
	}

	snap, err := newSnapshotAt(base, "sess", changes)
	if err != nil {
		t.Fatalf("newSnapshotAt: %v", err)
	}
	if len(snap.FilesBackedUp) != 2 {
		t.Fatalf("expected 2 recorded paths, got %d: %+v", len(snap.FilesBackedUp), snap.FilesBackedUp)
	}

	byPath := map[string]fileBackup{}
	for _, fb := range snap.FilesBackedUp {
		byPath[fb.Path] = fb
	}
	if fb := byPath[existing]; !fb.Existed {
		t.Errorf("existing file must be recorded as existed: %+v", fb)
	} else if testutil.UnixPermsSupported() && fb.Mode.Perm() != 0o640 {
		t.Errorf("mode not recorded: got %04o want 0640", fb.Mode.Perm())
	}
	if fb := byPath[created]; fb.Existed {
		t.Errorf("missing file must be recorded as created, got %+v", fb)
	}
}

// TestNewSnapshot_DeduplicatesPaths ensures a path declared by two changes is
// copied once.
func TestNewSnapshot_DeduplicatesPaths(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(t.TempDir(), "shared.conf")
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	snap, err := newSnapshotAt(base, "sess", []modules.Change{
		{Files: []string{path}},
		{Files: []string{path}},
	})
	if err != nil {
		t.Fatalf("newSnapshotAt: %v", err)
	}
	if len(snap.FilesBackedUp) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(snap.FilesBackedUp))
	}
}

// TestRestore_RewritesAndRemoves covers both halves of a real rollback: content
// that was modified comes back, and a path created by apply is deleted.
func TestRestore_RewritesAndRemoves(t *testing.T) {
	base := t.TempDir()
	work := t.TempDir()

	modified := filepath.Join(work, "modified.conf")
	if err := os.WriteFile(modified, []byte("original\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(work, "created.conf")

	snap, err := newSnapshotAt(base, "sess", []modules.Change{{
		Files: []string{modified, created},
	}})
	if err != nil {
		t.Fatalf("newSnapshotAt: %v", err)
	}
	if err := snap.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Simulate the apply phase.
	if err := os.WriteFile(modified, []byte("hardened\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(created, []byte("new file\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := snap.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	got, err := os.ReadFile(modified)
	if err != nil {
		t.Fatalf("reading restored file: %v", err)
	}
	if string(got) != "original\n" {
		t.Errorf("content not restored: %q", got)
	}
	info, err := os.Stat(modified)
	if err != nil {
		t.Fatal(err)
	}
	if testutil.UnixPermsSupported() && info.Mode().Perm() != 0o640 {
		t.Errorf("mode not restored: got %04o want 0640", info.Mode().Perm())
	}

	if _, err := os.Stat(created); !os.IsNotExist(err) {
		t.Errorf("file created by apply should be removed on rollback, stat err = %v", err)
	}
}

// TestRestore_SkipsUnreadableSysctl verifies that a sysctl key that does not
// exist on this kernel does not abort snapshot creation.
func TestRestore_SkipsUnreadableSysctl(t *testing.T) {
	snap, err := newSnapshotAt(t.TempDir(), "sess", []modules.Change{
		{SysctlKeys: []string{"hardbox.does.not.exist"}},
	})
	if err != nil {
		t.Fatalf("newSnapshotAt must tolerate unknown sysctl keys: %v", err)
	}
	if len(snap.SysctlValues) != 0 {
		t.Errorf("unknown key must not be snapshotted, got %+v", snap.SysctlValues)
	}
}
