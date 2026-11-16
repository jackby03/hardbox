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

package filesystem

import (
	"path/filepath"
	"testing"
)

func TestParseMountEntries(t *testing.T) {
	data := []byte(`/dev/sda1 / ext4 rw,relatime 0 0
C:\134 /mnt/c 9p rw,noatime 0 0
nas:/vol /srv/with\040space nfs4 rw 0 0
# a comment

malformed
`)

	entries := parseMountEntries(data)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d: %+v", len(entries), entries)
	}
	if entries[1].MountPoint != "/mnt/c" || entries[1].FSType != "9p" {
		t.Errorf("unexpected 9p entry: %+v", entries[1])
	}
	if entries[2].MountPoint != "/srv/with space" || entries[2].FSType != "nfs4" {
		t.Errorf("octal escape not decoded: %+v", entries[2])
	}
}

func TestScanSkipFunc(t *testing.T) {
	root := string(filepath.Separator)
	overlay := filepath.Join(root, "var", "lib", "docker", "overlay2", "x")
	excluded := map[string]struct{}{
		filepath.Clean(filepath.Join(root, "mnt", "c")): {},
		filepath.Clean(overlay):                       {},
	}
	skip := scanSkipFunc(root, excluded)

	cases := []struct {
		path string
		want bool
	}{
		{root, false},
		{filepath.Join(root, "etc"), false},
		{filepath.Join(root, "mnt", "c"), true},
		{filepath.Join(root, "proc"), true},
		{filepath.Join(root, "sys"), true},
		{filepath.Join(root, "dev"), true},
		{overlay, true},
		{filepath.Join(overlay, "y"), false}, // only the exact mount point is skipped
	}
	for _, c := range cases {
		if got := skip(c.path); got != c.want {
			t.Errorf("skip(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestNonLocalFSTypes(t *testing.T) {
	for _, fs := range []string{"9p", "nfs", "nfs4", "cifs", "overlay", "squashfs", "proc", "sysfs"} {
		if !nonLocalFSTypes[fs] {
			t.Errorf("%s should be skipped", fs)
		}
	}
	// Local storage, including encrypted FUSE disks, must still be scanned.
	for _, fs := range []string{"ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "fuse.gocryptfs", "tmpfs"} {
		if nonLocalFSTypes[fs] {
			t.Errorf("%s must not be skipped", fs)
		}
	}
}
