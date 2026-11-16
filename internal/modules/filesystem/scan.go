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
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// mountEntry is the subset of a /proc/mounts line needed to decide whether a
// scan may descend into a mount point.
type mountEntry struct {
	MountPoint string
	FSType     string
}

// nonLocalFSTypes lists filesystem types that a directory scan must not
// descend into. Two distinct hazards are covered:
//
//   - Network and emulated filesystems (9p, NFS, CIFS, sshfs, ...). Reading a
//     stale handle can block indefinitely, so a scan that walks one turns an
//     audit that finishes in seconds into one that hangs until the mount is
//     recovered. This is how `hardbox audit` hung on WSL, where the Windows
//     drives appear as 9p mounts under /mnt.
//   - Layered and pseudo filesystems (overlay, squashfs, proc, sysfs, ...).
//     On a Docker or snap host these duplicate the root tree once per layer,
//     and the kernel virtual trees contain no files worth auditing.
//
// The list is deliberately narrow. Generic FUSE types are not skipped, because
// an encrypted disk mounted with gocryptfs or similar is local storage the
// operator does expect to be audited.
var nonLocalFSTypes = map[string]bool{
	// Network and emulated.
	"9p": true, "drvfs": true, "virtiofs": true,
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "smbfs": true,
	"sshfs": true, "fuse.sshfs": true, "ceph": true, "glusterfs": true,
	"afs": true, "lustre": true, "gpfs": true, "beegfs": true,
	// Layered container and read-only image filesystems.
	"overlay": true, "squashfs": true, "erofs": true, "fuse.snapfuse": true,
	// Kernel pseudo filesystems.
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
	"cgroup": true, "cgroup2": true, "securityfs": true, "debugfs": true,
	"tracefs": true, "bpf": true, "configfs": true, "pstore": true,
	"mqueue": true, "hugetlbfs": true, "fusectl": true, "binfmt_misc": true,
	"nsfs": true, "rpc_pipefs": true, "selinuxfs": true, "autofs": true,
	"ramfs": true,
}

// parseMountEntries returns the mount point and filesystem type of every entry
// in a /proc/mounts style file.
func parseMountEntries(data []byte) []mountEntry {
	var entries []mountEntry
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: device mountpoint fstype options dump pass
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		entries = append(entries, mountEntry{
			MountPoint: unescapeOctal(fields[1]),
			FSType:     fields[2],
		})
	}
	return entries
}

// unescapeOctal decodes the \ooo escapes that /proc/mounts uses for characters
// that would otherwise be ambiguous, such as \040 for a space.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	).Replace(s)
}

// scanExclusions returns the mount points beneath the scan root that directory
// scans must not descend into. It returns nil when /proc/mounts cannot be read,
// in which case callers fall back to skipping the well-known virtual trees.
func (m *Module) scanExclusions() map[string]struct{} {
	root := filepath.Clean(m.scanRoot())

	data, err := os.ReadFile(m.procMounts())
	if err != nil {
		return nil
	}

	excluded := make(map[string]struct{})
	for _, entry := range parseMountEntries(data) {
		if !nonLocalFSTypes[entry.FSType] {
			continue
		}
		mountPoint := filepath.Clean(entry.MountPoint)
		// Never exclude the scan root itself. Inside a container the root
		// filesystem is overlay, and excluding it would skip everything.
		if mountPoint == root {
			continue
		}
		if root != string(os.PathSeparator) &&
			!strings.HasPrefix(mountPoint, root+string(os.PathSeparator)) {
			continue
		}
		excluded[mountPoint] = struct{}{}
	}
	return excluded
}

// scanSkipFunc returns a predicate reporting whether a walk rooted at root
// must not descend into path.
//
// The virtual trees are always skipped, even when /proc/mounts is unreadable,
// because walking them either yields nothing useful or blocks.
func scanSkipFunc(root string, excluded map[string]struct{}) func(path string) bool {
	return func(path string) bool {
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return false
		}
		switch rel {
		case "proc", "sys", "dev":
			return true
		}
		_, ok := excluded[filepath.Clean(path)]
		return ok
	}
}
