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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

// snapshotBaseDir is a variable so tests can redirect it away from /var/lib.
var snapshotBaseDir = "/var/lib/hardbox/snapshots"

// snapshot records the pre-apply state of the system so changes can be reverted.
type snapshot struct {
	SessionID     string            `json:"session_id"`
	Host          string            `json:"host"`
	Profile       string            `json:"profile"`
	Timestamp     time.Time         `json:"timestamp"`
	FilesBackedUp []fileBackup      `json:"files_backed_up"`
	SysctlValues  map[string]string `json:"sysctl_snapshot"`

	dir string // base directory on disk, not serialised
}

type fileBackup struct {
	Path   string      `json:"path"`
	SHA256 string      `json:"sha256"`
	Mode   os.FileMode `json:"mode"`
	// Existed is false when the change creates this path. Rollback then removes
	// the file instead of restoring content that was never there.
	Existed bool `json:"existed"`
}

// newSnapshot collects the current values of all resources that will be modified.
//
// Every path and sysctl key declared by the changes is captured here, before
// anything is applied. Rollback can only restore what was recorded at this
// point, so a change that modifies a file without declaring it is unrecoverable.
func newSnapshot(sessionID string, changes []modules.Change) (*snapshot, error) {
	return newSnapshotAt(snapshotBaseDir, sessionID, changes)
}

// newSnapshotAt is newSnapshot with an injectable base directory, so the backup
// and restore path can be tested without writing to /var/lib.
func newSnapshotAt(baseDir, sessionID string, changes []modules.Change) (*snapshot, error) {
	hostname, _ := os.Hostname()
	snap := &snapshot{
		SessionID: sessionID,
		Host:      hostname,
		Timestamp: time.Now().UTC(),
		dir:       filepath.Join(baseDir, sessionID),
	}

	seenFile := make(map[string]struct{})
	for _, ch := range changes {
		for _, path := range ch.Files {
			if path == "" {
				continue
			}
			if _, dup := seenFile[path]; dup {
				continue
			}
			seenFile[path] = struct{}{}
			if err := snap.BackupFile(path); err != nil {
				return nil, fmt.Errorf("backing up %s: %w", path, err)
			}
		}
		for _, key := range ch.SysctlKeys {
			if key == "" {
				continue
			}
			if _, ok := snap.SysctlValues[key]; ok {
				continue
			}
			value, err := readSysctl(key)
			if err != nil {
				// A key that does not exist on this kernel is not an error: there
				// is nothing to restore and the change most likely skips it too.
				log.Debug().Str("key", key).Err(err).Msg("sysctl not readable, not snapshotted")
				continue
			}
			if snap.SysctlValues == nil {
				snap.SysctlValues = make(map[string]string)
			}
			snap.SysctlValues[key] = value
		}
	}
	return snap, nil
}

// Save writes the snapshot manifest to disk.
func (s *snapshot) Save() error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("creating snapshot dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := util.AtomicWrite(filepath.Join(s.dir, "manifest.json"), data, 0o600); err != nil {
		return err
	}
	return nil
}

// snapshotRelativePath maps a target path to its location under the snapshot's
// files/ directory. Absolute paths cannot be used as a nested directory tree
// directly: on Windows the drive letter carries a colon, and on any platform a
// leading separator would produce an empty first element.
func snapshotRelativePath(target string) string {
	p := filepath.Clean(target)
	if vol := filepath.VolumeName(p); vol != "" {
		p = p[len(vol):]
	}
	return strings.TrimLeft(p, `/\`)
}

// BackupFile copies srcPath into the snapshot directory before it is modified.
//
// A path that does not exist yet is still recorded, with Existed=false, so that
// rollback removes it. Skipping it, as this used to do, silently leaked files
// created by Apply into a system that claims to be reverted.
func (s *snapshot) BackupFile(srcPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.FilesBackedUp = append(s.FilesBackedUp, fileBackup{
				Path:    srcPath,
				Existed: false,
			})
			return nil
		}
		return err
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	destDir := filepath.Join(s.dir, "files", filepath.Dir(snapshotRelativePath(srcPath)))
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return err
	}
	dest := filepath.Join(destDir, filepath.Base(srcPath))
	if err := util.AtomicWrite(dest, data, 0600); err != nil {
		return err
	}

	info, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("stat %s for backup: %w", srcPath, err)
	}

	s.FilesBackedUp = append(s.FilesBackedUp, fileBackup{
		Path:    srcPath,
		SHA256:  hash,
		Mode:    info.Mode().Perm(),
		Existed: true,
	})
	return nil
}

// Restore reverts every recorded change: files get their previous content back,
// paths the apply created are removed, and sysctl values are written back.
func (s *snapshot) Restore() error {
	for _, fb := range s.FilesBackedUp {
		if !fb.Existed {
			if err := os.Remove(fb.Path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("removing %s created by apply: %w", fb.Path, err)
			}
			continue
		}

		srcInSnap := filepath.Join(s.dir, "files", snapshotRelativePath(fb.Path))
		data, err := os.ReadFile(srcInSnap)
		if err != nil {
			return fmt.Errorf("reading backup for %s: %w", fb.Path, err)
		}

		// Ensure the parent directory already exists and is a directory before
		// writing. util.AtomicWrite would create missing parents with mode 0755,
		// which is unsafe for paths like /root/.ssh that must not be created.
		parentDir := filepath.Dir(fb.Path)
		info, statErr := os.Stat(parentDir)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return fmt.Errorf("restoring %s: parent directory %s does not exist", fb.Path, parentDir)
			}
			return fmt.Errorf("restoring %s: stat parent directory %s: %w", fb.Path, parentDir, statErr)
		}
		if !info.IsDir() {
			return fmt.Errorf("restoring %s: parent path %s is not a directory", fb.Path, parentDir)
		}

		mode := fb.Mode
		if mode == 0 {
			mode = 0644 // fallback for snapshots created before mode was recorded
		}
		if err := util.AtomicWrite(fb.Path, data, mode); err != nil {
			return fmt.Errorf("restoring %s: %w", fb.Path, err)
		}
	}

	for key, value := range s.SysctlValues {
		if err := writeSysctl(key, value); err != nil {
			return fmt.Errorf("restoring sysctl %s: %w", key, err)
		}
	}
	return nil
}

// ── sysctl helpers ──────────────────────────────────────────────────────────

// sysctlPath maps a dotted key to its /proc/sys file.
func sysctlPath(key string) string {
	return filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))
}

func readSysctl(key string) (string, error) {
	data, err := os.ReadFile(sysctlPath(key))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func writeSysctl(key, value string) error {
	return os.WriteFile(sysctlPath(key), []byte(value), 0o644)
}

// ── listing / loading snapshots ─────────────────────────────────────────────

func listSnapshots() ([]*snapshot, error) {
	entries, err := os.ReadDir(snapshotBaseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var snaps []*snapshot
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		s, err := loadSnapshot(e.Name())
		if err != nil {
			continue
		}
		snaps = append(snaps, s)
	}
	sort.Slice(snaps, func(i, j int) bool {
		return snaps[i].Timestamp.After(snaps[j].Timestamp)
	})
	return snaps, nil
}

func loadSnapshot(sessionID string) (*snapshot, error) {
	dir := filepath.Join(snapshotBaseDir, sessionID)
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var s snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	s.dir = dir
	return &s, nil
}

func latestSnapshot() (*snapshot, error) {
	snaps, err := listSnapshots()
	if err != nil {
		return nil, err
	}
	if len(snaps) == 0 {
		return nil, fmt.Errorf("no snapshots found")
	}
	return snaps[0], nil
}
