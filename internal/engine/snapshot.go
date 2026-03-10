package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util"
)

const snapshotBaseDir = "/var/lib/hardbox/snapshots"

// snapshot records the pre-apply state of the system so changes can be reverted.
type snapshot struct {
	SessionID    string            `json:"session_id"`
	Host         string            `json:"host"`
	Profile      string            `json:"profile"`
	Timestamp    time.Time         `json:"timestamp"`
	FilesBackedUp []fileBackup     `json:"files_backed_up"`
	SysctlValues map[string]string `json:"sysctl_snapshot"`

	dir string // base directory on disk, not serialised
}

type fileBackup struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// newSnapshot collects the current values of all resources that will be modified.
func newSnapshot(sessionID string, changes []modules.Change) (*snapshot, error) {
	hostname, _ := os.Hostname()
	snap := &snapshot{
		SessionID: sessionID,
		Host:      hostname,
		Timestamp: time.Now().UTC(),
		dir:       filepath.Join(snapshotBaseDir, sessionID),
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
	return os.WriteFile(filepath.Join(s.dir, "manifest.json"), data, 0600)
}

// BackupFile copies srcPath into the snapshot directory before it is modified.
func (s *snapshot) BackupFile(srcPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing to back up
		}
		return err
	}

	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])

	destDir := filepath.Join(s.dir, "files", filepath.Dir(srcPath))
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return err
	}
	dest := filepath.Join(destDir, filepath.Base(srcPath))
	if err := os.WriteFile(dest, data, 0600); err != nil {
		return err
	}

	s.FilesBackedUp = append(s.FilesBackedUp, fileBackup{Path: srcPath, SHA256: hash})
	return nil
}

// Restore reverts all backed-up files to their original content.
func (s *snapshot) Restore() error {
	for _, fb := range s.FilesBackedUp {
		srcInSnap := filepath.Join(s.dir, "files", fb.Path)
		data, err := os.ReadFile(srcInSnap)
		if err != nil {
			return fmt.Errorf("reading backup for %s: %w", fb.Path, err)
		}
		if err := util.AtomicWrite(fb.Path, data, 0644); err != nil {
			return fmt.Errorf("restoring %s: %w", fb.Path, err)
		}
	}
	return nil
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
