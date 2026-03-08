package util

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWrite writes data to path via a temp file rename to avoid partial writes.
func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("AtomicWrite mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".hardbox-tmp-")
	if err != nil {
		return fmt.Errorf("AtomicWrite create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("AtomicWrite write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("AtomicWrite close: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("AtomicWrite chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("AtomicWrite rename: %w", err)
	}
	return nil
}
