// Package util provides shared helpers for hardbox modules.
package util

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWrite writes data to path using a temp-file + rename so the target
// is never left in a partial state.
func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("atomicWrite mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".hardbox-tmp-")
	if err != nil {
		return fmt.Errorf("atomicWrite create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("atomicWrite write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("atomicWrite close: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("atomicWrite chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("atomicWrite rename: %w", err)
	}
	return nil
}
