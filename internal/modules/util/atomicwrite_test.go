package util_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules/util"
)

func TestAtomicWrite(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("success_new_file", func(t *testing.T) {
		path := filepath.Join(tempDir, "new_file.txt")
		data := []byte("hello world")
		mode := os.FileMode(0644)

		err := util.AtomicWrite(path, data, mode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("failed to stat file: %v", err)
		}

		if info.Mode() != mode {
			t.Errorf("expected mode %v, got %v", mode, info.Mode())
		}

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		if string(content) != string(data) {
			t.Errorf("expected content %q, got %q", string(data), string(content))
		}
	})

	t.Run("success_overwrite_file", func(t *testing.T) {
		path := filepath.Join(tempDir, "overwrite_file.txt")
		initialData := []byte("initial")
		mode := os.FileMode(0644)

		if err := os.WriteFile(path, initialData, mode); err != nil {
			t.Fatalf("failed to write initial file: %v", err)
		}

		newData := []byte("new data")
		newMode := os.FileMode(0600)

		err := util.AtomicWrite(path, newData, newMode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("failed to stat file: %v", err)
		}

		if info.Mode() != newMode {
			t.Errorf("expected mode %v, got %v", newMode, info.Mode())
		}

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		if string(content) != string(newData) {
			t.Errorf("expected content %q, got %q", string(newData), string(content))
		}
	})

	t.Run("success_creates_parent_directories", func(t *testing.T) {
		path := filepath.Join(tempDir, "nested", "dir", "file.txt")
		data := []byte("nested")
		mode := os.FileMode(0644)

		err := util.AtomicWrite(path, data, mode)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}

		if string(content) != string(data) {
			t.Errorf("expected content %q, got %q", string(data), string(content))
		}
	})

	t.Run("error_invalid_directory", func(t *testing.T) {
		filePath := filepath.Join(tempDir, "is_a_file")
		if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		path := filepath.Join(filePath, "file.txt")
		data := []byte("test")
		mode := os.FileMode(0644)

		err := util.AtomicWrite(path, data, mode)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
