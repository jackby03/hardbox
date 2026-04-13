package testutil

import (
	"path/filepath"
	"testing"
)

// TestdataPath returns the relative path to a file or directory in testdata/.
func TestdataPath(elem ...string) string {
	return filepath.Join(append([]string{"testdata"}, elem...)...)
}

// TestdataAbsPath returns the absolute path to a file or directory in testdata/, logging an error if it fails.
// This is provided for compatibility with tests that require absolute paths.
func TestdataAbsPath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("TestdataAbsPath(%q): %v", name, err)
	}
	return p
}
