// Copyright (C) 2024 Jack (jackby03)
// Standard AGPLv3 License header or matching existing headers in the codebase

package testutil

import (
	"path/filepath"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
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

// AssertStatus verifies that a finding with the given check ID exists and has the expected status.
func AssertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Errorf("check %s: got status %q, want %q (current=%q, detail=%q)", id, f.Status, want, f.Current, f.Detail)
			}
			return
		}
	}
	t.Errorf("check %s: not found in findings", id)
}
