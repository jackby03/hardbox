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

// AssertStatus verifies that a finding with the given check ID exists in findings
// and has the expected status.
func AssertStatus(t *testing.T, findings []modules.Finding, id string, want modules.Status) {
	t.Helper()
	for _, f := range findings {
		if f.Check.ID == id {
			if f.Status != want {
				t.Errorf("check %s: got %q, want %q (current=%q)", id, f.Status, want, f.Current)
			}
			return
		}
	}
	t.Errorf("check %s: not found in findings", id)
}
