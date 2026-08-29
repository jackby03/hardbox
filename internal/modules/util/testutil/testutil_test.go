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

package testutil_test

import (
	"path/filepath"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
)

func TestTestdataPath(t *testing.T) {
	got := testutil.TestdataPath("foo", "bar.txt")
	want := filepath.Join("testdata", "foo", "bar.txt")
	if got != want {
		t.Errorf("TestdataPath() = %q, want %q", got, want)
	}
}

func TestTestdataAbsPath(t *testing.T) {
	got := testutil.TestdataAbsPath(t, "foo.txt")
	want, err := filepath.Abs(filepath.Join("testdata", "foo.txt"))
	if err != nil {
		t.Fatalf("filepath.Abs error: %v", err)
	}
	if got != want {
		t.Errorf("TestdataAbsPath() = %q, want %q", got, want)
	}
}

func TestAssertStatus(t *testing.T) {
	findings := []modules.Finding{
		{
			Check:   modules.Check{ID: "check-1"},
			Status:  modules.StatusCompliant,
			Current: "enabled",
			Detail:  "check 1 detail",
		},
		{
			Check:   modules.Check{ID: "check-2"},
			Status:  modules.StatusNonCompliant,
			Current: "disabled",
			Detail:  "check 2 detail",
		},
	}

	t.Run("matching status", func(t *testing.T) {
		testutil.AssertStatus(t, findings, "check-1", modules.StatusCompliant)
		testutil.AssertStatus(t, findings, "check-2", modules.StatusNonCompliant)
	})

	t.Run("status mismatch", func(t *testing.T) {
		mockT := &testing.T{}
		testutil.AssertStatus(mockT, findings, "check-1", modules.StatusNonCompliant)
		if !mockT.Failed() {
			t.Errorf("AssertStatus should have failed on status mismatch")
		}
	})

	t.Run("check not found", func(t *testing.T) {
		mockT := &testing.T{}
		testutil.AssertStatus(mockT, findings, "check-3", modules.StatusCompliant)
		if !mockT.Failed() {
			t.Errorf("AssertStatus should have failed when check ID was not found")
		}
	})
}
