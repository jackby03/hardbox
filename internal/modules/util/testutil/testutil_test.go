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
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
)

func TestTestdataPath(t *testing.T) {
	path := testutil.TestdataPath("foo", "bar")
	expected := "testdata/foo/bar"
	if path != expected {
		t.Errorf("got %q, want %q", path, expected)
	}
}

func TestTestdataAbsPath(t *testing.T) {
	path := testutil.TestdataAbsPath(t, "foo")
	if path == "" {
		t.Error("expected non-empty absolute path")
	}
}

func TestAssertStatus(t *testing.T) {
	findings := []modules.Finding{
		{
			Check:   modules.Check{ID: "chk-001"},
			Status:  modules.StatusCompliant,
			Current: "enabled",
			Detail:  "all good",
		},
		{
			Check:   modules.Check{ID: "chk-002"},
			Status:  modules.StatusNonCompliant,
			Current: "disabled",
			Detail:  "needs fix",
		},
	}

	t.Run("Status matches expected", func(t *testing.T) {
		mockT := &testing.T{}
		testutil.AssertStatus(mockT, findings, "chk-001", modules.StatusCompliant)
		if mockT.Failed() {
			t.Errorf("expected AssertStatus to succeed for matching status")
		}
	})

	t.Run("Status mismatch", func(t *testing.T) {
		mockT := &testing.T{}
		testutil.AssertStatus(mockT, findings, "chk-001", modules.StatusNonCompliant)
		if !mockT.Failed() {
			t.Errorf("expected AssertStatus to fail for mismatched status")
		}
	})

	t.Run("Check ID not found", func(t *testing.T) {
		mockT := &testing.T{}
		testutil.AssertStatus(mockT, findings, "chk-003", modules.StatusCompliant)
		if !mockT.Failed() {
			t.Errorf("expected AssertStatus to fail for missing check ID")
		}
	})
}
