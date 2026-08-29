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

func TestAssertStatus(t *testing.T) {
	findings := []modules.Finding{
		{
			Check:  modules.Check{ID: "test-001"},
			Status: modules.StatusCompliant,
		},
		{
			Check:  modules.Check{ID: "test-002"},
			Status: modules.StatusNonCompliant,
		},
	}

	// Test matching ID with expected status (should pass)
	fakeT1 := &testing.T{}
	testutil.AssertStatus(fakeT1, findings, "test-001", modules.StatusCompliant)
	if fakeT1.Failed() {
		t.Errorf("AssertStatus failed unexpectedly for matching check and status")
	}

	// Test matching ID with unexpected status (should fail fakeT2)
	fakeT2 := &testing.T{}
	testutil.AssertStatus(fakeT2, findings, "test-001", modules.StatusNonCompliant)
	if !fakeT2.Failed() {
		t.Errorf("AssertStatus should have failed when status mismatched")
	}

	// Test missing check ID (should fail fakeT3)
	fakeT3 := &testing.T{}
	testutil.AssertStatus(fakeT3, findings, "test-003", modules.StatusCompliant)
	if !fakeT3.Failed() {
		t.Errorf("AssertStatus should have failed when check ID was missing")
	}
}
