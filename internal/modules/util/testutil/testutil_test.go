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
	"sync"
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
)

func TestAssertStatus(t *testing.T) {
	findings := []modules.Finding{
		{
			Check:  modules.Check{ID: "check-1"},
			Status: modules.StatusCompliant,
		},
		{
			Check:  modules.Check{ID: "check-2"},
			Status: modules.StatusNonCompliant,
		},
	}

	t.Run("matching check ID and status", func(t *testing.T) {
		testutil.AssertStatus(t, findings, "check-1", modules.StatusCompliant)
		testutil.AssertStatus(t, findings, "check-2", modules.StatusNonCompliant)
	})

	t.Run("status mismatch", func(t *testing.T) {
		mockT := &testing.T{}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			testutil.AssertStatus(mockT, findings, "check-1", modules.StatusNonCompliant)
		}()
		wg.Wait()
		if !mockT.Failed() {
			t.Errorf("expected AssertStatus to fail when status mismatches")
		}
	})

	t.Run("check ID not found", func(t *testing.T) {
		mockT := &testing.T{}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			testutil.AssertStatus(mockT, findings, "check-3", modules.StatusCompliant)
		}()
		wg.Wait()
		if !mockT.Failed() {
			t.Errorf("expected AssertStatus to fail when check ID is not found")
		}
	})
}
