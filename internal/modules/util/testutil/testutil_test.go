// Copyright (C) 2026 Hardbox Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

package testutil_test

import (
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
)

func TestTestdataPath(t *testing.T) {
	got := testutil.TestdataPath("foo", "bar")
	if got != "testdata/foo/bar" && got != "testdata\\foo\\bar" {
		t.Errorf("TestdataPath = %q, want testdata/foo/bar", got)
	}
}

func TestTestdataAbsPath(t *testing.T) {
	got := testutil.TestdataAbsPath(t, "foo")
	if got == "" {
		t.Error("TestdataAbsPath returned empty string")
	}
}

func TestAssertStatus(t *testing.T) {
	findings := []modules.Finding{
		{
			Check:  modules.Check{ID: "chk-001"},
			Status: modules.StatusCompliant,
		},
		{
			Check:  modules.Check{ID: "chk-002"},
			Status: modules.StatusNonCompliant,
		},
	}

	testutil.AssertStatus(t, findings, "chk-001", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "chk-002", modules.StatusNonCompliant)
}
