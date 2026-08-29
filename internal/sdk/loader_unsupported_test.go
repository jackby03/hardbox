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

//go:build !linux && !darwin && !freebsd

package sdk_test

import (
	"strings"
	"testing"

	"github.com/hardbox-io/hardbox/internal/sdk"
)

func TestLoadPlugins_Unsupported(t *testing.T) {
	entries, err := sdk.LoadPlugins("any/dir")
	if err == nil {
		t.Fatal("expected error on unsupported platform, got nil")
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries on unsupported platform, got %d", len(entries))
	}
	if !strings.Contains(err.Error(), "not supported on this platform") {
		t.Errorf("expected unsupported platform error message, got: %v", err)
	}
}
