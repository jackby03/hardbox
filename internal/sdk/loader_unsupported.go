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

package sdk

import "fmt"

// LoadPlugins is not supported on this platform. Go's plugin package requires
// Linux, macOS, or FreeBSD. This stub returns an informational error so the
// engine can log a warning and continue without plugins.
func LoadPlugins(_ string) ([]PluginEntry, error) {
	return nil, fmt.Errorf("plugin loading is not supported on this platform (requires Linux, macOS, or FreeBSD)")
}

