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

package engine

import (
	"github.com/hardbox-io/hardbox/internal/config"
	"github.com/hardbox-io/hardbox/internal/modules"
)

// NewEngineForTest returns an Engine with an injected module list so a failing
// module can be exercised without touching the real registry.
func NewEngineForTest(cfg *config.Config, mods ...modules.Module) *Engine {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &Engine{cfg: cfg, modules: mods}
}
