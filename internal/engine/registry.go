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
	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/auditd"
	"github.com/hardbox-io/hardbox/internal/modules/containers"
	"github.com/hardbox-io/hardbox/internal/modules/crypto"
	"github.com/hardbox-io/hardbox/internal/modules/filesystem"
	"github.com/hardbox-io/hardbox/internal/modules/firewall"
	"github.com/hardbox-io/hardbox/internal/modules/kernel"
	"github.com/hardbox-io/hardbox/internal/modules/logging"
	"github.com/hardbox-io/hardbox/internal/modules/mac"
	"github.com/hardbox-io/hardbox/internal/modules/mount"
	"github.com/hardbox-io/hardbox/internal/modules/network"
	"github.com/hardbox-io/hardbox/internal/modules/ntp"
	"github.com/hardbox-io/hardbox/internal/modules/services"
	"github.com/hardbox-io/hardbox/internal/modules/ssh"
	"github.com/hardbox-io/hardbox/internal/modules/updates"
	"github.com/hardbox-io/hardbox/internal/modules/users"
)

// registeredModules returns the list of all built-in hardening modules.
// Each module is instantiated here; disabled ones are filtered by the engine.
func registeredModules() []modules.Module {
	// Modules are applied in dependency order:
	// kernel and filesystem first, then services, then daemons, then access control.
	return []modules.Module{
		&kernel.Module{},
		&filesystem.Module{},
		&mount.Module{},
		&mac.Module{},
		&network.Module{},
		&ntp.Module{},
		&services.Module{},
		&updates.Module{},
		&auditd.Module{},
		&logging.Module{},
		&users.Module{},
		&firewall.Module{},
		&crypto.Module{},
		&containers.Module{},
		&ssh.Module{},
		// Stub placeholders — each will be fully implemented in its own package.
		// &pam.Module{},
	}
}

