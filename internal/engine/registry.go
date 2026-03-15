package engine

import (
	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/auditd"
	"github.com/hardbox-io/hardbox/internal/modules/containers"
	"github.com/hardbox-io/hardbox/internal/modules/crypto"
	"github.com/hardbox-io/hardbox/internal/modules/firewall"
	"github.com/hardbox-io/hardbox/internal/modules/ssh"
	"github.com/hardbox-io/hardbox/internal/modules/filesystem"
	"github.com/hardbox-io/hardbox/internal/modules/kernel"
	"github.com/hardbox-io/hardbox/internal/modules/logging"
	"github.com/hardbox-io/hardbox/internal/modules/mac"
	"github.com/hardbox-io/hardbox/internal/modules/network"
	"github.com/hardbox-io/hardbox/internal/modules/ntp"
	"github.com/hardbox-io/hardbox/internal/modules/services"
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
