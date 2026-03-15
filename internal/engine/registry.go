package engine

import (
	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/auditd"
	"github.com/hardbox-io/hardbox/internal/modules/filesystem"
	"github.com/hardbox-io/hardbox/internal/modules/kernel"
	"github.com/hardbox-io/hardbox/internal/modules/logging"
	"github.com/hardbox-io/hardbox/internal/modules/mac"
	"github.com/hardbox-io/hardbox/internal/modules/network"
	"github.com/hardbox-io/hardbox/internal/modules/ntp"
	"github.com/hardbox-io/hardbox/internal/modules/services"
	"github.com/hardbox-io/hardbox/internal/modules/updates"
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
		// Stub placeholders — each will be fully implemented in its own package.
		// &ssh.Module{},
		// &firewall.Module{},
		// &users.Module{},
		// &pam.Module{},
		// &crypto.Module{},
		// &containers.Module{},
	}
}
