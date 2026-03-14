package engine

import (
	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/filesystem"
	"github.com/hardbox-io/hardbox/internal/modules/kernel"
	"github.com/hardbox-io/hardbox/internal/modules/ntp"
	"github.com/hardbox-io/hardbox/internal/modules/services"
)

// registeredModules returns the list of all built-in hardening modules.
// Each module is instantiated here; disabled ones are filtered by the engine.
func registeredModules() []modules.Module {
	// Modules are applied in dependency order:
	// kernel and filesystem first, then services, then daemons, then access control.
	return []modules.Module{
		&kernel.Module{},
		&filesystem.Module{},
		&ntp.Module{},
		&services.Module{},
		// Stub placeholders — each will be fully implemented in its own package.
		// &updates.Module{},
		// &network.Module{},
		// &ssh.Module{},
		// &firewall.Module{},
		// &users.Module{},
		// &pam.Module{},
		// &auditd.Module{},
		// &logging.Module{},
		// &mac.Module{},
		// &crypto.Module{},
		// &containers.Module{},
	}
}
