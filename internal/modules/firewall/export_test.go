package firewall

import "github.com/hardbox-io/hardbox/internal/distro"

// NewModuleForTest builds a firewall module with injectable dependencies.
func NewModuleForTest(
	run commandRunner,
	detect distroDetector,
	hasBinary binaryChecker,
	backendOverride string,
	ipv6DisablePath string,
) *Module {
	return &Module{
		run:             run,
		detectDistro:    detect,
		hasBinary:       hasBinary,
		backendOverride: backend(backendOverride),
		ipv6DisablePath: ipv6DisablePath,
	}
}

var (
	ParseUFWDefaults = parseUFWDefaults
	NftHasIPv6Rules  = nftHasIPv6Rules
)

func FakeDistroDebian() (*distro.Info, error) {
	return &distro.Info{ID: "ubuntu", Family: distro.FamilyDebian}, nil
}

func FakeDistroRHEL() (*distro.Info, error) {
	return &distro.Info{ID: "rocky", Family: distro.FamilyRHEL}, nil
}
